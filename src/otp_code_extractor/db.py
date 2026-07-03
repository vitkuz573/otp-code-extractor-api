"""Async database engine, session factory, and ORM models for multi-tenant API.

Models: Tenant, ApiKey, UsageLog.
Helpers: API key generation/hashing (HMAC-SHA256), Argon2 password hashing,
scope validation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import TYPE_CHECKING

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .config import Settings, get_settings

if TYPE_CHECKING:
    from .config import Settings


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all ORM models."""

    pass


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------


class Tenant(Base):
    """Tenant account (organization or individual)."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    api_keys: Mapped[list[ApiKey]] = relationship(
        "ApiKey", back_populates="tenant", lazy="selectin"
    )

    __mapper_args__ = {"eager_defaults": True}


class ApiKey(Base):
    """API key belonging to a tenant."""

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_tenant_active", "tenant_id", "is_active"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id"), index=True
    )
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(255), default="default")
    scopes: Mapped[str] = mapped_column(String(255), default="read")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="api_keys")


class UsageLog(Base):
    """API usage log entry."""

    __tablename__ = "usage_logs"
    __table_args__ = (Index("ix_usage_logs_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    api_key_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("api_keys.id"), nullable=True
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id"), nullable=True
    )
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Engine & Session Factory
# ---------------------------------------------------------------------------


_engine_cache: dict[str, tuple[AsyncEngine, async_sessionmaker[AsyncSession]]] = {}
_engine_lock = __import__("threading").Lock()


def _build_engine_kwargs(database_url: str) -> dict:
    """Return engine kwargs appropriate for the given database URL."""
    if database_url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 10,
    }


def _get_engine_and_factory(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Return the (engine, factory) pair for ``database_url``, building lazily."""
    cached = _engine_cache.get(database_url)
    if cached is not None:
        return cached
    with _engine_lock:
        cached = _engine_cache.get(database_url)
        if cached is not None:
            return cached
        engine = create_async_engine(database_url, **_build_engine_kwargs(database_url))
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        _engine_cache[database_url] = (engine, factory)
        return engine, factory


def reset_engine_cache() -> None:
    """Discard cached engines (used by tests)."""
    with _engine_lock:
        _engine_cache.clear()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session."""
    factory = _get_engine_and_factory(get_settings().database_url)[1]
    session = factory()
    try:
        yield session
    finally:
        await session.close()


def async_session_factory(settings: Settings | None = None):
    """Return the async sessionmaker for the configured (or given) database URL."""
    database_url = (settings or get_settings()).database_url
    return _get_engine_and_factory(database_url)[1]


def async_engine(settings: Settings | None = None) -> AsyncEngine:
    """Return the async engine for lifecycle management (lifespan)."""
    database_url = (settings or get_settings()).database_url
    return _get_engine_and_factory(database_url)[0]


# ---------------------------------------------------------------------------
# Valid Scopes
# ---------------------------------------------------------------------------

VALID_SCOPES = {"read", "write", "admin"}


def parse_scopes(scopes_str: str) -> set[str]:
    """Parse a comma-separated scope string into a validated set."""
    if not scopes_str or not scopes_str.strip():
        return set()
    raw = {s.strip() for s in scopes_str.split(",") if s.strip()}
    unknown = raw - VALID_SCOPES
    if unknown:
        raise ValueError(f"Unknown scopes: {unknown!r}")
    return raw


def has_scope(key_scopes: str, required: str) -> bool:
    """Check whether a key's scopes satisfy a required scope.

    ``admin`` implies both ``read`` and ``write``.
    """
    scopes = parse_scopes(key_scopes)
    if required in scopes:
        return True
    if "admin" in scopes and required in ("read", "write"):
        return True
    return False


# ---------------------------------------------------------------------------
# API Key Helpers
# ---------------------------------------------------------------------------


def hash_api_key(raw_key: str, secret: str) -> str:
    """Return HMAC-SHA256 hexdigest of raw_key using secret."""
    return hmac.new(
        secret.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()


def generate_api_key(secret: str | None = None) -> tuple[str, str, str]:
    """Generate a new API key.

    Returns:
        (raw_key, key_hash, key_prefix)

    The raw key starts with ``otp_`` and is 43 chars long (token_urlsafe(32)).
    """
    if secret is None:
        secret = get_settings().api_key_hmac_secret
    raw = f"otp_{secrets.token_urlsafe(32)}"
    key_hash = hash_api_key(raw, secret)
    prefix = raw[:12]
    return raw, key_hash, prefix


def verify_api_key(raw_key: str, secret: str, stored_hash: str) -> bool:
    """Timing-safe verification of an API key against a stored hash."""
    computed = hmac.new(
        secret.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(computed, stored_hash)


# ---------------------------------------------------------------------------
# Password Helpers (Argon2)
# ---------------------------------------------------------------------------


def _build_password_hasher(settings: Settings) -> PasswordHasher:
    """Return a PasswordHasher configured with the given parameters."""
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
    )


def hash_password(password: str, settings: Settings) -> str:
    """Hash a plaintext password using Argon2id with the settings parameters."""
    return _build_password_hasher(settings).hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        PasswordHasher().verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
