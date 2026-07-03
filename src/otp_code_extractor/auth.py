"""Tenant registration, API key validation and usage statistics."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .db import (
    ApiKey,
    Tenant,
    UsageLog,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_api_key,
    verify_password,
)
from .exceptions import (
    ApiKeyNotFoundError,
    AuthenticationError,
    TenantAlreadyExistsError,
    TenantNotFoundError,
)


@dataclass
class ValidatedKey:
    """Result of validating an inbound bearer token."""

    api_key_id: str
    tenant_id: str
    scopes: str
    key_prefix: str


_AUTH_CACHE: dict[str, ValidatedKey | None] = {}
_AUTH_CACHE_MAX = 1024


def reset_auth_cache() -> None:
    """Clear the validation cache (used by tests)."""
    _AUTH_CACHE.clear()


async def register_tenant(
    db: AsyncSession,
    email: str,
    password: str,
    name: str,
    settings: Settings,
) -> tuple[Tenant, str]:
    """Create a tenant and its first API key, returning (tenant, raw_key)."""
    email_norm = email.strip().lower()
    existing = (
        await db.execute(select(Tenant).where(Tenant.email == email_norm))
    ).scalar_one_or_none()
    if existing is not None:
        raise TenantAlreadyExistsError(
            f"A tenant with email {email_norm!r} already exists"
        )

    tenant = Tenant(
        email=email_norm,
        name=name.strip(),
        password_hash=hash_password(password, settings),
    )
    db.add(tenant)
    await db.flush()

    raw_key, key_hash, key_prefix = generate_api_key(settings.api_key_hmac_secret)
    api_key = ApiKey(
        tenant_id=tenant.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name="default",
        scopes="read,write",
        is_active=True,
    )
    db.add(api_key)
    await db.flush()
    return tenant, raw_key


async def list_tenant_api_keys(db: AsyncSession, tenant_id: str) -> list[ApiKey]:
    """Return all API keys for a tenant."""
    result = await db.execute(
        select(ApiKey).where(ApiKey.tenant_id == tenant_id).order_by(ApiKey.created_at)
    )
    return list(result.scalars().all())


async def revoke_api_key(
    db: AsyncSession, key_id: str, tenant_id: str
) -> bool:
    """Mark an API key as inactive. Returns False when not found."""
    api_key = (
        await db.execute(
            select(ApiKey).where(
                ApiKey.id == key_id, ApiKey.tenant_id == tenant_id
            )
        )
    ).scalar_one_or_none()
    if api_key is None or not api_key.is_active:
        return False
    api_key.is_active = False
    await db.flush()
    _AUTH_CACHE.clear()
    return True


async def regenerate_api_key(
    db: AsyncSession, key_id: str, tenant_id: str, settings: Settings
) -> tuple[ApiKey, str] | None:
    """Rotate the secret of an API key. Returns (api_key, new_raw_key) or None."""
    api_key = (
        await db.execute(
            select(ApiKey).where(
                ApiKey.id == key_id, ApiKey.tenant_id == tenant_id
            )
        )
    ).scalar_one_or_none()
    if api_key is None or not api_key.is_active:
        return None
    raw_key, key_hash, key_prefix = generate_api_key(settings.api_key_hmac_secret)
    api_key.key_hash = key_hash
    api_key.key_prefix = key_prefix
    await db.flush()
    _AUTH_CACHE.clear()
    return api_key, raw_key


async def validate_api_key(
    db: AsyncSession, raw_key: str, settings: Settings
) -> ValidatedKey | None:
    """Validate ``raw_key`` against the database, using a small in-process cache."""
    if not raw_key:
        return None
    secret = settings.api_key_hmac_secret
    if not secret:
        return None

    cache_key = hashlib.sha256((secret + ":" + raw_key).encode()).hexdigest()
    if cache_key in _AUTH_CACHE:
        return _AUTH_CACHE[cache_key]

    presented_hash = hash_api_key(raw_key, secret)
    api_key = (
        await db.execute(
            select(ApiKey).where(
                ApiKey.key_hash == presented_hash, ApiKey.is_active.is_(True)
            )
        )
    ).scalar_one_or_none()

    if api_key is None:
        # Fall back to a timing-safe constant-time check to avoid leaking
        # whether the key prefix was recognised.
        verify_api_key(raw_key, secret, presented_hash)
        _enforce_cache_limit()
        _AUTH_CACHE[cache_key] = None
        return None

    api_key.last_used_at = datetime.now(timezone.utc)
    await db.flush()
    result = ValidatedKey(
        api_key_id=api_key.id,
        tenant_id=api_key.tenant_id,
        scopes=api_key.scopes,
        key_prefix=api_key.key_prefix,
    )
    _enforce_cache_limit()
    _AUTH_CACHE[cache_key] = result
    return result


def _enforce_cache_limit() -> None:
    """Evict the oldest cache entries when the cache exceeds its max size."""
    while len(_AUTH_CACHE) >= _AUTH_CACHE_MAX:
        oldest = next(iter(_AUTH_CACHE))
        _AUTH_CACHE.pop(oldest, None)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


async def authenticate_tenant(
    db: AsyncSession, email: str, password: str
) -> Tenant:
    """Authenticate a tenant by email + password."""
    email_norm = email.strip().lower()
    tenant = (
        await db.execute(select(Tenant).where(Tenant.email == email_norm))
    ).scalar_one_or_none()
    if tenant is None or not tenant.is_active:
        raise AuthenticationError("Invalid email or password")
    try:
        ok = verify_password(password, tenant.password_hash)
    except VerifyMismatchError:
        ok = False
    if not ok:
        raise AuthenticationError("Invalid email or password")
    return tenant


# ---------------------------------------------------------------------------
# Usage statistics
# ---------------------------------------------------------------------------


async def _query_usage(
    db: AsyncSession,
    tenant_id: str | None,
    period: str,
    days: int,
) -> dict[str, Any]:
    """Aggregate usage rows for either a tenant or the whole system."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    base = select(UsageLog).where(UsageLog.created_at >= cutoff)
    if tenant_id is not None:
        base = base.where(UsageLog.tenant_id == tenant_id)

    rows = (await db.execute(base.order_by(UsageLog.created_at))).scalars().all()

    bucket: dict[str, dict[str, Any]] = {}
    endpoint_counter: dict[str, dict[str, Any]] = {}
    total = 0
    for row in rows:
        if period == "monthly":
            key = row.created_at.strftime("%Y-%m")
        else:
            key = row.created_at.strftime("%Y-%m-%d")
        bucket.setdefault(
            key,
            {"period": key, "requests": 0, "latency_sum": 0.0, "error_count": 0},
        )
        bucket[key]["requests"] += 1
        bucket[key]["latency_sum"] += row.response_time_ms
        if row.status_code >= 400:
            bucket[key]["error_count"] += 1

        endpoint_counter.setdefault(
            row.endpoint,
            {"endpoint": row.endpoint, "count": 0, "latency_sum": 0.0},
        )
        endpoint_counter[row.endpoint]["count"] += 1
        endpoint_counter[row.endpoint]["latency_sum"] += row.response_time_ms
        total += 1

    breakdown = [
        UsagePeriodStat(
            period=v["period"],
            requests=v["requests"],
            avg_latency_ms=round(v["latency_sum"] / v["requests"], 3) if v["requests"] else 0.0,
            error_count=v["error_count"],
        )
        for v in sorted(bucket.values(), key=lambda x: x["period"])
    ]
    by_endpoint = [
        UsageEndpointStat(
            endpoint=v["endpoint"],
            count=v["count"],
            avg_latency_ms=round(v["latency_sum"] / v["count"], 3) if v["count"] else 0.0,
        )
        for v in sorted(endpoint_counter.values(), key=lambda x: x["count"], reverse=True)
    ]
    return {"total_requests": total, "period_breakdown": breakdown, "by_endpoint": by_endpoint}


async def get_tenant_usage_stats(
    db: AsyncSession,
    tenant_id: str,
    period: str,
    days: int,
) -> dict[str, Any]:
    """Return usage statistics for one tenant."""
    if (await db.get(Tenant, tenant_id)) is None:
        raise TenantNotFoundError(f"Tenant {tenant_id!r} not found")
    data = await _query_usage(db, tenant_id, period, days)
    return {
        "tenant_id": tenant_id,
        "period": period,
        "days": days,
        **data,
    }


async def get_all_usage_stats(
    db: AsyncSession, period: str, days: int
) -> dict[str, Any]:
    """Return system-wide usage statistics."""
    data = await _query_usage(db, None, period, days)
    return {"period": period, "days": days, **data, "top_tenants": []}


async def get_system_metrics(db: AsyncSession) -> dict[str, Any]:
    """Return aggregate counts for the admin dashboard."""
    tenants = (
        await db.execute(select(func.count(Tenant.id)))
    ).scalar_one()
    keys = (await db.execute(select(func.count(ApiKey.id)))).scalar_one()
    active_keys = (
        await db.execute(
            select(func.count(ApiKey.id)).where(ApiKey.is_active.is_(True))
        )
    ).scalar_one()
    logs = (await db.execute(select(func.count(UsageLog.id)))).scalar_one()
    return {
        "tenants_total": int(tenants or 0),
        "api_keys_total": int(keys or 0),
        "api_keys_active": int(active_keys or 0),
        "usage_logs_total": int(logs or 0),
    }


async def admin_list_tenant_keys(
    db: AsyncSession, tenant_id: str
) -> list[ApiKey]:
    """Return all (including inactive) keys for a tenant — admin only."""
    if (await db.get(Tenant, tenant_id)) is None:
        raise TenantNotFoundError(f"Tenant {tenant_id!r} not found")
    result = await db.execute(
        select(ApiKey).where(ApiKey.tenant_id == tenant_id).order_by(ApiKey.created_at)
    )
    return list(result.scalars().all())


__all__ = [
    "ValidatedKey",
    "register_tenant",
    "list_tenant_api_keys",
    "revoke_api_key",
    "regenerate_api_key",
    "validate_api_key",
    "authenticate_tenant",
    "get_tenant_usage_stats",
    "get_all_usage_stats",
    "get_system_metrics",
    "admin_list_tenant_keys",
    "reset_auth_cache",
    "ApiKeyNotFoundError",
]
