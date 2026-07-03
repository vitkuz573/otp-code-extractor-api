"""Pytest configuration and fixtures."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from otp_code_extractor import redis_client  # noqa: E402
from otp_code_extractor.auth import reset_auth_cache  # noqa: E402
from otp_code_extractor.config import Settings, get_settings  # noqa: E402
from otp_code_extractor.db import Base, async_engine, reset_engine_cache  # noqa: E402
from otp_code_extractor.main import create_app  # noqa: E402

# Well-known test secret. RFC 6238 / Google-Authenticator compatible.
SAMPLE_SECRET = "JBSWY3DPEHPK3PXP"
SAMPLE_URI_TOTP = (
    "otpauth://totp/ACME:alice@example.com"
    "?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30"
)
SAMPLE_URI_HOTP = (
    "otpauth://hotp/ACME:bob@example.com"
    "?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&counter=42"
)


@pytest.fixture(autouse=True)
def _reset_test_state(monkeypatch, tmp_path):
    """Reset module-level caches before each test and create the schema."""
    test_db = tmp_path / "test.db"
    monkeypatch.setenv("OTP_EXTRACTOR_USE_IN_MEMORY_REDIS", "true")
    monkeypatch.setenv("OTP_EXTRACTOR_AUTH_ENABLED", "false")
    monkeypatch.setenv("OTP_EXTRACTOR_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("OTP_EXTRACTOR_DATABASE_URL", f"sqlite+aiosqlite:///{test_db}")
    monkeypatch.setenv("OTP_EXTRACTOR_API_KEY_HMAC_SECRET", "test-secret-please-change")
    get_settings.cache_clear()
    redis_client.reset_redis_for_tests()
    reset_auth_cache()
    reset_engine_cache()

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("loop closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    engine = async_engine()
    loop.run_until_complete(_create_schema(engine))

    yield

    get_settings.cache_clear()
    redis_client.reset_redis_for_tests()
    reset_auth_cache()


async def _create_schema(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture(scope="session")
def sample_secret() -> str:
    """A well-known RFC 6238 test secret."""
    return SAMPLE_SECRET


@pytest.fixture(scope="session")
def sample_uri_totp() -> str:
    """A canonical TOTP URI used across many tests."""
    return SAMPLE_URI_TOTP


@pytest.fixture(scope="session")
def sample_uri_hotp() -> str:
    """A canonical HOTP URI used across many tests."""
    return SAMPLE_URI_HOTP


@pytest.fixture(scope="session")
def sample_qr_png(tmp_path_factory) -> Path:
    """Generate a PNG containing the sample TOTP URI encoded as a QR code.

    Created once per session and cached under ``tests/fixtures``.
    """
    fixture_path = ROOT / "tests" / "fixtures" / "sample_otp.png"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    if not fixture_path.exists():
        try:
            import qrcode  # type: ignore[import-not-found]

            image = qrcode.make(SAMPLE_URI_TOTP)
            image.save(fixture_path)
        except ImportError:
            fixture_path.write_bytes(b"")
    return fixture_path


@pytest.fixture()
def app():
    """Return a FastAPI app with safe defaults for tests."""
    settings = Settings(
        auth_enabled=False,
        rate_limit_enabled=False,
        use_in_memory_redis=True,
    )
    application = create_app(settings=settings)
    return application


@pytest.fixture()
def client(app):
    """Return a TestClient bound to the fixture app."""
    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def auth_client(tmp_path, monkeypatch):
    """Return a TestClient with auth enabled and a registered tenant."""
    settings = Settings(
        auth_enabled=True,
        rate_limit_enabled=False,
        use_in_memory_redis=True,
        api_key_hmac_secret="test-secret-please-change",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}",
    )
    application = create_app(settings=settings)
    from fastapi.testclient import TestClient

    with TestClient(application) as test_client:
        resp = test_client.post(
            "/v1/auth/register",
            json={"email": "alice@example.com", "password": "Sup3rSecret!", "name": "Alice"},
        )
        assert resp.status_code == 200, resp.text
        api_key = resp.json()["api_key"]
        test_client.headers["Authorization"] = f"Bearer {api_key}"
        yield test_client


@pytest.fixture()
def qr_png_b64(sample_qr_png) -> str:
    """Return the QR fixture as a base64 string (empty when qreader is absent)."""
    data = sample_qr_png.read_bytes()
    if not data:
        return ""
    return base64.b64encode(data).decode()
