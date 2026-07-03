"""Tests for tenant registration, API key validation and usage stats."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from otp_code_extractor.auth import (
    authenticate_tenant,
    register_tenant,
    validate_api_key,
)
from otp_code_extractor.config import Settings


class TestTenantLifecycle:
    async def test_register_then_authenticate(self, db_session, settings: Settings):
        tenant, raw_key = await register_tenant(
            db_session, "alice@example.com", "Sup3rSecret!", "Alice", settings
        )
        assert tenant.id
        assert raw_key.startswith("otp_")

        # Round-trip authentication via the email/password path.
        authed = await authenticate_tenant(
            db_session, "alice@example.com", "Sup3rSecret!"
        )
        assert authed.id == tenant.id

    async def test_register_duplicate_email(self, db_session, settings: Settings):
        await register_tenant(
            db_session, "alice@example.com", "Sup3rSecret!", "Alice", settings
        )
        with pytest.raises(Exception):
            await register_tenant(
                db_session, "alice@example.com", "anotherpwd1!", "Alice2", settings
            )

    async def test_register_then_validate_key(self, db_session, settings: Settings):
        tenant, raw_key = await register_tenant(
            db_session, "bob@example.com", "Sup3rSecret!", "Bob", settings
        )
        validated = await validate_api_key(db_session, raw_key, settings)
        assert validated is not None
        assert validated.tenant_id == tenant.id
        assert "read" in validated.scopes
        assert "write" in validated.scopes

    async def test_validate_unknown_key_returns_none(self, db_session, settings: Settings):
        result = await validate_api_key(
            db_session, "otp_does-not-exist", settings
        )
        assert result is None


class TestAuthApiEndpoints:
    def test_register_and_use_key(self, auth_client: TestClient):
        # auth_client fixture already registered and set the bearer header.
        r = auth_client.get("/v1/auth/me")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["email"] == "alice@example.com"
        assert body["api_key_count"] >= 1

    def test_list_api_keys(self, auth_client: TestClient):
        r = auth_client.get("/v1/auth/api-keys")
        assert r.status_code == 200
        keys = r.json()
        assert len(keys) >= 1
        assert keys[0]["is_active"] is True

    def test_usage_stats(self, auth_client: TestClient):
        r = auth_client.get("/v1/auth/usage-stats?days=7")
        assert r.status_code == 200
        body = r.json()
        assert body["days"] == 7
        assert "total_requests" in body

    def test_regenerate_and_revoke(self, auth_client: TestClient):
        keys = auth_client.get("/v1/auth/api-keys").json()
        key_id = keys[0]["id"]
        r = auth_client.post(f"/v1/auth/api-keys/{key_id}/regenerate")
        assert r.status_code == 200, r.text
        new_key = r.json()["api_key"]
        assert new_key.startswith("otp_")

        # The new key should now work.
        new_headers = {"Authorization": f"Bearer {new_key}"}
        r2 = auth_client.get("/v1/auth/me", headers=new_headers)
        assert r2.status_code == 200

        r3 = auth_client.post(f"/v1/auth/api-keys/{key_id}/revoke")
        assert r3.status_code == 200

        # Revoking means validate_api_key returns None for the new raw key.
        r4 = auth_client.get("/v1/auth/me", headers=new_headers)
        assert r4.status_code == 401


class TestAdminEndpoints:
    def test_admin_tenants_requires_admin_scope(self, auth_client: TestClient):
        r = auth_client.get("/v1/admin/tenants")
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "authorization_failed"

    def test_admin_metrics_requires_admin_scope(self, auth_client: TestClient):
        r = auth_client.get("/v1/admin/metrics")
        assert r.status_code == 403


@pytest.fixture()
async def db_session():
    """Provide an async session bound to the test database."""
    from otp_code_extractor.db import async_session_factory

    factory = async_session_factory()
    async with factory() as session:
        yield session


@pytest.fixture()
def settings(monkeypatch) -> Settings:
    monkeypatch.setenv("OTP_EXTRACTOR_API_KEY_HMAC_SECRET", "test-secret-please-change")
    from otp_code_extractor.config import get_settings

    get_settings.cache_clear()
    return get_settings()
