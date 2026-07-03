"""Tests for the HTTP middleware stack."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from otp_code_extractor.config import Settings
from otp_code_extractor.exceptions import register_exception_handlers
from otp_code_extractor.middleware import register_middleware


def _build_app(auth_enabled: bool, rate_limit_enabled: bool) -> FastAPI:
    from otp_code_extractor.routes import router

    app = FastAPI()
    app.include_router(router)
    settings = Settings(
        auth_enabled=auth_enabled,
        rate_limit_enabled=rate_limit_enabled,
        use_in_memory_redis=True,
    )
    register_exception_handlers(app)
    register_middleware(app, settings)

    @app.get("/protected")
    def protected():
        return {"ok": True}

    @app.get("/public")
    def public():
        return {"ok": True}

    return app


class TestAuth:
    def test_no_auth_disabled_passes(self):
        app = _build_app(auth_enabled=False, rate_limit_enabled=False)
        client = TestClient(app)
        r = client.get("/protected")
        assert r.status_code == 200

    def test_auth_required_when_enabled(self):
        app = _build_app(auth_enabled=True, rate_limit_enabled=False)
        client = TestClient(app)
        r = client.get("/protected")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "authentication_required"

    def test_auth_health_is_public(self):
        app = _build_app(auth_enabled=True, rate_limit_enabled=False)
        client = TestClient(app)
        assert client.get("/health").status_code == 200

    def test_auth_bad_bearer(self):
        app = _build_app(auth_enabled=True, rate_limit_enabled=False)
        client = TestClient(app)
        r = client.get("/protected", headers={"Authorization": "Bearer otp_badkey"})
        assert r.status_code == 401


class TestRateLimit:
    def test_rate_limit_headers_present(self):
        app = _build_app(auth_enabled=False, rate_limit_enabled=True)
        client = TestClient(app)
        r = client.get("/livez")
        assert r.status_code == 200
        assert "x-ratelimit-limit" in {k.lower() for k in r.headers.keys()}

    def test_rate_limit_disabled_omits_headers(self):
        app = _build_app(auth_enabled=False, rate_limit_enabled=False)
        client = TestClient(app)
        r = client.get("/livez")
        # Without the limiter the response-headers middleware still attaches
        # '0/0/0' defaults to keep clients sane.
        assert r.headers.get("X-RateLimit-Limit") in ("0", None)


class TestRequestContext:
    def test_request_id_is_echoed(self):
        app = _build_app(auth_enabled=False, rate_limit_enabled=False)
        client = TestClient(app)
        r = client.get("/livez", headers={"x-request-id": "abc123"})
        assert r.headers.get("x-request-id") == "abc123"

    def test_request_id_generated_when_missing(self):
        app = _build_app(auth_enabled=False, rate_limit_enabled=False)
        client = TestClient(app)
        r = client.get("/livez")
        assert r.headers.get("x-request-id")
