"""Tests for the FastAPI routes."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class TestSystem:
    def test_root(self, client: TestClient):
        r = client.get("/")
        assert r.status_code == 200
        assert "name" in r.json()

    def test_health(self, client: TestClient):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "qr_decoder_enabled" in body

    def test_livez(self, client: TestClient):
        assert client.get("/livez").status_code == 200

    def test_readyz(self, client: TestClient):
        r = client.get("/readyz")
        assert r.status_code == 200
        assert r.json()["ready"] is True

    def test_metrics(self, client: TestClient):
        r = client.get("/metrics")
        assert r.status_code == 200
        body = r.json()
        assert "requests_total" in body

    def test_audit(self, client: TestClient):
        # Trigger at least one request so the audit ring has an entry
        client.get("/livez")
        r = client.get("/audit")
        assert r.status_code == 200
        body = r.json()
        assert "entries" in body and "total" in body


class TestReference:
    def test_algorithms(self, client: TestClient):
        r = client.get("/v1/otp/algorithms")
        assert r.status_code == 200
        assert "SHA1" in r.json()["algorithms"]
        assert "SHA256" in r.json()["algorithms"]
        assert "SHA512" in r.json()["algorithms"]

    def test_digits(self, client: TestClient):
        r = client.get("/v1/otp/digits")
        assert r.status_code == 200
        assert r.json()["digits"] == [6, 8]

    def test_periods(self, client: TestClient):
        r = client.get("/v1/otp/periods")
        assert r.status_code == 200
        assert 30 in r.json()["periods"]


class TestFromUri:
    def test_valid_totp_uri(self, client: TestClient, sample_uri_totp):
        r = client.post("/v1/otp/from-uri", json={"uri": sample_uri_totp})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["type"] == "totp"
        assert body["issuer"] == "ACME"
        assert body["account"] == "alice@example.com"
        assert len(body["code"]) == 6
        assert body["code"].isdigit()
        assert body["remaining_seconds"] is not None

    def test_invalid_uri(self, client: TestClient):
        r = client.post("/v1/otp/from-uri", json={"uri": "not-a-uri"})
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "invalid_otp_uri"

    def test_uri_missing_secret(self, client: TestClient):
        r = client.post(
            "/v1/otp/from-uri",
            json={"uri": "otpauth://totp/ACME:alice@example.com"},
        )
        assert r.status_code == 400


class TestFromSecret:
    def test_valid_secret(self, client: TestClient):
        r = client.post(
            "/v1/otp/from-secret", json={"secret": "JBSWY3DPEHPK3PXP"}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["type"] == "totp"
        assert len(body["code"]) == 6

    def test_invalid_secret(self, client: TestClient):
        r = client.post("/v1/otp/from-secret", json={"secret": "SHORT"})
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "invalid_secret"

    def test_unsupported_algorithm(self, client: TestClient):
        r = client.post(
            "/v1/otp/from-secret",
            json={"secret": "JBSWY3DPEHPK3PXP", "algorithm": "MD5"},
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "unsupported_algorithm"

    def test_hotp_with_counter(self, client: TestClient):
        r = client.post(
            "/v1/otp/from-secret",
            json={"secret": "JBSWY3DPEHPK3PXP", "counter": 1},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["type"] == "hotp"
        assert body["counter"] == 1
        assert body["remaining_seconds"] is None


class TestParse:
    def test_parse_uri_redacted(self, client: TestClient, sample_uri_totp):
        r = client.post("/v1/otp/parse", json={"uri": sample_uri_totp, "redact": True})
        assert r.status_code == 200
        body = r.json()
        assert body["secret"] is None
        assert body["secret_redacted"] is True

    def test_parse_uri_unredacted(self, client: TestClient, sample_uri_totp):
        r = client.post("/v1/otp/parse", json={"uri": sample_uri_totp, "redact": False})
        assert r.status_code == 200
        body = r.json()
        assert body["secret"] == "JBSWY3DPEHPK3PXP"

    def test_parse_missing_input(self, client: TestClient):
        r = client.post("/v1/otp/parse", json={})
        assert r.status_code == 400


class TestFromString:
    def test_auto_secret(self, client: TestClient):
        r = client.post(
            "/v1/otp/from-string", json={"input": "JBSWY3DPEHPK3PXP"}
        )
        assert r.status_code == 200

    def test_auto_uri(self, client: TestClient, sample_uri_totp):
        r = client.post("/v1/otp/from-string", json={"input": sample_uri_totp})
        assert r.status_code == 200

    def test_auto_unknown(self, client: TestClient):
        r = client.post("/v1/otp/from-string", json={"input": "this is not an otp"})
        assert r.status_code == 400


class TestBatch:
    def test_batch_success(self, client: TestClient, sample_uri_totp):
        r = client.post(
            "/v1/otp/batch",
            json={
                "items": [
                    {"kind": "uri", "uri": sample_uri_totp, "label": "first"},
                    {"kind": "secret", "secret": "JBSWY3DPEHPK3PXP"},
                ]
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 2
        assert body["succeeded"] == 2
        assert body["failed"] == 0
        assert body["results"][0]["label"] == "first"

    def test_batch_partial_failure(self, client: TestClient, sample_uri_totp):
        r = client.post(
            "/v1/otp/batch",
            json={
                "items": [
                    {"kind": "uri", "uri": sample_uri_totp},
                    {"kind": "secret", "secret": "INVALID"},
                ]
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["succeeded"] == 1
        assert body["failed"] == 1
        assert body["results"][1]["error"] is not None

    def test_batch_too_large(self, client: TestClient, sample_uri_totp):
        items = [{"kind": "uri", "uri": sample_uri_totp} for _ in range(101)]
        r = client.post("/v1/otp/batch", json={"items": items})
        assert r.status_code == 413
        assert r.json()["error"]["code"] == "batch_too_large"


@pytest.mark.skipif(
    not Path("tests/fixtures/sample_otp.png").exists()
    or Path("tests/fixtures/sample_otp.png").stat().st_size == 0,
    reason="qrcode fixture is not available",
)
class TestFromQr:
    def test_from_qr_base64(self, client: TestClient, sample_qr_png):
        data = sample_qr_png.read_bytes()
        b64 = base64.b64encode(data).decode()
        r = client.post(
            "/v1/otp/from-qr", json={"image_base64": b64, "mime_type": "image/png"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["type"] == "totp"
        assert body["issuer"] == "ACME"

    def test_from_qr_multipart(self, client: TestClient, sample_qr_png):
        with sample_qr_png.open("rb") as fh:
            r = client.post(
                "/v1/otp/from-qr",
                files={"file": ("qr.png", fh, "image/png")},
            )
        assert r.status_code == 200, r.text

    def test_from_qr_invalid_base64(self, client: TestClient):
        r = client.post(
            "/v1/otp/from-qr", json={"image_base64": "not-base64!@#"}
        )
        assert r.status_code in (400, 422)


class TestReadyzDbState:
    def test_readyz_handles_no_db_state(self, client: TestClient):
        # /readyz should be safe even if state was never initialised.
        r = client.get("/readyz")
        assert r.status_code == 200
