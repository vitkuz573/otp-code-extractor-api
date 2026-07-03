# OTP Code Extractor API

[![CI](https://github.com/vitkuz573/otp-code-extractor-api/actions/workflows/ci.yml/badge.svg)](https://github.com/vitkuz573/otp-code-extractor-api/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://docs.astral.sh/ruff/)

A clean, fast REST API that **extracts OTP codes** from QR images, `otpauth://` URIs
and raw base32 secrets — built with FastAPI and `pyotp`. Fully offline, no
external calls, no third-party auth services.

## Highlights

- **QR image → code** via `qreader` (opencv-based, handles rotated/blurry codes)
- **`otpauth://` URI → code** (TOTP + HOTP, RFC 6238/4226)
- **Raw base32 secret → code** with safe defaults
- **Auto-detect** of the input format (URI / secret / data-URI image)
- **Batch** processing and **metadata-only** parsing
- **CLI** for offline use
- **Docker** image, GitHub Actions CI, Makefile
- **Multi-tenant** with API key auth, **rate limiting**, **metrics** and **audit log**
- **200+** tests, fully offline, no Stripe / billing / external payments

## Quick start

```bash
git clone https://github.com/vitkuz573/otp-code-extractor-api.git
cd otp-code-extractor-api
pip install -r requirements-dev.txt
uvicorn otp_code_extractor.main:app --reload
```

Open <http://localhost:8000/docs> for interactive documentation.

## Docker

```bash
docker build -t otp-code-extractor-api:local .
docker compose up -d
```

## Endpoints

| Method | Path                       | Description                                          |
|--------|----------------------------|------------------------------------------------------|
| GET    | `/`                        | Service info                                         |
| GET    | `/health`                  | Health, uptime, QR decoder status                    |
| GET    | `/livez`                   | Liveness probe                                       |
| GET    | `/readyz`                  | Readiness probe                                      |
| GET    | `/metrics`                 | In-process metrics snapshot                          |
| GET    | `/audit`                   | Recent audit log entries                             |
| POST   | `/v1/otp/from-qr`          | QR image (multipart upload) → code                   |
| POST   | `/v1/otp/from-qr-base64`   | QR image (JSON base64) → code                        |
| POST   | `/v1/otp/from-uri`         | `otpauth://` URI → code                              |
| POST   | `/v1/otp/from-secret`      | Base32 secret → code                                 |
| POST   | `/v1/otp/from-string`      | Auto-detect URI / secret / data-URI image            |
| POST   | `/v1/otp/batch`            | Batch OTP extraction                                 |
| GET    | `/v1/otp/parse`            | Parse URI / secret without generating a code         |
| GET    | `/v1/otp/algorithms`       | Supported hashing algorithms                         |
| GET    | `/v1/otp/digits`           | Supported digit counts                               |
| GET    | `/v1/otp/periods`          | Supported TOTP periods                               |
| POST   | `/v1/auth/register`        | Register a tenant account                            |
| GET    | `/v1/auth/me`              | Authenticated tenant profile                         |
| GET    | `/v1/auth/api-keys`        | List API keys                                        |
| POST   | `/v1/auth/api-keys/{id}/revoke`     | Revoke an API key                        |
| POST   | `/v1/auth/api-keys/{id}/regenerate` | Regenerate an API key                     |
| GET    | `/v1/auth/usage-stats`     | Tenant usage statistics                              |
| GET    | `/v1/admin/tenants`        | List tenants (admin only)                            |
| GET    | `/v1/admin/metrics`        | System metrics (admin only)                          |
| GET    | `/v1/admin/usage-stats`    | System usage stats (admin only)                      |

### Sample: extract a code from an `otpauth://` URI

```bash
curl -X POST http://localhost:8000/v1/otp/from-uri \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30"
  }'
```

```json
{
  "code": "123456",
  "type": "totp",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "issuer": "ACME",
  "account": "alice@example.com",
  "remaining_seconds": 17,
  "generated_at": "2026-07-03T12:34:56+00:00"
}
```

### Sample: extract a code from a QR image

Multipart upload:

```bash
curl -X POST http://localhost:8000/v1/otp/from-qr \
  -F "file=@qr.png"
```

JSON base64 (POST to `/v1/otp/from-qr-base64`):

```bash
curl -X POST http://localhost:8000/v1/otp/from-qr-base64 \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "image_base64": "<base64-encoded PNG of the QR code>",
  "mime_type": "image/png"
}
JSON
```

### Auto-detect (`from-string`)

```bash
curl -X POST http://localhost:8000/v1/otp/from-string \
  -H "Content-Type: application/json" \
  -d '{ "input": "JBSWY3DPEHPK3PXP" }'
```

Accepts: `otpauth://...`, raw base32 secret, `data:image/png;base64,...`.

### CLI

```bash
pip install -e .
otp-extractor code --uri "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP"
otp-extractor code --secret JBSWY3DPEHPK3PXP --digits 6 --period 30
otp-extractor code --qr data/sample_otp.png
otp-extractor parse --uri "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP"
otp-extractor qr --out data/my_qr.png --uri "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP"
```

## Configuration

All settings live in `otp_code_extractor.config.Settings` and can be overridden
via environment variables with the `OTP_EXTRACTOR_` prefix or a `.env` file.
See [ARCHITECTURE.md](ARCHITECTURE.md#configuration) for the full table.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, request lifecycle, security
- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [examples/](examples/) — curl, Python, JavaScript, Go and Postman
- Interactive docs at `/docs`, ReDoc at `/redoc`

## Testing

```bash
pytest
pytest --cov=otp_code_extractor --cov-report=term-missing
```

## Notes

- The service performs **only cryptographic code generation**. It does **not**
  transmit secrets anywhere — every computation happens locally.
- Secrets are **never logged** or persisted. They are returned to the caller in
  the response only when explicitly requested via the parse endpoint, and can be
  opted out with `redact=true`.
- See [SECURITY.md](SECURITY.md) for guidance on running the service in
  production.

## License

MIT — see [LICENSE](LICENSE).
