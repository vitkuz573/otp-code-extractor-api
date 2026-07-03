# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-03

### Added
- FastAPI application with multi-tenant API key auth, rate limiting, metrics,
  audit log, request-id tracking and structured logging.
- `POST /v1/otp/from-qr` — extract a code from a QR image (multipart upload).
- `POST /v1/otp/from-qr-base64` — extract a code from a QR image (JSON base64).
- `POST /v1/otp/from-uri` — extract a code from an `otpauth://` URI.
- `POST /v1/otp/from-secret` — extract a code from a raw base32 secret.
- `POST /v1/otp/from-string` — auto-detect URI / secret / data-URI image.
- `POST /v1/otp/batch` — batch extraction across mixed input types.
- `GET /v1/otp/parse` — parse a URI / secret without producing a code.
- `GET /v1/otp/algorithms`, `/digits`, `/periods` — reference endpoints.
- Auth: register tenant, list / revoke / regenerate API keys, `me`,
  `usage-stats`.
- Admin: tenants, metrics, usage-stats.
- CLI: `otp-extractor code`, `parse`, `qr`.
- Docker image, docker-compose, GitHub Actions CI, Makefile.
- 200+ tests covering parsers, generators, QR decoder stubs, middleware,
  auth, CLI.
