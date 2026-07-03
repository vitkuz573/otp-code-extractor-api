# Architecture

## Layers

```
src/otp_code_extractor/
  main.py            - FastAPI app factory and lifespan
  routes.py          - HTTP routes and request/response shaping
  config.py          - Pydantic-Settings environment configuration
  logging_config.py  - structlog wiring (JSON or console)
  exceptions.py      - Domain exceptions + FastAPI handlers
  middleware.py      - Request ID, CORS, auth, rate limit, metrics/audit
  observability.py   - In-process metrics counters and audit ring buffer
  redis_client.py    - Sliding-window limiter (Redis or in-memory)
  db.py              - Async engine, ORM models, API key / password helpers
  auth.py            - Tenant registration, API key validation, usage stats
  models.py          - Pydantic request/response models
  validators.py      - Secret / URI / base32 validators
  otp.py             - URI parser + TOTP/HOTP code generation (pyotp)
  qr_decoder.py      - QR decoder wrapper around qreader/opencv
  cli.py             - argparse-based CLI wrapper
```

## Request lifecycle

1. **CORS** (outermost) — headers for cross-origin browsers.
2. **Rate limit** — sliding-window per API key or client IP.
3. **API key auth** — rejects requests without a valid `Authorization` header
   when `OTP_EXTRACTOR_AUTH_ENABLED=true`.
4. **Request context** — assigns a UUID `x-request-id`, measures latency,
   records metrics, appends to the audit ring buffer and dispatches a
   fire-and-forget `UsageLog` write.

## OTP extraction flow

The `extract_code` helper handles all three input shapes:

1. **Normalise** the input:
   - If it starts with `otpauth://` → parse as a URI.
   - If it matches `data:image/...;base64,...` → decode and run QR detection.
   - If it looks like a base32 secret (length 16+ and valid charset) → use as
     a raw secret with safe defaults.
   - Otherwise raise `InvalidOtpInputError`.
2. **For QR images**: decode via `qr_decoder.decode_qr_image` (qreader +
   opencv-headless), which returns one or more decoded strings. The first
   `otpauth://` URI is used; non-otpauth content raises `QrDecodeError` /
   `InvalidOtpInputError`.
3. **For URIs**: `otp.parse_otpauth_uri` parses type, label, secret, algorithm,
   digits, period, counter. Each parameter is validated against the supported
   set.
4. **For raw secrets**: validate base32 and build a TOTP config with the
   configured defaults (`OTP_EXTRACTOR_DEFAULT_*`).
5. **Generate** the code via `pyotp.TOTP(...).now()` or
   `pyotp.HOTP(...).at(counter)` and compute `remaining_seconds` for TOTP.
6. **Audit log** records `{type, digits, period, algorithm, has_counter}` —
   never the secret, never the code.

## Storage

- **No persistent OTP state.** Secrets are never written to disk.
- Tenants, API keys and usage logs are stored in the configured database
  (SQLite by default; PostgreSQL via asyncpg in production).
- Redis is used **only** for rate limiting; the limiter falls back to an
  in-memory implementation when `OTP_EXTRACTOR_USE_IN_MEMORY_REDIS=true`.

## Configuration

All settings live in `otp_code_extractor.config.Settings`. Override with
environment variables using the `OTP_EXTRACTOR_` prefix or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `OTP_EXTRACTOR_ENVIRONMENT` | `development` | `development` / `staging` / `production` / `test` |
| `OTP_EXTRACTOR_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR / CRITICAL |
| `OTP_EXTRACTOR_LOG_FORMAT` | `console` | `console` or `json` |
| `OTP_EXTRACTOR_RATE_LIMIT_ENABLED` | `true` | Enable Redis-backed sliding window limiter |
| `OTP_EXTRACTOR_RATE_LIMIT_PER_MINUTE` | `60` | Sustained limit per client |
| `OTP_EXTRACTOR_RATE_LIMIT_BURST` | `20` | Burst capacity |
| `OTP_EXTRACTOR_AUTH_ENABLED` | `false` | Require API key when `true` |
| `OTP_EXTRACTOR_API_KEYS` | `""` | Comma-separated list of valid keys |
| `OTP_EXTRACTOR_CORS_ORIGINS` | `["*"]` | Allowed origins |
| `OTP_EXTRACTOR_MAX_BATCH_SIZE` | `100` | Maximum items per batch request |
| `OTP_EXTRACTOR_DEFAULT_ALGORITHM` | `SHA1` | Default hashing algorithm for raw secrets |
| `OTP_EXTRACTOR_DEFAULT_DIGITS` | `6` | Default code length |
| `OTP_EXTRACTOR_DEFAULT_PERIOD` | `30` | Default TOTP period |
| `OTP_EXTRACTOR_QR_DECODER_ENABLED` | `true` | Whether the QR decoder is loaded |
| `OTP_EXTRACTOR_QR_DECODER_MODEL` | `detector_v1` | Model hint for qreader |
| `OTP_EXTRACTOR_MAX_QR_IMAGE_BYTES` | `5242880` | Maximum size of an accepted QR image |
| `OTP_EXTRACTOR_DATABASE_URL` | `sqlite+aiosqlite:///./otp_extractor.db` | Async DB URL |
| `OTP_EXTRACTOR_REDIS_URL` | `redis://localhost:6379/0` | Redis URL |
| `OTP_EXTRACTOR_USE_IN_MEMORY_REDIS` | `false` | Use in-memory limiter (tests / single-process) |

## Observability

- **Logging** — structlog with request IDs, latency, status, path, method.
- **Metrics** — `GET /metrics` returns counters and average latency.
- **Audit log** — `GET /audit?limit=N` dumps the most recent requests.

## Security model

- Secrets are processed in memory and never logged. The audit log records only
  metadata (`type`, `digits`, `period`, `algorithm`, `has_counter`).
- Multi-tenant isolation: API keys are HMAC-SHA256 hashed with
  `OTP_EXTRACTOR_API_KEY_HMAC_SECRET`. Argon2id is used for tenant passwords.
- Rate limiting is per-key or per-IP. Burst is configurable.
- All responses are explicitly opt-in about which fields include the secret —
  the `/v1/otp/parse` endpoint accepts `redact=true` to omit the secret from
  its response entirely.
