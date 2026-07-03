# Security

The OTP Code Extractor API handles **OTP secrets** which can be used to generate
authentication codes for the issuing account. Treat them like passwords.

## Threat model

The service is designed for:

- **Trusted operators** running the API inside a private network or behind an
  authenticated reverse proxy.
- **Mutually distrustful tenants** that share the same deployment but have
  isolated API keys, scopes and rate limits.

It is **not** designed to be exposed to the public internet without:

1. TLS termination at a trusted proxy.
2. `OTP_EXTRACTOR_AUTH_ENABLED=true`.
3. A strong, unique `OTP_EXTRACTOR_API_KEY_HMAC_SECRET`.

## What the service does NOT do

- It does **not** call any third-party service.
- It does **not** transmit secrets off the host.
- It does **not** log secrets, codes, or any portion of the secret.
- It does **not** persist secrets — they live in the request and are dropped
  after the response is built.
- It does **not** perform any payment, billing or account-issuing operation.

## Secret handling

- Secrets arrive in the request body, in a QR image, or in a CLI argument.
- They are normalised to upper-case base32 and held in memory only for the
  duration of the request.
- They are **never** written to logs, audit records or the database.
- The `/v1/otp/parse` endpoint echoes the secret back to the caller unless
  `redact=true` is passed.

## Recommended production hardening

1. Set a strong `OTP_EXTRACTOR_API_KEY_HMAC_SECRET` (32+ random bytes).
2. Run behind TLS (nginx, Caddy, ALB, Cloudflare, etc.).
3. Keep `OTP_EXTRACTOR_AUTH_ENABLED=true`.
4. Set restrictive `OTP_EXTRACTOR_CORS_ORIGINS` to your client origins only.
5. Lock down `OTP_EXTRACTOR_RATE_LIMIT_PER_MINUTE` to a value that matches
   your legitimate traffic.
6. Run the process as a non-root user (the Docker image already does this).
7. Keep `pyotp`, `qreader` and `opencv-python-headless` patched.
8. Run `make audit` (or your equivalent) periodically to look for new CVEs.

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive bugs. Email
`vitkuz573@gmail.com` with a description and reproduction steps. We will
respond within 72 hours and coordinate a fix before any public disclosure.
