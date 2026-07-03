"""Input validators for secrets, URIs and base32 strings."""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .config import Settings, get_settings
from .exceptions import (
    InvalidOtpUriError,
    InvalidSecretError,
    UnsupportedAlgorithmError,
    UnsupportedDigitsError,
    UnsupportedPeriodError,
)
from .models import OtpAlgorithm, SUPPORTED_DIGITS, SUPPORTED_PERIODS

_BASE32_ALPHABET = re.compile(r"^[A-Z2-7]+=*$")
_BASE32_NO_PADDING = re.compile(r"^[A-Z2-7]+$")


def normalize_secret(raw: str) -> str:
    """Strip whitespace and uppercase a base32 secret.

    Raises ``InvalidSecretError`` when the result is empty.
    """
    if raw is None:
        raise InvalidSecretError("Secret is required")
    cleaned = re.sub(r"\s+", "", raw).upper()
    if not cleaned:
        raise InvalidSecretError("Secret is empty")
    return cleaned


def is_valid_base32(secret: str, *, allow_padding: bool = True) -> bool:
    """Return True if ``secret`` looks like a valid base32 string."""
    if not secret:
        return False
    pattern = _BASE32_ALPHABET if allow_padding else _BASE32_NO_PADDING
    if not pattern.match(secret):
        return False
    try:
        # ``validate=True`` ensures the encoding is well-formed.
        base64.b32decode(secret, casefold=True)
        return True
    except (binascii.Error, ValueError):
        return False


def validate_algorithm(value: str | OtpAlgorithm | None, default: str | None = None) -> OtpAlgorithm:
    """Validate and normalize an algorithm name."""
    if value is None:
        value = default
    if value is None:
        return OtpAlgorithm.SHA1
    if isinstance(value, OtpAlgorithm):
        return value
    try:
        return OtpAlgorithm(str(value).upper())
    except ValueError as exc:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {value!r}. Supported: {[a.value for a in OtpAlgorithm]}"
        ) from exc


def validate_digits(value: int | None, default: int | None = None) -> int:
    """Validate a digit count and fall back to the default if None."""
    if value is None:
        value = default
    if value is None:
        return 6
    if value not in SUPPORTED_DIGITS:
        raise UnsupportedDigitsError(
            f"Unsupported digits: {value}. Supported: {list(SUPPORTED_DIGITS)}"
        )
    return value


def validate_period(value: int | None, default: int | None = None) -> int:
    """Validate a TOTP period and fall back to the default if None."""
    if value is None:
        value = default
    if value is None:
        return 30
    if value not in SUPPORTED_PERIODS:
        raise UnsupportedPeriodError(
            f"Unsupported period: {value}. Supported: {list(SUPPORTED_PERIODS)}"
        )
    return value


def validate_secret(raw: str | None, *, min_length: int = 16) -> str:
    """Normalise and validate a base32 secret."""
    secret = normalize_secret(raw or "")
    if not is_valid_base32(secret):
        raise InvalidSecretError("Secret is not valid base32")
    if len(secret) < min_length:
        raise InvalidSecretError(
            f"Secret too short: got {len(secret)} chars, need at least {min_length}"
        )
    return secret


def detect_input_kind(value: str) -> str:
    """Return one of ``uri``, ``data_uri``, ``secret`` based on the input shape."""
    if not value:
        return "unknown"
    stripped = value.strip()
    lower = stripped.lower()
    if lower.startswith("otpauth://"):
        return "uri"
    if lower.startswith("data:image/"):
        return "data_uri"
    # Bare base32 secrets are uppercase letters/digits 2-7 (and optional padding).
    if _BASE32_NO_PADDING.match(stripped) or _BASE32_ALPHABET.match(stripped):
        if len(stripped) >= 16 and is_valid_base32(stripped):
            return "secret"
    return "unknown"


def split_otpauth_label(label: str | None) -> tuple[str | None, str | None]:
    """Split ``Issuer:Account`` or ``/Issuer:Account`` into (issuer, account)."""
    if not label:
        return None, None
    text = label.strip()
    if text.startswith("/"):
        text = text[1:]
    if ":" in text:
        issuer, _, account = text.partition(":")
        return (issuer.strip() or None), (account.strip() or None)
    return None, text or None


def parse_otpauth_uri(uri: str, settings: Settings | None = None) -> dict:
    """Parse an otpauth:// URI into a normalised config dict.

    Raises ``InvalidOtpUriError`` when the URI is malformed.
    """
    settings = settings or get_settings()
    if not uri:
        raise InvalidOtpUriError("URI is empty")
    if not uri.lower().startswith("otpauth://"):
        raise InvalidOtpUriError("URI must start with otpauth://")

    try:
        parts = urlsplit(uri)
    except ValueError as exc:
        raise InvalidOtpUriError(f"Could not parse URI: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme != "otpauth":
        raise InvalidOtpUriError(f"Unsupported scheme: {scheme!r}")

    type_raw = parts.netloc.lower() or parts.path.lstrip("/").split("/", 1)[0].lower()
    if not type_raw:
        raise InvalidOtpUriError("OTP type is required (totp or hotp)")

    label = unquote(parts.path.lstrip("/")) if parts.path else ""

    query = parse_qs(parts.query, keep_blank_values=True)
    flat = {k.lower(): v[0] if len(v) == 1 else v for k, v in query.items()}

    raw_secret = flat.get("secret")
    if not raw_secret:
        raise InvalidOtpUriError("URI is missing the 'secret' parameter")

    secret = validate_secret(raw_secret, min_length=8)

    issuer_from_query = flat.get("issuer")
    issuer_from_label, account = split_otpauth_label(label)
    issuer = (issuer_from_query or issuer_from_label or "").strip() or None

    algorithm = validate_algorithm(flat.get("algorithm"), default=settings.default_algorithm)
    digits = validate_digits(
        _safe_int(flat.get("digits")), default=settings.default_digits
    )
    period = validate_period(
        _safe_int(flat.get("period")), default=settings.default_period
    )
    counter = _safe_int(flat.get("counter"))

    if type_raw == "totp":
        return {
            "type": "totp",
            "secret": secret,
            "algorithm": algorithm,
            "digits": digits,
            "period": period,
            "issuer": issuer,
            "account": account,
            "label": label or None,
            "counter": None,
        }
    if type_raw == "hotp":
        if counter is None:
            raise InvalidOtpUriError("HOTP URI is missing the 'counter' parameter")
        return {
            "type": "hotp",
            "secret": secret,
            "algorithm": algorithm,
            "digits": digits,
            "period": None,
            "issuer": issuer,
            "account": account,
            "label": label or None,
            "counter": counter,
        }
    raise InvalidOtpUriError(f"Unsupported OTP type: {type_raw!r}")


def _safe_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
