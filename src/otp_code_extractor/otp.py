"""OTP domain core: URI parsing, TOTP/HOTP code generation and orchestration.

This module wraps ``pyotp`` to provide a stable, exception-rich interface for
the rest of the service. Secrets never leave this module's call stack — every
caller receives a response object that contains only the *result* of the
computation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pyotp

from .config import Settings, get_settings
from .exceptions import (
    InvalidOtpInputError,
    OtpGenerationError,
    QrDecodeError,
    QrDisabledError,
    QrImageTooLargeError,
)
from .models import OtpAlgorithm, OtpType
from .qr_decoder import decode_qr_image_bytes
from .validators import (
    detect_input_kind,
    parse_otpauth_uri,
    validate_algorithm,
    validate_digits,
    validate_period,
    validate_secret,
)

__all__ = [
    "OtpConfig",
    "extract_code",
    "extract_code_from_uri",
    "extract_code_from_secret",
    "extract_code_from_qr",
    "extract_code_from_string",
    "parse_only",
    "build_pyotp",
]


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class OtpConfig:
    """Validated, normalised OTP parameters."""

    type: OtpType
    secret: str
    algorithm: OtpAlgorithm = OtpAlgorithm.SHA1
    digits: int = 6
    period: int = 30
    counter: int | None = None
    issuer: str | None = None
    account: str | None = None
    label: str | None = None

    def to_response_dict(self) -> dict[str, Any]:
        """Return the public-facing dict for this config (no secret)."""
        return {
            "type": self.type,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period if self.type == OtpType.TOTP else None,
            "counter": self.counter if self.type == OtpType.HOTP else None,
            "issuer": self.issuer,
            "account": self.account,
            "label": self.label,
        }


def _config_from_parsed(parsed: dict, settings: Settings) -> OtpConfig:
    """Build an OtpConfig from a parsed URI dict."""
    return OtpConfig(
        type=OtpType(parsed["type"]),
        secret=parsed["secret"],
        algorithm=parsed["algorithm"],
        digits=parsed["digits"],
        period=parsed["period"] or settings.default_period,
        counter=parsed["counter"],
        issuer=parsed["issuer"],
        account=parsed["account"],
        label=parsed["label"],
    )


def build_pyotp(config: OtpConfig) -> pyotp.TOTP | pyotp.HOTP:
    """Create a pyotp instance from a config."""
    digest = {
        OtpAlgorithm.SHA1: "sha1",
        OtpAlgorithm.SHA256: "sha256",
        OtpAlgorithm.SHA512: "sha512",
    }[config.algorithm]

    if config.type == OtpType.TOTP:
        return pyotp.TOTP(
            base64.b32encode(config.secret.encode()).decode().rstrip("="),
            digits=config.digits,
            digest=digest,
            interval=config.period,
        )
    if config.type == OtpType.HOTP:
        if config.counter is None:
            raise OtpGenerationError("HOTP requires a counter value")
        return pyotp.HOTP(
            base64.b32encode(config.secret.encode()).decode().rstrip("="),
            digits=config.digits,
            digest=digest,
        )
    raise OtpGenerationError(f"Unknown OTP type: {config.type}")


def generate_code(config: OtpConfig, *, now: datetime | None = None) -> str:
    """Generate the current code for the config."""
    instance = build_pyotp(config)
    if config.type == OtpType.TOTP:
        if now is None:
            return instance.now()
        return instance.at(now)
    if config.counter is None:
        raise OtpGenerationError("HOTP requires a counter value")
    return instance.at(config.counter)


def remaining_seconds(period: int, *, now: datetime | None = None) -> int:
    """Return the number of whole seconds left in the current TOTP slot."""
    moment = now or datetime.now(timezone.utc)
    epoch = int(moment.timestamp())
    return period - (epoch % period)


# ---------------------------------------------------------------------------
# Public extraction helpers
# ---------------------------------------------------------------------------


def _parse_common(
    *,
    uri: str | None = None,
    secret: str | None = None,
    algorithm: OtpAlgorithm | str | None = None,
    digits: int | None = None,
    period: int | None = None,
    counter: int | None = None,
    settings: Settings | None = None,
) -> OtpConfig:
    settings = settings or get_settings()
    if uri and secret:
        raise InvalidOtpInputError("Provide either 'uri' or 'secret', not both")
    if not uri and not secret:
        raise InvalidOtpInputError("Either 'uri' or 'secret' is required")

    if uri:
        parsed = parse_otpauth_uri(uri, settings=settings)
        config = _config_from_parsed(parsed, settings)
        if counter is not None and config.type == OtpType.HOTP:
            config.counter = counter
        return config

    secret_norm = validate_secret(secret)
    otp_type = OtpType.HOTP if counter is not None else OtpType.TOTP
    return OtpConfig(
        type=otp_type,
        secret=secret_norm,
        algorithm=validate_algorithm(algorithm, default=settings.default_algorithm),
        digits=validate_digits(digits, default=settings.default_digits),
        period=validate_period(period, default=settings.default_period),
        counter=counter,
        issuer=None,
        account=None,
        label=None,
    )


def extract_code_from_uri(uri: str, *, settings: Settings | None = None) -> tuple[OtpConfig, str]:
    """Parse ``uri`` and return (config, code)."""
    config = _parse_common(uri=uri, settings=settings)
    return config, generate_code(config)


def extract_code_from_secret(
    secret: str,
    *,
    algorithm: OtpAlgorithm | str | None = None,
    digits: int | None = None,
    period: int | None = None,
    counter: int | None = None,
    settings: Settings | None = None,
) -> tuple[OtpConfig, str]:
    """Generate a code from a raw secret."""
    config = _parse_common(
        secret=secret,
        algorithm=algorithm,
        digits=digits,
        period=period,
        counter=counter,
        settings=settings,
    )
    return config, generate_code(config)


def extract_code_from_qr(
    image_bytes: bytes,
    *,
    mime_type: str | None = None,
    settings: Settings | None = None,
) -> tuple[OtpConfig, str]:
    """Decode a QR image and return (config, code)."""
    settings = settings or get_settings()
    if not settings.qr_decoder_enabled:
        raise QrDisabledError("The QR decoder is disabled in this deployment")

    if len(image_bytes) > settings.max_qr_image_bytes:
        raise QrImageTooLargeError(
            f"QR image is too large: {len(image_bytes)} > {settings.max_qr_image_bytes}"
        )

    decoded = decode_qr_image_bytes(image_bytes, mime_type=mime_type)
    if not decoded:
        raise QrDecodeError("No QR code found in the supplied image")
    uri = next((d for d in decoded if d.lower().startswith("otpauth://")), None)
    if uri is None:
        raise QrDecodeError("QR code did not contain an otpauth:// URI")
    return extract_code_from_uri(uri, settings=settings)


def extract_code_from_string(
    value: str,
    *,
    settings: Settings | None = None,
) -> tuple[OtpConfig, str]:
    """Auto-detect the input shape and return (config, code)."""
    settings = settings or get_settings()
    kind = detect_input_kind(value)
    if kind == "uri":
        return extract_code_from_uri(value, settings=settings)
    if kind == "data_uri":
        try:
            header, b64 = value.split(",", 1)
        except ValueError as exc:
            raise InvalidOtpInputError("Malformed data URI") from exc
        mime = header[len("data:") :].split(";", 1)[0] or None
        try:
            image_bytes = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidOtpInputError(f"Could not decode base64 image: {exc}") from exc
        return extract_code_from_qr(image_bytes, mime_type=mime, settings=settings)
    if kind == "secret":
        return extract_code_from_secret(value, settings=settings)
    raise InvalidOtpInputError(
        "Could not detect input kind. Provide an otpauth:// URI, "
        "a base32 secret or a data:image/... URI."
    )


def extract_code(**kwargs: Any) -> tuple[OtpConfig, str]:
    """Dispatcher used by the HTTP layer.

    Accepts any of: ``uri``, ``secret``, ``image_bytes``, ``raw_string``.
    """
    settings = kwargs.pop("settings", None) or get_settings()
    if "raw_string" in kwargs:
        return extract_code_from_string(kwargs["raw_string"], settings=settings)
    if "image_bytes" in kwargs:
        return extract_code_from_qr(
            kwargs["image_bytes"],
            mime_type=kwargs.get("mime_type"),
            settings=settings,
        )
    if "uri" in kwargs:
        return extract_code_from_uri(kwargs["uri"], settings=settings)
    if "secret" in kwargs:
        return extract_code_from_secret(
            kwargs["secret"],
            algorithm=kwargs.get("algorithm"),
            digits=kwargs.get("digits"),
            period=kwargs.get("period"),
            counter=kwargs.get("counter"),
            settings=settings,
        )
    raise InvalidOtpInputError("No input provided to extract_code")


def parse_only(
    *,
    uri: str | None = None,
    secret: str | None = None,
    algorithm: OtpAlgorithm | str | None = None,
    digits: int | None = None,
    period: int | None = None,
    counter: int | None = None,
    redact: bool = True,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Parse a URI / secret without generating a code."""
    config = _parse_common(
        uri=uri,
        secret=secret,
        algorithm=algorithm,
        digits=digits,
        period=period,
        counter=counter,
        settings=settings,
    )
    data = config.to_response_dict()
    if redact:
        data["secret"] = None
        data["secret_redacted"] = True
    else:
        data["secret"] = config.secret
        data["secret_redacted"] = False
    return data
