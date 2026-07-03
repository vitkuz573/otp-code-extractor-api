"""Pydantic models for the OTP Code Extractor API."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class OtpType(str, Enum):
    """OTP family."""

    TOTP = "totp"
    HOTP = "hotp"


class OtpAlgorithm(str, Enum):
    """Supported HMAC algorithms."""

    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


SUPPORTED_DIGITS = (6, 8)
SUPPORTED_PERIODS = (15, 30, 60, 90, 120, 300)


# ---------------------------------------------------------------------------
# Request / response models for OTP extraction
# ---------------------------------------------------------------------------


class OtpFromUriRequest(BaseModel):
    """Extract a code from an otpauth:// URI."""

    uri: str = Field(..., min_length=8, max_length=2048, description="otpauth:// URI")


class OtpFromSecretRequest(BaseModel):
    """Extract a code from a raw base32 secret."""

    secret: str = Field(
        ..., min_length=4, max_length=128, description="Base32-encoded shared secret"
    )
    algorithm: str | None = Field(None, description="Hashing algorithm (default SHA1)")
    digits: int | None = Field(None, description="Code length (default 6)")
    period: int | None = Field(None, description="TOTP period (default 30)")
    counter: int | None = Field(
        None, ge=0, description="HOTP counter (treats input as HOTP when set)"
    )


class OtpFromQrBase64Request(BaseModel):
    """Extract a code from a QR image supplied as base64."""

    image_base64: str = Field(..., min_length=16, description="Base64-encoded image bytes")
    mime_type: str | None = Field(
        None, description="Optional mime type, e.g. image/png (auto-detected if omitted)"
    )


class OtpFromStringRequest(BaseModel):
    """Auto-detect input shape (URI / secret / data-URI image) and extract."""

    input: str = Field(..., min_length=8, max_length=65536)


class OtpBatchItem(BaseModel):
    """A single batch entry."""

    kind: str = Field("auto", description="auto | uri | secret | qr_base64")
    uri: str | None = Field(None, description="For kind=uri")
    secret: str | None = Field(None, description="For kind=secret")
    image_base64: str | None = Field(None, description="For kind=qr_base64")
    algorithm: OtpAlgorithm | None = None
    digits: int | None = Field(None, ge=4, le=10)
    period: int | None = Field(None, ge=5, le=300)
    counter: int | None = Field(None, ge=0)
    label: str | None = Field(None, description="Caller-supplied label echoed back")


class OtpBatchRequest(BaseModel):
    """Batch extraction request."""

    items: list[OtpBatchItem] = Field(..., min_length=1, max_length=1000)


class OtpBatchError(BaseModel):
    """Per-item failure in a batch response."""

    index: int
    label: str | None = None
    code: str
    message: str


class OtpBatchResultItem(BaseModel):
    """Per-item success in a batch response."""

    index: int
    label: str | None = None
    code: str | None = None
    type: OtpType | None = None
    algorithm: OtpAlgorithm | None = None
    digits: int | None = None
    period: int | None = None
    remaining_seconds: int | None = None
    generated_at: str | None = None
    error: OtpBatchError | None = None


class OtpBatchResponse(BaseModel):
    """Batch extraction response."""

    total: int
    succeeded: int
    failed: int
    results: list[OtpBatchResultItem]


class OtpCodeResponse(BaseModel):
    """Successful code extraction."""

    code: str = Field(..., description="The generated OTP code")
    type: OtpType = Field(..., description="TOTP or HOTP")
    algorithm: OtpAlgorithm = Field(..., description="HMAC algorithm used")
    digits: int = Field(..., description="Code length")
    period: int | None = Field(None, description="TOTP period in seconds")
    counter: int | None = Field(None, description="HOTP counter value")
    issuer: str | None = Field(None, description="Issuer from the otpauth label")
    account: str | None = Field(None, description="Account label (e.g. alice@example.com)")
    label: str | None = Field(None, description="Raw otpauth label (issuer:account)")
    remaining_seconds: int | None = Field(
        None, description="Seconds until the current TOTP code expires"
    )
    generated_at: str = Field(..., description="UTC ISO timestamp of generation")


class OtpParseRequest(BaseModel):
    """Parse-only request (no code generation)."""

    uri: str | None = Field(None, description="otpauth:// URI")
    secret: str | None = Field(None, description="Raw base32 secret")
    algorithm: OtpAlgorithm | None = None
    digits: int | None = Field(None, ge=4, le=10)
    period: int | None = Field(None, ge=5, le=300)
    counter: int | None = Field(None, ge=0)
    redact: bool = Field(
        True,
        description="When true, the secret is omitted from the response (recommended).",
    )

    @field_validator("uri", "secret", mode="before")
    @classmethod
    def _empty_to_none(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value


class OtpParseResponse(BaseModel):
    """Parse-only response (no code)."""

    type: OtpType = Field(..., description="TOTP or HOTP")
    algorithm: OtpAlgorithm
    digits: int
    period: int | None = None
    counter: int | None = None
    issuer: str | None = None
    account: str | None = None
    label: str | None = None
    secret: str | None = Field(None, description="The secret, omitted when redact=true (default).")
    secret_redacted: bool = Field(False, description="True if the secret was redacted.")


# ---------------------------------------------------------------------------
# System / reference response models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    version: str
    qr_decoder_enabled: bool
    uptime_seconds: float


class ReadinessResponse(BaseModel):
    ready: bool
    qr_decoder_enabled: bool
    database_initialized: bool


class LivenessResponse(BaseModel):
    alive: bool


class MetricsResponse(BaseModel):
    uptime_seconds: float
    requests_total: int
    otp_requests: int
    qr_requests: int
    parse_requests: int
    batch_requests: int
    errors_total: int
    average_latency_ms: float


class AuditLogEntry(BaseModel):
    timestamp: str
    method: str
    path: str
    status: int
    request_id: str
    duration_ms: float
    api_key: str | None = None
    remote: str | None = None
    category: str | None = None


class AuditLogResponse(BaseModel):
    entries: list[AuditLogEntry]
    total: int


class AlgorithmListResponse(BaseModel):
    algorithms: list[str]


class DigitsListResponse(BaseModel):
    digits: list[int]


class PeriodsListResponse(BaseModel):
    periods: list[int]


class ErrorPayload(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Auth models
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=1, max_length=255)


class RegisterResponse(BaseModel):
    tenant_id: str
    email: str
    api_key: str


class ApiKeyResponse(BaseModel):
    id: str
    key_prefix: str
    name: str
    scopes: str
    is_active: bool
    created_at: str
    last_used_at: str | None


class RegenerateKeyResponse(BaseModel):
    api_key: str
    key_prefix: str
    message: str


class TenantAdminResponse(BaseModel):
    id: str
    email: str
    name: str
    is_active: bool
    is_admin: bool
    created_at: str
    api_key_count: int
    active_key_count: int


class MeResponse(BaseModel):
    tenant_id: str
    email: str
    name: str | None
    is_active: bool
    is_admin: bool
    api_key_count: int
    created_at: str | None


class UsagePeriodStat(BaseModel):
    period: str
    requests: int
    avg_latency_ms: float
    error_count: int


class UsageEndpointStat(BaseModel):
    endpoint: str
    count: int
    avg_latency_ms: float


class TenantUsageStatsResponse(BaseModel):
    tenant_id: str
    period: str
    days: int
    total_requests: int
    period_breakdown: list[UsagePeriodStat]
    by_endpoint: list[UsageEndpointStat]


class AllUsageStatsResponse(BaseModel):
    period: str
    days: int
    total_requests: int
    period_breakdown: list[UsagePeriodStat]
    top_tenants: list[dict]
    top_endpoints: list[UsageEndpointStat]
