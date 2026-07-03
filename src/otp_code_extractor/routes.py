"""FastAPI routes for the OTP Code Extractor API."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import (
    admin_list_tenant_keys,
    get_all_usage_stats,
    get_system_metrics,
    get_tenant_usage_stats,
    list_tenant_api_keys,
    regenerate_api_key,
    register_tenant,
    revoke_api_key,
)
from .config import get_settings
from .db import ApiKey, Tenant, get_db, has_scope
from .exceptions import (
    ApiKeyNotFoundError,
    AuthenticationError,
    AuthorizationError,
    BatchTooLargeError,
    InvalidOtpInputError,
    OtpExtractorError,
    TenantNotFoundError,
)
from .models import (
    SUPPORTED_DIGITS,
    SUPPORTED_PERIODS,
    AlgorithmListResponse,
    AllUsageStatsResponse,
    ApiKeyResponse,
    AuditLogEntry,
    AuditLogResponse,
    DigitsListResponse,
    HealthResponse,
    LivenessResponse,
    MeResponse,
    MetricsResponse,
    OtpAlgorithm,
    OtpBatchError,
    OtpBatchItem,
    OtpBatchRequest,
    OtpBatchResponse,
    OtpBatchResultItem,
    OtpCodeResponse,
    OtpFromQrBase64Request,
    OtpFromSecretRequest,
    OtpFromStringRequest,
    OtpFromUriRequest,
    OtpParseRequest,
    OtpParseResponse,
    OtpType,
    PeriodsListResponse,
    ReadinessResponse,
    RegenerateKeyResponse,
    RegisterRequest,
    RegisterResponse,
    TenantAdminResponse,
    TenantUsageStatsResponse,
)
from .otp import (
    extract_code_from_qr,
    extract_code_from_secret,
    extract_code_from_string,
    extract_code_from_uri,
    parse_only,
)

router = APIRouter()


_START_TIME = time.monotonic()


# ---------------------------------------------------------------------------
# Auth Request / Response Models (also defined locally for backward parity)
# ---------------------------------------------------------------------------


class _ApiKeyListResponse(BaseModel):
    keys: list[ApiKeyResponse]


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------


@router.get("/", tags=["system"])
def root() -> dict:
    """Return basic service information."""
    settings = get_settings()
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
    }


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """Return service health and feature flags."""
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        qr_decoder_enabled=settings.qr_decoder_enabled,
        uptime_seconds=time.monotonic() - _START_TIME,
    )


@router.get("/livez", response_model=LivenessResponse, tags=["system"])
def livez() -> LivenessResponse:
    """Liveness probe (always returns 200 while the process is alive)."""
    return LivenessResponse(alive=True)


@router.get("/readyz", response_model=ReadinessResponse, tags=["system"])
def readyz(request: Request) -> ReadinessResponse:
    """Readiness probe (200 when core dependencies are up)."""
    settings = get_settings()
    db_ready = getattr(request.app.state, "db_ready", True)
    return ReadinessResponse(
        ready=db_ready,
        qr_decoder_enabled=settings.qr_decoder_enabled,
        database_initialized=db_ready,
    )


@router.get("/metrics", response_model=MetricsResponse, tags=["system"])
def metrics(request: Request) -> MetricsResponse:
    """Return a snapshot of in-process metrics."""
    snapshot = request.app.state.metrics.snapshot(
        uptime_seconds=time.monotonic() - _START_TIME,
    )
    return MetricsResponse(**snapshot)


@router.get("/audit", response_model=AuditLogResponse, tags=["system"])
def audit(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
) -> AuditLogResponse:
    """Return the most recent audit log entries (default 100)."""
    entries = request.app.state.audit.list(limit=limit)
    return AuditLogResponse(
        entries=[AuditLogEntry(**e) for e in entries],
        total=len(entries),
    )


@router.get("/audit/export", tags=["system"])
def audit_export(
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = Query(1000, ge=1, le=10000),
):
    """Export audit log entries as JSON or CSV download."""
    from fastapi.responses import JSONResponse, Response

    entries = request.app.state.audit.list(limit=limit)
    if format == "csv":
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "timestamp",
                "method",
                "path",
                "status",
                "duration_ms",
                "request_id",
                "api_key",
                "remote",
                "category",
            ]
        )
        for entry in entries:
            writer.writerow(
                [
                    entry.get("timestamp", ""),
                    entry.get("method", ""),
                    entry.get("path", ""),
                    entry.get("status", ""),
                    entry.get("duration_ms", ""),
                    entry.get("request_id", ""),
                    entry.get("api_key") or "",
                    entry.get("remote") or "",
                    entry.get("category") or "",
                ]
            )
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit-log.csv"},
        )
    return JSONResponse(
        content={"total": len(entries), "entries": entries},
        headers={"Content-Disposition": "attachment; filename=audit-log.json"},
    )


# ---------------------------------------------------------------------------
# Reference endpoints
# ---------------------------------------------------------------------------


@router.get("/v1/otp/algorithms", response_model=AlgorithmListResponse, tags=["otp"])
def list_algorithms() -> AlgorithmListResponse:
    """Return the supported HMAC algorithms."""
    return AlgorithmListResponse(algorithms=[a.value for a in OtpAlgorithm])


@router.get("/v1/otp/digits", response_model=DigitsListResponse, tags=["otp"])
def list_digits() -> DigitsListResponse:
    """Return the supported code lengths."""
    return DigitsListResponse(digits=list(SUPPORTED_DIGITS))


@router.get("/v1/otp/periods", response_model=PeriodsListResponse, tags=["otp"])
def list_periods() -> PeriodsListResponse:
    """Return the supported TOTP periods."""
    return PeriodsListResponse(periods=list(SUPPORTED_PERIODS))


# ---------------------------------------------------------------------------
# OTP extraction endpoints
# ---------------------------------------------------------------------------


def _code_response(config, code: str) -> OtpCodeResponse:
    """Build an ``OtpCodeResponse`` from a config and a generated code."""
    from .otp import remaining_seconds

    return OtpCodeResponse(
        code=code,
        type=config.type,
        algorithm=config.algorithm,
        digits=config.digits,
        period=config.period if config.type == OtpType.TOTP else None,
        counter=config.counter if config.type == OtpType.HOTP else None,
        issuer=config.issuer,
        account=config.account,
        label=config.label,
        remaining_seconds=remaining_seconds(config.period) if config.type == OtpType.TOTP else None,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
    )


@router.post(
    "/v1/otp/from-uri",
    response_model=OtpCodeResponse,
    tags=["otp"],
)
def from_uri(payload: OtpFromUriRequest) -> OtpCodeResponse:
    """Extract a code from an ``otpauth://`` URI."""
    config, code = extract_code_from_uri(payload.uri)
    return _code_response(config, code)


@router.post(
    "/v1/otp/from-secret",
    response_model=OtpCodeResponse,
    tags=["otp"],
)
def from_secret(payload: OtpFromSecretRequest) -> OtpCodeResponse:
    """Extract a code from a raw base32 secret."""
    config, code = extract_code_from_secret(
        payload.secret,
        algorithm=payload.algorithm,
        digits=payload.digits,
        period=payload.period,
        counter=payload.counter,
    )
    return _code_response(config, code)


@router.post(
    "/v1/otp/from-qr",
    response_model=OtpCodeResponse,
    tags=["otp"],
)
async def from_qr(
    file: UploadFile = File(..., description="QR image (PNG / JPEG / ...)"),
) -> OtpCodeResponse:
    """Extract a code from a QR image uploaded as multipart/form-data."""
    image_bytes = await file.read()
    config, code = extract_code_from_qr(image_bytes, mime_type=file.content_type)
    return _code_response(config, code)


@router.post(
    "/v1/otp/from-qr-base64",
    response_model=OtpCodeResponse,
    tags=["otp"],
)
def from_qr_base64(payload: OtpFromQrBase64Request) -> OtpCodeResponse:
    """Extract a code from a QR image supplied as JSON base64."""
    image_bytes = _b64_to_bytes(payload.image_base64)
    config, code = extract_code_from_qr(image_bytes, mime_type=payload.mime_type)
    return _code_response(config, code)


def _b64_to_bytes(b64_payload: str) -> bytes:
    import base64
    import binascii

    try:
        return base64.b64decode(b64_payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidOtpInputError(f"Could not decode base64 image: {exc}") from exc


@router.post(
    "/v1/otp/from-string",
    response_model=OtpCodeResponse,
    tags=["otp"],
)
def from_string(payload: OtpFromStringRequest) -> OtpCodeResponse:
    """Auto-detect URI / secret / data-URI image and extract a code."""
    config, code = extract_code_from_string(payload.input)
    return _code_response(config, code)


@router.post(
    "/v1/otp/parse",
    response_model=OtpParseResponse,
    tags=["otp"],
)
def parse(payload: OtpParseRequest) -> OtpParseResponse:
    """Parse a URI / secret without generating a code."""
    data = parse_only(
        uri=payload.uri,
        secret=payload.secret,
        algorithm=payload.algorithm,
        digits=payload.digits,
        period=payload.period,
        counter=payload.counter,
        redact=payload.redact,
    )
    return OtpParseResponse(**data)


@router.post(
    "/v1/otp/batch",
    response_model=OtpBatchResponse,
    tags=["otp"],
)
def batch(payload: OtpBatchRequest) -> OtpBatchResponse:
    """Extract codes for a batch of mixed input items."""
    settings = get_settings()
    if len(payload.items) > settings.max_batch_size:
        raise BatchTooLargeError(
            f"Batch size {len(payload.items)} exceeds limit {settings.max_batch_size}"
        )
    results: list[OtpBatchResultItem] = []
    succeeded = 0
    failed = 0
    for index, item in enumerate(payload.items):
        try:
            code_resp = _process_batch_item(item)
            results.append(
                OtpBatchResultItem(
                    index=index,
                    label=item.label,
                    code=code_resp.code,
                    type=code_resp.type,
                    algorithm=code_resp.algorithm,
                    digits=code_resp.digits,
                    period=code_resp.period,
                    remaining_seconds=code_resp.remaining_seconds,
                    generated_at=code_resp.generated_at,
                )
            )
            succeeded += 1
        except OtpExtractorError as exc:
            results.append(
                OtpBatchResultItem(
                    index=index,
                    label=item.label,
                    error=OtpBatchError(
                        index=index,
                        label=item.label,
                        code=exc.code,
                        message=exc.message,
                    ),
                )
            )
            failed += 1
        except Exception as exc:  # noqa: BLE001
            results.append(
                OtpBatchResultItem(
                    index=index,
                    label=item.label,
                    error=OtpBatchError(
                        index=index,
                        label=item.label,
                        code="batch_item_failed",
                        message=str(exc),
                    ),
                )
            )
            failed += 1
    return OtpBatchResponse(total=len(results), succeeded=succeeded, failed=failed, results=results)


def _process_batch_item(item: OtpBatchItem) -> OtpCodeResponse:
    """Dispatch a single batch item to the right extractor."""
    kind = (item.kind or "auto").lower()
    if kind in ("uri",) or (
        kind == "auto" and item.uri and item.uri.lower().startswith("otpauth://")
    ):
        if not item.uri:
            raise InvalidOtpInputError("kind=uri requires 'uri'")
        config, code = extract_code_from_uri(item.uri)
        return _code_response(config, code)
    if kind == "secret" or (kind == "auto" and item.secret):
        config, code = extract_code_from_secret(
            item.secret or "",
            algorithm=item.algorithm,
            digits=item.digits,
            period=item.period,
            counter=item.counter,
        )
        return _code_response(config, code)
    if kind == "qr_base64" or (kind == "auto" and item.image_base64):
        if not item.image_base64:
            raise InvalidOtpInputError("kind=qr_base64 requires 'image_base64'")
        image_bytes = _b64_to_bytes(item.image_base64)
        config, code = extract_code_from_qr(image_bytes, mime_type=None)
        return _code_response(config, code)
    if kind == "auto":
        raise InvalidOtpInputError("auto-detect could not determine input kind for the batch item")
    raise InvalidOtpInputError(f"Unknown batch kind: {kind!r}")


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------


class _RegisterRequestAlias(RegisterRequest):
    """Pydantic alias used purely for OpenAPI consistency."""


@router.post("/v1/auth/register", response_model=RegisterResponse, tags=["auth"])
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)) -> RegisterResponse:
    """Register a new tenant account.

    Returns the tenant record and a raw API key that is shown only at creation
    time. Store this key securely — it cannot be retrieved again.
    """
    settings = get_settings()
    tenant, raw_key = await register_tenant(db, req.email, req.password, req.name, settings)
    await db.commit()
    return RegisterResponse(
        tenant_id=tenant.id,
        email=tenant.email,
        api_key=raw_key,
    )


@router.get(
    "/v1/auth/api-keys",
    response_model=list[ApiKeyResponse],
    tags=["auth"],
)
async def list_keys(request: Request, db: AsyncSession = Depends(get_db)) -> list[ApiKeyResponse]:
    """List all API keys for the authenticated tenant."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise AuthenticationError("Authenticated tenant required")
    keys = await list_tenant_api_keys(db, tenant_id)
    return [
        ApiKeyResponse(
            id=k.id,
            key_prefix=k.key_prefix,
            name=k.name,
            scopes=k.scopes,
            is_active=k.is_active,
            created_at=k.created_at.isoformat() if k.created_at else "",
            last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        )
        for k in keys
    ]


@router.post("/v1/auth/api-keys/{key_id}/revoke", tags=["auth"])
async def revoke_key(key_id: str, request: Request, db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke an API key belonging to the authenticated tenant."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise AuthenticationError("Authenticated tenant required")
    ok = await revoke_api_key(db, key_id, tenant_id)
    if not ok:
        raise ApiKeyNotFoundError(f"API key {key_id!r} not found or already revoked.")
    await db.commit()
    return {"message": "API key revoked", "key_id": key_id}


@router.post(
    "/v1/auth/api-keys/{key_id}/regenerate",
    response_model=RegenerateKeyResponse,
    tags=["auth"],
)
async def regenerate_key(
    key_id: str, request: Request, db: AsyncSession = Depends(get_db)
) -> RegenerateKeyResponse:
    """Regenerate an API key, replacing it with a new one."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise AuthenticationError("Authenticated tenant required")
    settings = get_settings()
    result = await regenerate_api_key(db, key_id, tenant_id, settings)
    if result is None:
        raise ApiKeyNotFoundError(f"API key {key_id!r} not found or already revoked.")
    api_key, raw_key = result
    await db.commit()
    return RegenerateKeyResponse(
        api_key=raw_key,
        key_prefix=api_key.key_prefix,
        message=(
            "API key regenerated successfully. "
            "Store the new key securely — it cannot be retrieved again."
        ),
    )


@router.get("/v1/auth/me", response_model=MeResponse, tags=["auth"])
async def get_me(request: Request, db: AsyncSession = Depends(get_db)) -> MeResponse:
    """Return the authenticated tenant's profile summary."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise AuthorizationError("Authenticated tenant required")
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise TenantNotFoundError(f"Tenant {tenant_id!r} not found")
    key_count = (
        await db.execute(
            select(func.count(ApiKey.id)).where(
                ApiKey.tenant_id == tenant_id, ApiKey.is_active.is_(True)
            )
        )
    ).scalar_one()
    return MeResponse(
        tenant_id=tenant_id,
        email=tenant.email,
        name=tenant.name,
        is_active=tenant.is_active,
        is_admin=tenant.is_admin,
        api_key_count=int(key_count or 0),
        created_at=tenant.created_at.isoformat() if tenant.created_at else None,
    )


@router.get(
    "/v1/auth/usage-stats",
    response_model=TenantUsageStatsResponse,
    tags=["auth"],
)
async def get_my_usage_stats(
    request: Request,
    period: str = Query("daily", pattern="^(daily|monthly)$"),
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
) -> TenantUsageStatsResponse:
    """Return usage statistics for the authenticated tenant."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise AuthorizationError("Authenticated tenant required")
    stats = await get_tenant_usage_stats(db, tenant_id, period, days)
    return TenantUsageStatsResponse(**stats)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/v1/admin/tenants",
    response_model=list[TenantAdminResponse],
    tags=["admin"],
)
async def admin_tenants(
    request: Request,
    db: AsyncSession = Depends(get_db),
    search: str | None = Query(None, description="Filter by email substring"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[TenantAdminResponse]:
    """List all tenants. Requires admin scope."""
    api_scopes = getattr(request.state, "api_scopes", "")
    if not has_scope(api_scopes, "admin"):
        raise AuthorizationError("Admin scope required.")

    query = select(Tenant)
    if search:
        query = query.where(Tenant.email.ilike(f"%{search}%"))
    if is_active is not None:
        query = query.where(Tenant.is_active == is_active)
    query = query.order_by(Tenant.created_at.desc()).limit(limit).offset(offset)
    tenants = (await db.execute(query)).scalars().all()

    results: list[TenantAdminResponse] = []
    for t in tenants:
        keys = (await db.execute(select(ApiKey.id).where(ApiKey.tenant_id == t.id))).all()
        active = (
            await db.execute(
                select(func.count(ApiKey.id)).where(
                    ApiKey.tenant_id == t.id, ApiKey.is_active.is_(True)
                )
            )
        ).scalar_one()
        results.append(
            TenantAdminResponse(
                id=t.id,
                email=t.email,
                name=t.name,
                is_active=t.is_active,
                is_admin=t.is_admin,
                created_at=t.created_at.isoformat() if t.created_at else "",
                api_key_count=len(keys),
                active_key_count=int(active or 0),
            )
        )
    return results


@router.get(
    "/v1/admin/tenants/{tenant_id}/api-keys",
    response_model=list[ApiKeyResponse],
    tags=["admin"],
)
async def admin_tenant_keys(
    tenant_id: str, request: Request, db: AsyncSession = Depends(get_db)
) -> list[ApiKeyResponse]:
    """List all API keys for a specific tenant. Requires admin scope."""
    api_scopes = getattr(request.state, "api_scopes", "")
    if not has_scope(api_scopes, "admin"):
        raise AuthorizationError("Admin scope required.")
    keys = await admin_list_tenant_keys(db, tenant_id)
    return [
        ApiKeyResponse(
            id=k.id,
            key_prefix=k.key_prefix,
            name=k.name,
            scopes=k.scopes,
            is_active=k.is_active,
            created_at=k.created_at.isoformat() if k.created_at else "",
            last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        )
        for k in keys
    ]


@router.get(
    "/v1/admin/metrics",
    response_model=dict,
    tags=["admin"],
)
async def admin_metrics(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return system-wide metrics. Requires admin scope."""
    api_scopes = getattr(request.state, "api_scopes", "")
    if not has_scope(api_scopes, "admin"):
        raise AuthorizationError("Admin scope required.")
    return await get_system_metrics(db)


@router.get(
    "/v1/admin/usage-stats",
    response_model=AllUsageStatsResponse,
    tags=["admin"],
)
async def admin_usage_stats(
    request: Request,
    period: str = Query("daily", pattern="^(daily|monthly)$"),
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
) -> AllUsageStatsResponse:
    """Return system-wide usage statistics. Requires admin scope."""
    api_scopes = getattr(request.state, "api_scopes", "")
    if not has_scope(api_scopes, "admin"):
        raise AuthorizationError("Admin scope required.")
    stats = await get_all_usage_stats(db, period, days)
    return AllUsageStatsResponse(**stats)


@router.get(
    "/v1/admin/usage-stats/{target_tenant_id}",
    response_model=TenantUsageStatsResponse,
    tags=["admin"],
)
async def admin_tenant_usage_stats(
    target_tenant_id: str,
    request: Request,
    period: str = Query("daily", pattern="^(daily|monthly)$"),
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
) -> TenantUsageStatsResponse:
    """Return usage statistics for a specific tenant. Requires admin scope."""
    api_scopes = getattr(request.state, "api_scopes", "")
    if not has_scope(api_scopes, "admin"):
        raise AuthorizationError("Admin scope required.")
    stats = await get_tenant_usage_stats(db, target_tenant_id, period, days)
    return TenantUsageStatsResponse(**stats)
