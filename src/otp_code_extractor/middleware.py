"""HTTP middleware stack.

Order (outer → inner):

1. ``CORSMiddleware`` — handles browser pre-flight and exposes custom headers.
2. ``ResponseHeadersMiddleware`` — writes ``X-RateLimit-*`` headers on every
   response (success *and* error paths).
3. ``RateLimitMiddleware`` — Redis sliding window per tenant or client IP.
4. ``APIKeyAuthMiddleware`` — verifies the bearer token, populates
   ``request.state.tenant_*`` and enforces scopes.
5. ``RequestContextMiddleware`` — assigns the request ID, records metrics /
   audit, and dispatches the fire-and-forget ``UsageLog`` write.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import Settings
from .exceptions import AuthenticationError, AuthorizationError, RateLimitExceededError
from .logging_config import get_logger
from .observability import AuditLog, MetricsState, now_iso
from .redis_client import SlidingWindowLimiter, get_redis, rate_limit_key

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Route protection metadata
# ---------------------------------------------------------------------------


PUBLIC_PATHS = frozenset(
    {
        "/",
        "/health",
        "/livez",
        "/readyz",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/openapi.json?format=json",
        "/metrics",
    }
)


_SCOPE_TEMPLATES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(template), scope)
    for template, scope in (
        (r"^/v1/otp/from-qr$", "write"),
        (r"^/v1/otp/from-uri$", "write"),
        (r"^/v1/otp/from-secret$", "write"),
        (r"^/v1/otp/from-string$", "write"),
        (r"^/v1/otp/batch$", "write"),
        (r"^/v1/otp/parse$", "read"),
        # Admin routes
        (r"^/v1/admin/tenants$", "admin"),
        (r"^/v1/admin/tenants/[^/]+/api-keys$", "admin"),
        (r"^/v1/admin/metrics$", "admin"),
        (r"^/v1/admin/usage-stats$", "admin"),
        (r"^/v1/admin/usage-stats/[^/]+$", "admin"),
        # Auth endpoints
        (r"^/v1/auth/[^/]+$", "write"),
        (r"^/v1/auth/[^/]+/[^/]+$", "write"),
        (r"^/v1/auth/[^/]+/[^/]+/[^/]+$", "write"),
    )
)


def _category_for(path: str) -> str | None:
    if path.endswith("/from-qr"):
        return "qr"
    if path.endswith("/parse"):
        return "parse"
    if path.endswith("/batch"):
        return "batch"
    if path.startswith("/v1/otp/"):
        return "otp"
    return None


def _required_scope(path: str) -> str | None:
    for pattern, scope in _SCOPE_TEMPLATES:
        if pattern.match(path):
            return scope
    return None


def _has_scope(scopes_str: str, required: str) -> bool:
    """Check whether a comma-separated scope string satisfies ``required``.

    ``admin`` implies ``read`` and ``write``.
    """
    if not scopes_str:
        return False
    scopes = {s.strip() for s in scopes_str.split(",") if s.strip()}
    if required in scopes:
        return True
    if required in ("read", "write") and "admin" in scopes:
        return True
    return False


def _error_response(exc, request: Request) -> JSONResponse:
    """Build a JSONResponse for an OtpExtractorError."""
    request_id = getattr(request.state, "request_id", None)
    payload: dict = {"error": {"code": exc.code, "message": exc.message}}
    if exc.details:
        payload["error"]["details"] = exc.details
    if request_id:
        payload["request_id"] = request_id
    return JSONResponse(status_code=exc.http_status, content=payload)


# ---------------------------------------------------------------------------
# Middleware classes
# ---------------------------------------------------------------------------


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request ID, record metrics/audit and dispatch usage logging."""

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings
        self._background_tasks: set[asyncio.Task] = set()

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["x-request-id"] = request_id
            return response
        except Exception:
            logger.exception(
                "request_failed",
                method=request.method,
                path=request.url.path,
                request_id=request_id,
            )
            raise
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            category = _category_for(request.url.path)
            self._record_metrics(request, status_code, duration_ms, category)
            self._record_audit(request, status_code, request_id, duration_ms, category)
            self._dispatch_usage_log(request, status_code, duration_ms)

    def _record_metrics(
        self,
        request: Request,
        status: int,
        duration_ms: float,
        category: str | None,
    ) -> None:
        metrics: MetricsState | None = getattr(request.app.state, "metrics", None)
        if metrics is None:
            return
        metrics.record_request(duration_ms=duration_ms, status=status, category=category)

    def _record_audit(
        self,
        request: Request,
        status: int,
        request_id: str,
        duration_ms: float,
        category: str | None,
    ) -> None:
        audit: AuditLog | None = getattr(request.app.state, "audit", None)
        if audit is None or request.url.path == "/metrics":
            return
        audit.add(
            {
                "timestamp": now_iso(),
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "request_id": request_id,
                "duration_ms": round(duration_ms, 2),
                "api_key": getattr(request.state, "api_key", None),
                "remote": request.client.host if request.client else None,
                "category": category,
            }
        )

    def _dispatch_usage_log(
        self,
        request: Request,
        status: int,
        duration_ms: float,
    ) -> None:
        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        api_key_id = getattr(request.state, "api_key_id", None)
        method = request.method
        path = request.url.path
        task = loop.create_task(
            _write_usage_log(tenant_id, api_key_id, method, path, status, duration_ms)
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)


async def _write_usage_log(
    tenant_id: str,
    api_key_id: str | None,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
) -> None:
    """Persist a UsageLog row without blocking the request."""
    try:
        from .db import UsageLog, async_session_factory

        async with async_session_factory()() as db:
            db.add(
                UsageLog(
                    tenant_id=tenant_id,
                    api_key_id=api_key_id,
                    endpoint=path[:2048],
                    method=method,
                    status_code=status_code,
                    response_time_ms=round(duration_ms, 2),
                )
            )
            await db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.debug("usage_log_write_failed", extra={"err": str(exc)})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Redis-backed sliding-window rate limiter keyed on tenant or client IP."""

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings
        self._window = 60.0
        self._limiter = SlidingWindowLimiter(
            get_redis(settings), window_seconds=self._window
        )

    def _client_key(self, request: Request) -> str:
        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id:
            return str(tenant_id)
        if request.client:
            return f"ip:{request.client.host}"
        return "ip:unknown"

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self._settings.rate_limit_enabled or request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        limit = self._settings.rate_limit_per_minute
        key = rate_limit_key(self._client_key(request), request.url.path)

        if limit <= 0:
            request.state._rate_limit_limit = -1
            request.state._rate_limit_remaining = -1
            request.state._rate_limit_reset = 0
            return await call_next(request)

        try:
            allowed, remaining, reset_time = await self._limiter.check(key, limit)
        except Exception as exc:  # noqa: BLE001
            # Fail-open if the limiter is unavailable so the API stays responsive.
            logger.warning("rate_limit_unavailable", extra={"err": str(exc)})
            allowed, remaining, reset_time = True, max(0, limit - 1), time.time() + self._window

        request.state._rate_limit_limit = limit
        request.state._rate_limit_remaining = remaining
        request.state._rate_limit_reset = int(reset_time)

        if not allowed:
            return _error_response(
                RateLimitExceededError(
                    f"Rate limit exceeded: {limit} requests per minute",
                    details={
                        "limit": limit,
                        "reset_at": int(reset_time),
                    },
                ),
                request,
            )
        return await call_next(request)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Validate the bearer token against the API key database (with cache)."""

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    @staticmethod
    def _is_protected(path: str) -> bool:
        if path in PUBLIC_PATHS:
            return False
        if path.startswith("/docs") or path.startswith("/redoc"):
            return False
        return True

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self._settings.auth_enabled:
            return await call_next(request)
        if not self._is_protected(request.url.path):
            return await call_next(request)

        token = self._extract_token(request)
        if not token:
            return _error_response(
                AuthenticationError(
                    "API key required",
                    details={"hint": "Include Authorization: Bearer otp_... header"},
                ),
                request,
            )

        from .auth import validate_api_key
        from .db import async_session_factory

        try:
            async with async_session_factory()() as db:
                validated = await validate_api_key(db, token, self._settings)
        except Exception as exc:  # noqa: BLE001
            logger.exception("api_key_lookup_failed", extra={"err": str(exc)})
            return _error_response(AuthenticationError("Authentication backend error"), request)

        if validated is None:
            return _error_response(
                AuthenticationError("Invalid or revoked API key"), request
            )

        request.state.api_key = token
        request.state.api_key_id = validated.api_key_id
        request.state.tenant_id = validated.tenant_id
        request.state.api_scopes = validated.scopes
        request.state.key_prefix = validated.key_prefix

        required = _required_scope(request.url.path)
        if required and not _has_scope(validated.scopes, required):
            return _error_response(
                AuthorizationError(
                    f"Insufficient scope: requires '{required}'",
                    details={"required": required, "available": validated.scopes},
                ),
                request,
            )
        return await call_next(request)

    @staticmethod
    def _extract_token(request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if not auth:
            return ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return auth.strip()


class ResponseHeadersMiddleware(BaseHTTPMiddleware):
    """Add ``X-RateLimit-*`` headers to every response (incl. error paths)."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        if "X-RateLimit-Limit" in response.headers:
            return response

        limit = getattr(request.state, "_rate_limit_limit", None)
        remaining = getattr(request.state, "_rate_limit_remaining", None)
        reset_ts = getattr(request.state, "_rate_limit_reset", None)

        if limit is None:
            response.headers["X-RateLimit-Limit"] = "0"
            response.headers["X-RateLimit-Remaining"] = "0"
            response.headers["X-RateLimit-Reset"] = "0"
            return response

        if limit == -1:
            response.headers["X-RateLimit-Limit"] = "unlimited"
            response.headers["X-RateLimit-Remaining"] = "unlimited"
            response.headers["X-RateLimit-Reset"] = "unlimited"
            return response

        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, int(remaining or 0)))
        response.headers["X-RateLimit-Reset"] = str(int(reset_ts or 0))
        return response


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_middleware(app: FastAPI, settings: Settings) -> None:
    """Install the middleware stack on the app in the correct order."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "x-request-id",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "X-RateLimit-Limit",
            "X-RateLimit-remaining",
            "X-RateLimit-Reset",
        ],
    )
    app.add_middleware(ResponseHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, settings=settings)
    app.add_middleware(APIKeyAuthMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware, settings=settings)
