"""Custom exceptions and FastAPI handlers."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .logging_config import get_logger

_UNPROCESSABLE = getattr(
    status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY
)

logger = get_logger(__name__)


class OtpExtractorError(Exception):
    """Base error for the OTP Code Extractor API."""

    code: str = "otp_extractor_error"
    http_status: int = status.HTTP_400_BAD_REQUEST

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        http_status: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if http_status is not None:
            self.http_status = http_status
        self.details = details or {}


class InvalidOtpInputError(OtpExtractorError):
    code = "invalid_otp_input"
    http_status = status.HTTP_400_BAD_REQUEST


class InvalidSecretError(OtpExtractorError):
    code = "invalid_secret"
    http_status = status.HTTP_400_BAD_REQUEST


class InvalidOtpUriError(OtpExtractorError):
    code = "invalid_otp_uri"
    http_status = status.HTTP_400_BAD_REQUEST


class UnsupportedAlgorithmError(OtpExtractorError):
    code = "unsupported_algorithm"
    http_status = status.HTTP_400_BAD_REQUEST


class UnsupportedDigitsError(OtpExtractorError):
    code = "unsupported_digits"
    http_status = status.HTTP_400_BAD_REQUEST


class UnsupportedPeriodError(OtpExtractorError):
    code = "unsupported_period"
    http_status = status.HTTP_400_BAD_REQUEST


class QrDecodeError(OtpExtractorError):
    code = "qr_decode_failed"
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY


class QrDisabledError(OtpExtractorError):
    code = "qr_decoder_disabled"
    http_status = status.HTTP_503_SERVICE_UNAVAILABLE


class QrImageTooLargeError(OtpExtractorError):
    code = "qr_image_too_large"
    http_status = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


class OtpGenerationError(OtpExtractorError):
    code = "otp_generation_failed"
    http_status = status.HTTP_500_INTERNAL_SERVER_ERROR


class BatchTooLargeError(OtpExtractorError):
    code = "batch_too_large"
    http_status = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


class RateLimitExceededError(OtpExtractorError):
    code = "rate_limit_exceeded"
    http_status = status.HTTP_429_TOO_MANY_REQUESTS


class AuthenticationError(OtpExtractorError):
    code = "authentication_required"
    http_status = status.HTTP_401_UNAUTHORIZED


class TenantAlreadyExistsError(OtpExtractorError):
    code = "tenant_already_exists"
    http_status = status.HTTP_409_CONFLICT


class TenantNotFoundError(OtpExtractorError):
    code = "tenant_not_found"
    http_status = status.HTTP_404_NOT_FOUND


class ApiKeyNotFoundError(OtpExtractorError):
    code = "api_key_not_found"
    http_status = status.HTTP_404_NOT_FOUND


class InvalidApiKeyError(OtpExtractorError):
    code = "invalid_api_key"
    http_status = status.HTTP_401_UNAUTHORIZED


class InsufficientScopeError(OtpExtractorError):
    code = "insufficient_scope"
    http_status = status.HTTP_403_FORBIDDEN


class AuthorizationError(OtpExtractorError):
    code = "authorization_failed"
    http_status = status.HTTP_403_FORBIDDEN


def _error_payload(
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    if request_id:
        payload["request_id"] = request_id
    return payload


def register_exception_handlers(app: FastAPI) -> None:
    """Register handlers for all custom and framework exceptions."""

    @app.exception_handler(OtpExtractorError)
    async def handle_otp_extractor_error(
        request: Request, exc: OtpExtractorError
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        logger.warning(
            "otp_extractor_error",
            code=exc.code,
            message=exc.message,
            path=request.url.path,
            request_id=request_id,
        )
        return JSONResponse(
            status_code=exc.http_status,
            content=_error_payload(exc.code, exc.message, exc.details, request_id),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=_UNPROCESSABLE,
            content=_error_payload(
                "validation_error",
                "Request validation failed",
                {"errors": exc.errors()},
                request_id,
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unhandled_error(
        request: Request, exc: Exception
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "unhandled_error",
            path=request.url.path,
            request_id=request_id,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_payload(
                "internal_error",
                "An internal error occurred",
                request_id=request_id,
            ),
        )
