"""FastAPI application entry point."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import Settings, get_settings
from .db import Base, async_engine
from .exceptions import register_exception_handlers
from .logging_config import configure_logging, get_logger
from .middleware import register_middleware
from .observability import AuditLog, MetricsState
from .routes import router

_START_TIME = time.monotonic()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = settings or get_settings()
    configure_logging(settings)
    logger = get_logger(__name__)

    metrics = MetricsState()
    audit = AuditLog(max_size=1000)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # --- Database lifecycle ---
        async with async_engine().begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        db_url = settings.database_url
        if "@" in db_url:
            db_url = db_url.split("@", 1)[1]
        logger.info("database_connected", url=db_url)
        app.state.db_ready = True

        # --- QR decoder lifecycle ---
        if settings.qr_decoder_enabled:
            try:
                from .qr_decoder import get_decoder

                get_decoder()
                logger.info("qr_decoder_loaded")
            except Exception as exc:  # noqa: BLE001
                logger.warning("qr_decoder_load_failed", error=str(exc))
                app.state.db_ready = False
        else:
            logger.info("qr_decoder_disabled")

        app.state.settings = settings
        app.state.metrics = metrics
        app.state.audit = audit
        app.state.start_time = time.monotonic()

        yield

        # --- Shutdown ---
        await async_engine().dispose()
        logger.info("application_shutdown")

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Extract OTP codes from QR images, otpauth:// URIs and base32 "
            "secrets — fully offline, multi-tenant, ready for production."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.version = settings.app_version

    app.include_router(router)
    register_exception_handlers(app)
    register_middleware(app, settings)
    return app


def uptime() -> float:
    """Return the process uptime in seconds."""
    return time.monotonic() - _START_TIME


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "otp_code_extractor.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
