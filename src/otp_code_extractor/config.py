"""Application configuration via environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the service."""

    model_config = SettingsConfigDict(
        env_prefix="OTP_EXTRACTOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "OTP Code Extractor API"
    app_version: str = "1.0.0"
    environment: Literal["development", "staging", "production", "test"] = "development"

    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_credentials: bool = False

    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 20

    auth_enabled: bool = False
    api_keys: list[str] = Field(default_factory=list)

    database_url: str = "sqlite+aiosqlite:///./otp_extractor.db"

    redis_url: str = "redis://localhost:6379/0"
    use_in_memory_redis: bool = False

    argon2_time_cost: int = 2
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

    api_key_hmac_secret: str = ""

    qr_decoder_enabled: bool = True
    qr_decoder_model: Literal["detector_v1", "detector_v2"] = "detector_v1"
    max_qr_image_bytes: int = 5 * 1024 * 1024

    default_algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"
    default_digits: int = 6
    default_period: int = 30

    metrics_enabled: bool = True
    audit_log_enabled: bool = True

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "console"

    max_batch_size: int = 100
    request_timeout_seconds: int = 30


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()


def reset_settings_cache() -> None:
    """Reset the cached settings (used by tests)."""
    get_settings.cache_clear()


def settings_from_env() -> Settings:
    """Re-read settings from the environment, bypassing the cache."""
    return Settings()
