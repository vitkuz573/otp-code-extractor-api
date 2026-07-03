"""Redis-backed and in-memory sliding-window rate limiter."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Awaitable
from threading import Lock
from typing import Any

from .config import Settings, get_settings
from .logging_config import get_logger

logger = get_logger(__name__)


def rate_limit_key(client_id: str, path: str) -> str:
    """Build a Redis key for the sliding window of a (client, path) pair."""
    return f"rl:{client_id}:{path}"


class _InMemoryWindow:
    """Single-client sliding window backed by a deque of timestamps."""

    def __init__(self, window_seconds: float) -> None:
        self._window = window_seconds
        self._buckets: dict[str, deque[float]] = {}
        self._lock = Lock()

    def check(self, key: str, limit: int) -> tuple[bool, int, float]:
        """Return (allowed, remaining, reset_at_unix_ts)."""
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                reset_at = bucket[0] + self._window
                return False, 0, reset_at
            bucket.append(now)
            return True, max(0, limit - len(bucket)), now + self._window


class SlidingWindowLimiter:
    """Async limiter that prefers Redis and falls back to in-memory."""

    def __init__(self, redis_client: Any, window_seconds: float = 60.0) -> None:
        self._redis = redis_client
        self._window = window_seconds
        self._fallback = _InMemoryWindow(window_seconds)
        self._fallback_lock = asyncio.Lock()

    async def check(self, key: str, limit: int) -> tuple[bool, int, float]:
        """Allow up to ``limit`` requests per window for the given key."""
        if self._redis is None:
            async with self._fallback_lock:
                return self._fallback.check(key, limit)

        script = """
        local key = KEYS[1]
        local now_ms = tonumber(ARGV[1])
        local window_ms = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
        local count = redis.call('ZCARD', key)
        if count >= limit then
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local reset = now_ms + window_ms
            if oldest and oldest[2] then
                reset = tonumber(oldest[2]) + window_ms
            end
            return {0, 0, reset}
        end
        redis.call('ZADD', key, now_ms, now_ms .. ':' .. math.random())
        redis.call('PEXPIRE', key, window_ms)
        return {1, limit - count - 1, now_ms + window_ms}
        """
        now_ms = int(time.time() * 1000)
        window_ms = int(self._window * 1000)
        try:
            result = await self._redis.eval(script, 1, key, now_ms, window_ms, limit)
        except Exception as exc:  # noqa: BLE001
            logger.warning("rate_limit_redis_failed", extra={"err": str(exc)})
            async with self._fallback_lock:
                return self._fallback.check(key, limit)

        allowed = bool(int(result[0]))
        remaining = int(result[1])
        reset_at = float(result[2]) / 1000.0
        return allowed, remaining, reset_at


# ---------------------------------------------------------------------------
# Redis client lifecycle
# ---------------------------------------------------------------------------


_redis_client: Any = None
_redis_lock = Lock()


def _build_redis(url: str) -> Any:
    """Build an async Redis client from the URL."""
    try:
        import redis.asyncio as redis_async  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - guarded at install time
        raise RuntimeError("redis is required for production rate limiting") from exc
    return redis_async.from_url(url, decode_responses=True)


def get_redis(settings: Settings | None = None) -> Any:
    """Return the shared async Redis client, or None for in-memory mode."""
    global _redis_client
    settings = settings or get_settings()
    with _redis_lock:
        if settings.use_in_memory_redis:
            if _redis_client is not None:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        pass
                    else:
                        loop.run_until_complete(_redis_client.close())
                except Exception:  # noqa: BLE001
                    pass
            _redis_client = None
            return None
        if _redis_client is None:
            _redis_client = _build_redis(settings.redis_url)
        return _redis_client


def reset_redis_for_tests() -> None:
    """Discard the cached Redis client (used by tests)."""
    global _redis_client
    with _redis_lock:
        _redis_client = None


async def wait_for(predicate: Awaitable[bool] | Any, timeout: float = 5.0) -> bool:
    """Poll ``predicate`` until it returns truthy or the timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = await predicate() if asyncio.iscoroutine(predicate) else predicate()
        except Exception as exc:  # noqa: BLE001
            logger.debug("wait_for_predicate_failed", extra={"err": str(exc)})
            value = False
        if value:
            return True
        await asyncio.sleep(0.1)
    return False
