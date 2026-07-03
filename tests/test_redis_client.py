"""Tests for the Redis / in-memory rate limiter."""

from __future__ import annotations

import time

import pytest

from otp_code_extractor.redis_client import (
    SlidingWindowLimiter,
    _InMemoryWindow,
    rate_limit_key,
)


class TestInMemoryWindow:
    def test_allows_up_to_limit(self):
        win = _InMemoryWindow(window_seconds=60.0)
        allowed, remaining, reset = win.check("k", 5)
        assert allowed is True
        assert remaining == 4
        assert reset > time.time()

    def test_blocks_after_limit(self):
        win = _InMemoryWindow(window_seconds=60.0)
        for _ in range(3):
            allowed, _, _ = win.check("k", 3)
            assert allowed is True
        allowed, remaining, _ = win.check("k", 3)
        assert allowed is False
        assert remaining == 0

    def test_keys_are_independent(self):
        win = _InMemoryWindow(window_seconds=60.0)
        for _ in range(3):
            win.check("a", 3)
        allowed_a, _, _ = win.check("a", 3)
        allowed_b, _, _ = win.check("b", 3)
        assert allowed_a is False
        assert allowed_b is True


class TestSlidingWindowLimiter:
    @pytest.mark.asyncio
    async def test_in_memory_fallback(self):
        limiter = SlidingWindowLimiter(redis_client=None, window_seconds=60.0)
        for _ in range(5):
            allowed, _, _ = await limiter.check("k", 5)
            assert allowed is True
        allowed, _, _ = await limiter.check("k", 5)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_redis_failure_falls_back_to_memory(self):
        class Boom:
            async def eval(self, *args, **kwargs):
                raise RuntimeError("redis is down")

        limiter = SlidingWindowLimiter(redis_client=Boom(), window_seconds=60.0)
        allowed, remaining, _ = await limiter.check("k", 3)
        assert allowed is True
        assert remaining == 2


class TestRateLimitKey:
    def test_builds_namespaced_key(self):
        assert rate_limit_key("tenant1", "/v1/otp/from-uri") == "rl:tenant1:/v1/otp/from-uri"

    def test_ip_fallback(self):
        assert rate_limit_key("ip:1.2.3.4", "/x").startswith("rl:ip:1.2.3.4:")
