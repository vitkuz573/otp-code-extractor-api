"""In-memory metrics counters and an audit log ring buffer."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import Lock

from .logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class MetricsState:
    """Lightweight in-process metrics."""

    requests_total: int = 0
    otp_requests: int = 0
    qr_requests: int = 0
    parse_requests: int = 0
    batch_requests: int = 0
    errors_total: int = 0
    latency_sum_ms: float = 0.0
    latency_count: int = 0

    def record_request(self, duration_ms: float, status: int, category: str | None = None) -> None:
        self.requests_total += 1
        if status >= 400:
            self.errors_total += 1
        self.latency_sum_ms += duration_ms
        self.latency_count += 1
        if category == "otp":
            self.otp_requests += 1
        elif category == "qr":
            self.qr_requests += 1
        elif category == "parse":
            self.parse_requests += 1
        elif category == "batch":
            self.batch_requests += 1

    def snapshot(self, uptime_seconds: float) -> dict:
        avg = self.latency_sum_ms / self.latency_count if self.latency_count else 0.0
        return {
            "uptime_seconds": uptime_seconds,
            "requests_total": self.requests_total,
            "otp_requests": self.otp_requests,
            "qr_requests": self.qr_requests,
            "parse_requests": self.parse_requests,
            "batch_requests": self.batch_requests,
            "errors_total": self.errors_total,
            "average_latency_ms": round(avg, 3),
        }


@dataclass
class AuditLog:
    """Ring buffer of recent requests."""

    max_size: int = 1000
    _entries: deque[dict] = field(default_factory=deque)
    _lock: Lock = field(default_factory=Lock)

    def add(self, entry: dict) -> None:
        with self._lock:
            self._entries.appendleft(entry)
            while len(self._entries) > self.max_size:
                self._entries.pop()

    def list(self, limit: int | None = None) -> list[dict]:
        with self._lock:
            items = list(self._entries)
        if limit is not None:
            return items[:limit]
        return items


def make_metrics() -> MetricsState:
    """Create a fresh metrics state."""
    return MetricsState()


def make_audit_log(max_size: int = 1000) -> AuditLog:
    """Create a fresh audit log."""
    return AuditLog(max_size=max_size)


def now_iso() -> str:
    """ISO 8601 UTC timestamp."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
