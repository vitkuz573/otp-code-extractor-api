"""Local performance benchmark for the OTP extractor.

Run with ``make benchmark``.  Spawns ``concurrency`` workers, each making
``requests`` calls to ``/v1/otp/from-secret``.  Reports p50 / p95 / p99 / RPS.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time
from collections.abc import Iterable

import httpx


DEFAULT_URL = "http://localhost:8000"
DEFAULT_CONCURRENCY = 8
DEFAULT_REQUESTS = 1000
SECRET = "JBSWY3DPEHPK3PXP"


async def _worker(client: httpx.AsyncClient, url: str, n: int, results: list[float]) -> None:
    for _ in range(n):
        start = time.perf_counter()
        r = await client.post(
            f"{url}/v1/otp/from-secret", json={"secret": SECRET}
        )
        r.raise_for_status()
        results.append((time.perf_counter() - start) * 1000)


async def _run(url: str, concurrency: int, total: int) -> None:
    per_worker = total // concurrency
    async with httpx.AsyncClient(timeout=30.0) as client:
        results: list[float] = []
        await asyncio.gather(
            *(_worker(client, url, per_worker, results) for _ in range(concurrency))
        )

    durations = sorted(results)
    p50 = _percentile(durations, 50)
    p95 = _percentile(durations, 95)
    p99 = _percentile(durations, 99)
    mean = statistics.fmean(durations)
    rps = len(durations) / (sum(durations) / 1000 / concurrency)
    print(f"requests:  {len(durations)}")
    print(f"mean:      {mean:.2f} ms")
    print(f"p50:       {p50:.2f} ms")
    print(f"p95:       {p95:.2f} ms")
    print(f"p99:       {p99:.2f} ms")
    print(f"approx rps: {rps:.0f}")


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = max(0, min(len(sorted_values) - 1, int(len(sorted_values) * pct / 100)))
    return sorted_values[idx]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--requests", type=int, default=DEFAULT_REQUESTS)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser()
    ns = args.parse_args(list(argv) if argv is not None else None)
    asyncio.run(_run(ns.url, ns.concurrency, ns.requests))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
