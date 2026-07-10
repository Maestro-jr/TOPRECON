"""
TOP RECON — rate limiting.

Two layers: a global requests/min cap (shown in the footer) and per-source
token buckets so a single API isn't hammered past its quota. Async-native.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    """Async sliding-window limiter combining a global cap + per-source caps."""

    def __init__(self, global_per_min: int = 1250) -> None:
        self.global_per_min = max(1, global_per_min)
        self._global = deque()               # timestamps of recent requests
        self._per_source: dict[str, deque] = {}
        self._per_source_cap: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._total = 0

    def configure_source(self, source: str, per_min: int) -> None:
        self._per_source_cap[source] = max(1, per_min)
        self._per_source.setdefault(source, deque())

    @property
    def total_requests(self) -> int:
        return self._total

    def current_rate(self) -> int:
        """Requests in the trailing 60s window (for the throughput readout)."""
        now = time.monotonic()
        while self._global and now - self._global[0] > 60:
            self._global.popleft()
        return len(self._global)

    async def acquire(self, source: str, weight: int = 1) -> None:
        """Block until a slot is free under both the global and source caps."""
        while True:
            async with self._lock:
                now = time.monotonic()
                self._trim(self._global, now)
                src_q = self._per_source.setdefault(source, deque())
                self._trim(src_q, now)
                src_cap = self._per_source_cap.get(source, self.global_per_min)
                if len(self._global) < self.global_per_min and len(src_q) < src_cap:
                    for _ in range(max(1, weight)):
                        self._global.append(now)
                        src_q.append(now)
                    self._total += 1
                    return
                # Compute the shortest wait until a slot frees.
                waits = []
                if len(self._global) >= self.global_per_min and self._global:
                    waits.append(60 - (now - self._global[0]))
                if len(src_q) >= src_cap and src_q:
                    waits.append(60 - (now - src_q[0]))
                delay = max(0.05, min(waits) if waits else 0.1)
            await asyncio.sleep(delay)

    @staticmethod
    def _trim(q: deque, now: float) -> None:
        while q and now - q[0] > 60:
            q.popleft()
