"""Per-principal token-bucket rate limiter (in-process). For multi-node
deployments put a shared limiter (e.g. Redis) behind the same interface."""

from __future__ import annotations

import threading
import time

from ash.core.errors import RateLimited


class RateLimiter:
    def __init__(self, per_minute: int):
        self.capacity = max(per_minute, 1)
        self.refill_per_s = self.capacity / 60.0
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def check(self, key: str, cost: float = 1.0) -> None:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_s)
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                raise RateLimited(f"rate limit exceeded for {key}")
            self._buckets[key] = (tokens - cost, now)
