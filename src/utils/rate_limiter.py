"""
Rate limiter for FORGE scan operations.

Closes the missing-rate-limit gap identified by reading xAI's grox
PlanSafetyPtos: production safety pipelines always include a rate-limit
stage to protect against abuse and runaway parallelism.

Two primitives provided:

- TokenBucket:   classic rate-limit (N tokens/period). Useful when
                 FORGE is exposed as a long-running service.
- RateLimiter:   convenience wrapper combining a token bucket with a
                 max-concurrency semaphore.

Single-process, in-memory only. For multi-process or distributed
enforcement, swap the backing store for Redis with the same API.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds the configured rate."""


@dataclass
class TokenBucket:
    """
    Classic token bucket.

    capacity:    maximum tokens the bucket can hold (burst size)
    refill_rate: tokens added per second
    """
    capacity: int
    refill_rate: float
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be > 0")
        if self.refill_rate <= 0:
            raise ValueError("refill_rate must be > 0")
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()

    async def acquire(self, tokens: int = 1, *, wait: bool = False) -> bool:
        """
        Try to take `tokens` tokens from the bucket.

        wait=False (default): return True if granted, False if denied.
        wait=True:            block until tokens available, always return True.
        """
        if tokens <= 0:
            raise ValueError("tokens must be > 0")
        if tokens > self.capacity:
            raise ValueError(
                f"request for {tokens} exceeds capacity {self.capacity}"
            )

        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                if not wait:
                    return False
                deficit = tokens - self._tokens
                sleep_for = deficit / self.refill_rate
            await asyncio.sleep(sleep_for)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        self._tokens = min(
            float(self.capacity),
            self._tokens + elapsed * self.refill_rate,
        )
        self._last_refill = now

    def available(self) -> float:
        """Inspect available tokens without consuming any."""
        self._refill()
        return self._tokens


@dataclass
class RateLimiter:
    """
    Combined rate + concurrency limit for FORGE scan operations.

    rate_per_second:    sustained scan invocations per second (burst = same)
    max_concurrent:     hard cap on simultaneous in-flight scans
    """
    rate_per_second: float = 5.0
    max_concurrent: int = 4
    _bucket: TokenBucket = field(init=False)
    _semaphore: asyncio.Semaphore = field(init=False)

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")
        if self.max_concurrent <= 0:
            raise ValueError("max_concurrent must be > 0")
        capacity = max(1, int(self.rate_per_second))
        self._bucket = TokenBucket(
            capacity=capacity, refill_rate=self.rate_per_second
        )
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def acquire(self, *, wait: bool = False) -> None:
        """
        Acquire one scan slot. Raises RateLimitExceeded if denied.

        Combines token bucket (per-second rate) with semaphore (concurrency).
        """
        granted = await self._bucket.acquire(1, wait=wait)
        if not granted:
            raise RateLimitExceeded(
                f"rate limit exceeded "
                f"(rate_per_second={self.rate_per_second})"
            )
        await self._semaphore.acquire()

    def release(self) -> None:
        self._semaphore.release()

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire(wait=True)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.release()


# Module-level default for callers that don't want to manage a limiter.
default_rate_limiter = RateLimiter(rate_per_second=5.0, max_concurrent=4)
