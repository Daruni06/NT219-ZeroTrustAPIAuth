"""Replay protection helpers."""

from __future__ import annotations

import redis.asyncio as redis

from .config import RedisConfig


class ReplayDetectedError(ValueError):
    """Raised when a DPoP jti was already used."""


class ReplayCache:
    def __init__(self, config: RedisConfig) -> None:
        self.config = config
        self.client = redis.from_url(config.url, password=config.password or None, decode_responses=True)

    async def check_and_store(self, jti: str, ttl_seconds: int | None = None) -> None:
        key = f"{self.config.replay_prefix}{jti}"
        ttl = ttl_seconds or self.config.replay_ttl_seconds
        stored = await self.client.set(key, "1", ex=ttl, nx=True)
        if not stored:
            raise ReplayDetectedError("DPoP jti replay detected")

    async def close(self) -> None:
        await self.client.aclose()
