import json
import logging
from typing import Any, Optional
import redis.asyncio as redis
from app.config import settings

logger = logging.getLogger(__name__)


class RedisCache:
    """Async Redis caching layer for threat intelligence and correlation engines."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis: Optional[redis.Redis] = None

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        try:
            self._redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            # Test ping to ensure connection works
            await self._redis.ping()
        except Exception as e:
            logger.warning(f"Could not connect to Redis at {self.redis_url}: {e}. Operating in pass-through mode.")
            self._redis = None

    async def disconnect(self) -> None:
        """Close Redis connection pool."""
        if self._redis:
            try:
                await self._redis.close()
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {e}")
            finally:
                self._redis = None

    async def get(self, key: str) -> Optional[Any]:
        """Get cached value. Returns None on miss or error."""
        if not self._redis:
            return None
        try:
            value = await self._redis.get(key)
            if value is None:
                return None
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        except Exception as e:
            logger.warning(f"Redis GET error for key '{key}': {e}")
            return None

    async def set(self, key: str, value: Any, ttl: int = 86400) -> bool:
        """Set cached value with TTL in seconds (default: 24h)."""
        if not self._redis:
            return False
        try:
            serialized = json.dumps(value, default=str)
            await self._redis.setex(key, ttl, serialized)
            return True
        except Exception as e:
            logger.warning(f"Redis SET error for key '{key}': {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete a cached key."""
        if not self._redis:
            return False
        try:
            await self._redis.delete(key)
            return True
        except Exception as e:
            logger.warning(f"Redis DELETE error for key '{key}': {e}")
            return False

    async def get_stats(self) -> dict:
        """Get cache statistics."""
        if not self._redis:
            return {"status": "disconnected", "hits": 0, "misses": 0, "hit_rate": 0.0}
        try:
            info = await self._redis.info("stats")
            hits = int(info.get("keyspace_hits", 0))
            misses = int(info.get("keyspace_misses", 0))
            total = hits + misses
            hit_rate = round((hits / total) * 100, 1) if total > 0 else 0.0
            return {
                "status": "connected",
                "hits": hits,
                "misses": misses,
                "hit_rate": hit_rate,
            }
        except Exception as e:
            logger.warning(f"Error fetching Redis stats: {e}")
            return {"status": "error", "error": str(e)}
