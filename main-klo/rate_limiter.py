import os
import logging
import redis.asyncio as aioredis

logger = logging.getLogger("rate_limiter")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "100"))
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))

# 2026-06-22 (F2/F3 fix): жёсткие лимиты для специфичных endpoints
# /api/integrity/nonce: real юзер использует 1-2 раза за сессию, > 10/мин = подозрительно
NONCE_LIMIT = int(os.getenv("NONCE_LIMIT", "10"))
NONCE_WINDOW = int(os.getenv("NONCE_WINDOW", "60"))
# /init per proxy_key: real юзеры открывают прилу несколько раз, 100/мин = с запасом,
# защищает от DoS через leaked proxy_key (APK reverse engineer)
INIT_LIMIT = int(os.getenv("INIT_LIMIT", "100"))
INIT_WINDOW = int(os.getenv("INIT_WINDOW", "60"))


class RateLimiter:
    def __init__(self):
        self._redis = None

    async def connect(self):
        try:
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            logger.info(f"Redis connected ({REDIS_URL}), limit={RATE_LIMIT} req/{RATE_WINDOW}s, "
                        f"nonce={NONCE_LIMIT}/{NONCE_WINDOW}s, init={INIT_LIMIT}/{INIT_WINDOW}s")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e} — rate limiting disabled")
            self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.aclose()

    async def check(self, ip):
        if not self._redis:
            return True, 0

        key = f"rate:{ip}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, RATE_WINDOW)
            return count <= RATE_LIMIT, count
        except Exception as e:
            logger.error(f"Redis error: {e}")
            return True, 0

    async def check_nonce(self, ip):
        """F3 (2026-06-22): жёсткий per-IP лимит на /api/integrity/nonce.
        Real юзеру нужно 1-2 nonce. > 10/мин = bot/DoS."""
        if not self._redis:
            return True, 0
        key = f"nonce_rate:{ip}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, NONCE_WINDOW)
            return count <= NONCE_LIMIT, count
        except Exception:
            return True, 0

    async def check_init(self, proxy_key, ip):
        """F2 (2026-06-22): per-proxy-key лимит на /init.
        Закрывает DoS через leaked proxy_key (APK reverse).
        Также fallback per-IP — если proxy_key пуст, лимитим по IP."""
        if not self._redis:
            return True, 0
        bucket_id = proxy_key[:16] if proxy_key else f"ip:{ip}"
        key = f"init_rate:{bucket_id}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, INIT_WINDOW)
            return count <= INIT_LIMIT, count
        except Exception:
            return True, 0


rate_limiter = RateLimiter()
