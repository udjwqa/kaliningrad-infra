import os
import time
import logging
import httpx
import redis.asyncio as aioredis
from rate_limiter import REDIS_URL
from database import async_session
from db_models import BannedIP
from sqlalchemy import select, delete

logger = logging.getLogger("honeypot")

BAN_TTL = 86400 * 365

CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")
CF_ZONE_ID = os.getenv("CF_ZONE_ID", "")
CF_API_BASE = "https://api.cloudflare.com/client/v4"

# P7-B2: CF API rate-limit guard (закрывает amplifier vulnerability —
# attacker spamming honeypot из 1000 IPs не должен жечь CF API quota)
CF_FIREWALL_THROTTLE_CAP = int(os.getenv("CF_FIREWALL_THROTTLE_CAP", "60"))  # per minute


class HoneypotBan:
    def __init__(self):
        self._redis = None

    async def connect(self):
        try:
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            logger.info("Honeypot ban list connected to Redis")
        except Exception as e:
            logger.warning(f"Redis unavailable for honeypot: {e}")
            self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.aclose()

    async def ban(self, ip, reason="honeypot"):
        if self._redis:
            await self._redis.set(f"honeypot:ban:{ip}", reason, ex=BAN_TTL)
            await self._redis.sadd("honeypot:banned_ips", ip)

        cf_rule_id = None
        try:
            cf_rule_id = await self._cf_block_ip(ip, reason)
        except Exception as e:
            logger.error(f"CF block failed for {ip}: {e}")

        try:
            async with async_session() as session:
                existing = await session.execute(
                    select(BannedIP).where(BannedIP.ip == ip)
                )
                if not existing.scalar():
                    entry = BannedIP(
                        ip=ip,
                        reason=reason,
                        source="honeypot",
                        cf_rule_id=cf_rule_id,
                    )
                    session.add(entry)
                    await session.commit()
        except Exception as e:
            logger.error(f"DB ban write failed for {ip}: {e}")

        logger.warning(f"HONEYPOT BAN: {ip} ({reason}) cf_rule={cf_rule_id}")

    async def is_banned(self, ip):
        if self._redis:
            if await self._redis.exists(f"honeypot:ban:{ip}"):
                return True
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(BannedIP).where(BannedIP.ip == ip)
                )
                if result.scalar():
                    return True
        except Exception:
            pass
        return False

    async def unban(self, ip):
        if self._redis:
            await self._redis.delete(f"honeypot:ban:{ip}")
            await self._redis.srem("honeypot:banned_ips", ip)
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(BannedIP).where(BannedIP.ip == ip)
                )
                entry = result.scalar()
                if entry:
                    if entry.cf_rule_id:
                        await self._cf_unblock_ip(entry.cf_rule_id)
                    await session.execute(delete(BannedIP).where(BannedIP.ip == ip))
                    await session.commit()
        except Exception as e:
            logger.error(f"Unban failed for {ip}: {e}")

    async def get_all_banned(self):
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(BannedIP).order_by(BannedIP.banned_at.desc())
                )
                return [b.to_dict() for b in result.scalars().all()]
        except Exception:
            return []

    async def _cf_throttle_ok(self) -> bool:
        """Защита CF API quota — cap N firewall rule creations/min. Returns False если over cap."""
        if not self._redis:
            return True
        try:
            bucket = int(time.time()) // 60
            key = f"cf_firewall:throttle:{bucket}"
            cnt = await self._redis.incr(key)
            if cnt == 1:
                await self._redis.expire(key, 65)
            return cnt <= CF_FIREWALL_THROTTLE_CAP
        except Exception:
            return True

    async def _cf_block_ip(self, ip, reason):
        if not CF_API_TOKEN or not CF_ZONE_ID:
            return None
        if not await self._cf_throttle_ok():
            logger.warning(f"CF firewall throttle cap reached, skipping block for {ip}")
            return None
        url = f"{CF_API_BASE}/zones/{CF_ZONE_ID}/firewall/access_rules/rules"
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                json={
                    "mode": "block",
                    "configuration": {"target": "ip", "value": ip},
                    "notes": f"Honeypot auto-ban: {reason[:100]}",
                },
                headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
                timeout=10,
            )
            if resp.status_code == 200:
                rule_id = resp.json().get("result", {}).get("id", "")
                logger.info(f"CF blocked {ip} (rule={rule_id})")
                return rule_id
            else:
                logger.error(f"CF block API: {resp.status_code} {resp.text[:200]}")
                return None

    async def _cf_unblock_ip(self, rule_id):
        if not CF_API_TOKEN or not CF_ZONE_ID or not rule_id:
            return
        url = f"{CF_API_BASE}/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{rule_id}"
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                url,
                headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info(f"CF unblocked rule {rule_id}")


honeypot_ban = HoneypotBan()
