"""
mini-КЛО Redis async client.

Used for:
- auto_ban check (autoban:{pkg}:{ip}, autoban:_:{ip})
- instance_burnt (instance_burnt:{pkg}:{iid}) — 24h TTL
- cloak_consumed (cloak_consumed:{pkg}:{iid}) — 24h SETNX one-shot
- velocity guard (vel:inst:{iid}, vel:sub:{sub}, vel:ip:{ip})

All Redis-dependent checks fail-OPEN — если Redis недоступен, скорим без них.
"""
import ipaddress
import logging
import os
from typing import Optional

try:
    import redis.asyncio as redis  # type: ignore
except ImportError:
    redis = None  # type: ignore

logger = logging.getLogger("redis")

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")

_client: Optional["redis.Redis"] = None


async def get_redis() -> Optional["redis.Redis"]:
    """Lazy singleton — returns None if redis package missing or connect fails."""
    global _client
    if redis is None:
        return None
    if _client is None:
        try:
            _client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=1.5)
            await _client.ping()
            logger.info(f"Redis connected: {REDIS_URL}")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e} — все Redis-checks fail-open")
            _client = None
    return _client


def subnet_key(ip: str) -> str:
    """/24 for v4, /64 for v6. Returns canonical network string."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{ip}/64", strict=False)
        return str(net.network_address)
    except Exception:
        return ip


# ==== auto_ban ====

async def is_autobanned(package_name: str, ip: str) -> tuple[bool, str]:
    """Check both package-scoped и global keys. Returns (banned, reason)."""
    r = await get_redis()
    if r is None or not ip:
        return False, ""
    try:
        pkg_key = f"autoban:{package_name}:{ip}"
        glob_key = f"autoban:_:{ip}"
        v = await r.get(pkg_key)
        if v:
            return True, f"autoban:{package_name}:{v}"
        v = await r.get(glob_key)
        if v:
            return True, f"autoban:_:{v}"
    except Exception as e:
        logger.debug(f"autoban check failed for {ip}: {e}")
    return False, ""


# ==== instance_burnt ====

async def is_instance_burnt(package_name: str, instance_id: str) -> tuple[bool, str]:
    # 2026-07-14: disabled per client — aligned with main КЛО max-conversion mode 07-09
    return (False, "")
    """24h burn per (pkg, instance_id). Returns (burnt, reason)."""
    r = await get_redis()
    if r is None or not instance_id:
        return False, ""
    try:
        reason = await r.get(f"instance_burnt:{package_name}:{instance_id}")
        if reason:
            return True, reason
    except Exception as e:
        logger.debug(f"instance_burnt check failed: {e}")
    return False, ""


async def mark_instance_burnt(package_name: str, instance_id: str, reason: str, ttl: int = 86400):
    r = await get_redis()
    if r is None or not instance_id:
        return
    try:
        await r.set(f"instance_burnt:{package_name}:{instance_id}", reason, ex=ttl)
    except Exception as e:
        logger.debug(f"mark_instance_burnt failed: {e}")


# ==== cloak_consumed (SETNX) ====

async def check_and_mark_cloak_consumed(package_name: str, instance_id: str, ip: str) -> tuple[bool, dict]:
    """
    Returns (consumed, info_dict).
    First hit: SETNX succeeds, returns (False, {first_time: True}).
    Repeat: SETNX fails, returns (True, {first_time: False, cached}).
    Fail-OPEN on empty instance_id or Redis error.
    """
    r = await get_redis()
    if r is None or not instance_id:
        return False, {"first_time": True, "reason": "no_redis_or_iid"}
    try:
        import json, time
        key = f"cloak_consumed:{package_name}:{instance_id}"
        payload = json.dumps({"ts": int(time.time()), "ip": ip, "verdict": "grey"})
        set_ok = await r.set(key, payload, nx=True, ex=86400)
        if set_ok:
            return False, {"first_time": True}
        cached = await r.get(key)
        return True, {"first_time": False, "cached": cached}
    except Exception as e:
        logger.debug(f"cloak_consumed check failed: {e}")
        return False, {"first_time": True, "reason": "redis_error"}


# ==== velocity guard ====

async def velocity_check(instance_id: str, ip: str, package_name: str) -> Optional[str]:
    """
    3-tier velocity check ported from main КЛО _velocity_check.
    Returns None if OK, else rejection reason string.
    Fail-OPEN on Redis error.
    """
    r = await get_redis()
    if r is None:
        return None
    try:
        # Per-instance: >12 per 5min
        if instance_id:
            k = f"vel:inst:{instance_id}"
            n = await r.incr(k)
            if n == 1:
                await r.expire(k, 300)
            if n > 12:
                return f"per_instance_burst:{n}/5min"

        # Per-IP raw: >60 per 5min (CGNAT-tolerant)
        if ip:
            k = f"vel:ip:{ip}"
            n = await r.incr(k)
            if n == 1:
                await r.expire(k, 300)
            if n > 60:
                return f"per_ip_burst:{n}/5min"

        # Per-subnet: SCARD >15 per 15min
        if ip and instance_id:
            sub = subnet_key(ip)
            k = f"vel:sub:{sub}"
            await r.sadd(k, instance_id)
            await r.expire(k, 900)
            card = await r.scard(k)
            if card > 15:
                return f"per_subnet_burst:{card}iids/15min:{sub}"
    except Exception as e:
        logger.debug(f"velocity_check failed: {e}")
    return None


# ==== warm auto_ban from bans.json ====

async def warm_autoban(ip_bans: list, ttl: int = 604800):
    """Load synced ip_bans (list of {ip, package_name, reason}) into Redis.
    Each entry becomes autoban:{pkg|_}:{ip} = reason with 7-day TTL.
    """
    r = await get_redis()
    if r is None:
        return 0
    loaded = 0
    try:
        pipe = r.pipeline()
        for entry in ip_bans:
            ip = entry.get("ip", "")
            pkg = entry.get("package_name") or "_"
            reason = entry.get("reason", "banned")
            if not ip:
                continue
            pipe.set(f"autoban:{pkg}:{ip}", reason, ex=ttl)
            loaded += 1
        await pipe.execute()
        logger.info(f"warm_autoban: loaded {loaded} ban entries into Redis")
    except Exception as e:
        logger.warning(f"warm_autoban failed: {e}")
    return loaded
