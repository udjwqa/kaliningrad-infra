"""Smart Auto-Banlist — top-layer negative cache per (ip, package_name).

2026-06-23 (Smart Auto-Banlist P1). Когда /init с IP+pkg попадает в hard-kill
с certain rejection_code — добавляем `(pkg, ip)` в banlist на 24h/7d. Следующие
/init с того же ключа — instant block без любых проверок.

Архитектура:
    Redis (hot cache, EXISTS < 1ms) ↔ Postgres (canonical, source of truth)
    Cold start: _warm_from_db() batched pipeline 1000/batch

3-tier ban model:
    1) instance_burnt (Redis 24h, server/api/init_routes.py) — per-instance
    2) auto_ban     (Redis+DB 24h-7d, ЭТОТ файл)              — per (ip, pkg)
    3) honeypot_ban (Redis+DB 365d+CF API, server/honeypot_ban.py) — per ip, perma

Shadow mode (AUTOBAN_ENFORCE=false):
    emit() пишет в Postgres с would_ban=true, НЕ пишет в Redis.
    is_banned() игнорирует would_ban rows.
    Используется для 7-day soak validation перед enforce flip.
"""

import os
import json
import time
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple
import redis.asyncio as aioredis
from sqlalchemy import select, delete, func, and_, or_
from sqlalchemy.dialects.postgresql import insert as pg_insert

from rate_limiter import REDIS_URL
from database import async_session
from db_models import AutoBannedEntry

logger = logging.getLogger("auto_ban")

# P7: CF KV throttle (защита от amplifier при ban-storm)
CF_KV_THROTTLE_CAP = int(os.getenv("CF_KV_THROTTLE_CAP", "1000"))  # per minute
CF_KV_PERMANENT_TTL = 315_360_000  # 10y для manual/permanent bans
CF_KV_DLQ_KEY = "cf_kv:dlq"
CF_KV_THROTTLE_PREFIX = "cf_kv:throttle"

# Env-driven config
AUTOBAN_ENFORCE = os.getenv("AUTOBAN_ENFORCE", "false").lower() == "true"
AUTOBAN_NEG_CACHE_TTL = int(os.getenv("AUTOBAN_NEG_CACHE_TTL", "3600"))  # 1h
AUTOBAN_G1_TTL = int(os.getenv("AUTOBAN_G1_TTL", "604800"))  # 7d
AUTOBAN_G2_TTL = int(os.getenv("AUTOBAN_G2_TTL", "86400"))   # 24h
AUTOBAN_G2_READY = os.getenv("AUTOBAN_G2_READY", "false").lower() == "true"

# Group 1 — атакеры точно, enforce сразу. 7d TTL.
AUTOBAN_CODES_G1 = frozenset({
    "pi_nonce_replay", "pi_capturing", "pi_controlling", "pi_unlicensed",
    "tor_exit", "ipqs_vpn", "asn_google", "asn_vpn", "asn_blocked",
    "instance_burnt", "honeypot", "device_hardban",
})

# Group 2 — после 7-day shadow validation. 24h TTL.
AUTOBAN_CODES_G2 = frozenset({
    "velocity_block", "codename_block", "gpu_block", "device_spoof",
    "bot_user_agent", "ip_range_blocked", "google_referer", "test_build_detected",
    "soft_ua_emulator", "soft_ua_google_device", "asn_rotation", "ipqs_fraud",
})

# Все codes которые НЕ зависят от package — IP плохой для любого приложения.
# Для них в БД package_name=NULL и в Redis ключ autoban:_:{ip}.
GLOBAL_AUTOBAN_CODES = frozenset({
    "tor_exit", "ipqs_vpn", "asn_google", "asn_vpn", "asn_blocked",
    "honeypot", "ip_range_blocked",
})

# TTL ladder per code (override default)
AUTOBAN_TTL = {
    # Group 1 — 7d (явно)
    "pi_nonce_replay": AUTOBAN_G1_TTL,
    "pi_capturing": AUTOBAN_G1_TTL,
    "pi_controlling": AUTOBAN_G1_TTL,
    "pi_unlicensed": AUTOBAN_G1_TTL,
    "tor_exit": AUTOBAN_G1_TTL,
    "ipqs_vpn": AUTOBAN_G1_TTL,
    "asn_google": AUTOBAN_G1_TTL,
    "asn_vpn": AUTOBAN_G1_TTL,
    "asn_blocked": AUTOBAN_G1_TTL,
    "instance_burnt": AUTOBAN_G1_TTL,
    "honeypot": AUTOBAN_G1_TTL,
    "device_hardban": AUTOBAN_G1_TTL,
    # Group 2 — 24h default через .get()
}


def _norm_ip(ip: str) -> str:
    """Canonical IP form (RFC 5952 + IPv4-mapped IPv6 unwrap). Fail-soft на invalid input
    чтобы не сломать existing flow — returns trimmed original. P7 IP-normalization fix."""
    try:
        from api.cf_sync import normalize_ip
        return normalize_ip(ip)
    except (ValueError, ImportError):
        return (ip or "").strip()


def _redis_key(pkg: Optional[str], ip: str) -> str:
    """Redis key. NULL pkg → '_' (global ban). Normalized IP для consistency на write/read."""
    return f"autoban:{pkg or '_'}:{_norm_ip(ip)}"


def _neg_cache_key(pkg: Optional[str], ip: str) -> str:
    """Positive signal — IP был grey недавно → skip ban check next hour."""
    return f"autoban:neg:{pkg or '_'}:{_norm_ip(ip)}"


class AutoBan:
    def __init__(self):
        self._redis = None

    # ─── P7: CF KV edge sync (fire-and-forget, throttled, DLQ-backed) ───

    async def _cf_throttle_ok(self) -> bool:
        """True если квота на эту минуту не превышена. CF API rate-limit guard."""
        if not self._redis:
            return False
        try:
            bucket = int(time.time()) // 60
            key = f"{CF_KV_THROTTLE_PREFIX}:{bucket}"
            cnt = await self._redis.incr(key)
            if cnt == 1:
                await self._redis.expire(key, 65)
            return cnt <= CF_KV_THROTTLE_CAP
        except Exception:
            return False  # Redis down — пропускаем CF write (origin Redis всё равно блокирует)

    async def _cf_enqueue_dlq(self, op: str, ip: str, code: str, ttl_sec: Optional[int]):
        """Push dropped/failed CF write в Redis sorted set для retry через 30s."""
        if not self._redis:
            return
        try:
            payload = json.dumps({"op": op, "ip": ip, "code": code, "ttl": ttl_sec, "ts": int(time.time())})
            score = time.time() + 30  # retry through 30s
            await self._redis.zadd(CF_KV_DLQ_KEY, {payload: score})
        except Exception as e:
            logger.warning(f"DLQ enqueue failed: {e}")

    async def _cf_kv_write(self, ip: str, code: str, ttl_sec: int):
        """Fire-and-forget CF KV PUT с 3s circuit breaker. Async task, never blocks /init."""
        async def _task():
            try:
                from api.cf_sync import put_kv, banlist_key, CF_KV_BANLIST_NAMESPACE_ID
                if not CF_KV_BANLIST_NAMESPACE_ID:
                    return  # banlist namespace ещё не настроен
                if not await self._cf_throttle_ok():
                    await self._cf_enqueue_dlq("put", ip, code, ttl_sec)
                    return
                try:
                    key = banlist_key(ip)
                except ValueError as e:
                    logger.warning(f"CF KV skip invalid ip {ip!r}: {e}")
                    return
                ok = await asyncio.wait_for(
                    put_kv(key, code, ttl_sec=ttl_sec, namespace_id=CF_KV_BANLIST_NAMESPACE_ID),
                    timeout=3.0,
                )
                if not ok:
                    await self._cf_enqueue_dlq("put", ip, code, ttl_sec)
            except asyncio.TimeoutError:
                logger.warning(f"CF KV PUT timeout for {ip}")
                await self._cf_enqueue_dlq("put", ip, code, ttl_sec)
            except Exception as e:
                logger.warning(f"CF KV PUT task error for {ip}: {e}")
        asyncio.create_task(_task())

    async def _cf_kv_delete(self, ip: str):
        """Fire-and-forget CF KV DELETE с 3s circuit breaker."""
        async def _task():
            try:
                from api.cf_sync import delete_kv, banlist_key, CF_KV_BANLIST_NAMESPACE_ID
                if not CF_KV_BANLIST_NAMESPACE_ID:
                    return
                if not await self._cf_throttle_ok():
                    await self._cf_enqueue_dlq("del", ip, "", None)
                    return
                try:
                    key = banlist_key(ip)
                except ValueError:
                    return
                ok = await asyncio.wait_for(
                    delete_kv(key, namespace_id=CF_KV_BANLIST_NAMESPACE_ID),
                    timeout=3.0,
                )
                if not ok:
                    await self._cf_enqueue_dlq("del", ip, "", None)
            except asyncio.TimeoutError:
                logger.warning(f"CF KV DELETE timeout for {ip}")
                await self._cf_enqueue_dlq("del", ip, "", None)
            except Exception as e:
                logger.warning(f"CF KV DELETE task error for {ip}: {e}")
        asyncio.create_task(_task())

    async def drain_dlq(self, max_items: int = 50) -> int:
        """Pop expired DLQ items and retry. Called by background loop in main.py lifespan."""
        if not self._redis:
            return 0
        try:
            now = time.time()
            from api.cf_sync import put_kv, delete_kv, banlist_key, CF_KV_BANLIST_NAMESPACE_ID
            if not CF_KV_BANLIST_NAMESPACE_ID:
                return 0
            items = await self._redis.zrangebyscore(CF_KV_DLQ_KEY, 0, now, start=0, num=max_items)
            if not items:
                return 0
            drained = 0
            for raw in items:
                try:
                    payload = json.loads(raw)
                    ip, op, code, ttl = payload["ip"], payload["op"], payload.get("code", ""), payload.get("ttl")
                    if not await self._cf_throttle_ok():
                        break  # квота кончилась — оставляем в очереди, retry next cycle
                    try:
                        key = banlist_key(ip)
                    except ValueError:
                        await self._redis.zrem(CF_KV_DLQ_KEY, raw)
                        continue
                    ok = False
                    if op == "put":
                        ok = await asyncio.wait_for(
                            put_kv(key, code, ttl_sec=ttl, namespace_id=CF_KV_BANLIST_NAMESPACE_ID),
                            timeout=3.0,
                        )
                    elif op == "del":
                        ok = await asyncio.wait_for(
                            delete_kv(key, namespace_id=CF_KV_BANLIST_NAMESPACE_ID),
                            timeout=3.0,
                        )
                    if ok:
                        await self._redis.zrem(CF_KV_DLQ_KEY, raw)
                        drained += 1
                    else:
                        # bump score +60s для exponential-ish backoff
                        await self._redis.zadd(CF_KV_DLQ_KEY, {raw: now + 60})
                except Exception as e:
                    logger.warning(f"DLQ item retry error: {e}")
                    await self._redis.zrem(CF_KV_DLQ_KEY, raw)  # poison-pill drop
            if drained:
                logger.info(f"CF KV DLQ drained {drained} items")
            return drained
        except Exception as e:
            logger.warning(f"DLQ drain failed: {e}")
            return 0

    # ─── P1-6: core ban logic ───

    async def connect(self):
        try:
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            logger.info(
                f"AutoBan connected (enforce={AUTOBAN_ENFORCE}, g2_ready={AUTOBAN_G2_READY}, "
                f"g1_ttl={AUTOBAN_G1_TTL}s, g2_ttl={AUTOBAN_G2_TTL}s)"
            )
            # Warm Redis cache from DB on cold start (best-effort, не блокирует startup)
            try:
                warmed = await self._warm_from_db()
                logger.info(f"AutoBan warmed {warmed} active entries from DB")
            except Exception as e:
                logger.warning(f"AutoBan warm failed: {e}")
        except Exception as e:
            logger.warning(f"Redis unavailable for AutoBan: {e}")
            self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.aclose()

    async def emit(
        self,
        ip: str,
        package_name: Optional[str],
        code: str,
        reason: str,
        ttl_sec: Optional[int] = None,
        origin_request_id=None,
        classification: Optional[str] = None,
    ) -> bool:
        """Записать ban в Postgres+Redis (или shadow mode только в Postgres).

        Returns True если ban активен (записан в Redis), False — shadow или fail.
        Race-condition note: concurrent emit() для same (ip,pkg) safe через Postgres
        ON CONFLICT (uq_autoban_pkg_ip) — strike_count increments atomically.
        """
        if not ip or not code:
            return False
        # P7: canonical IP form для всех downstream storage (Redis/DB/CF KV)
        ip = _norm_ip(ip)

        # Effective TTL
        if ttl_sec is None:
            ttl_sec = AUTOBAN_TTL.get(code, AUTOBAN_G2_TTL)

        # Decision: enforce или shadow для этого code
        is_g1 = code in AUTOBAN_CODES_G1
        is_g2 = code in AUTOBAN_CODES_G2
        will_enforce = AUTOBAN_ENFORCE and (is_g1 or (is_g2 and AUTOBAN_G2_READY))
        would_ban = not will_enforce  # для shadow mode flag

        # GLOBAL codes — НЕ важен package_name (NULL в БД, '_' в Redis)
        pkg_key = None if code in GLOBAL_AUTOBAN_CODES else package_name

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=ttl_sec)

        # 1) Postgres upsert (ON CONFLICT increment strike_count)
        try:
            async with async_session() as session:
                stmt = pg_insert(AutoBannedEntry).values(
                    ip=ip,
                    package_name=pkg_key,
                    code=code,
                    reason=(reason or "")[:500],
                    banned_at=now,
                    expires_at=expires_at,
                    banned_by="auto",
                    source="auto",
                    strike_count=1,
                    would_ban=would_ban,
                    origin_request_id=origin_request_id,
                    classification_at_ban=classification,
                )
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_autoban_pkg_ip",
                    set_={
                        "code": stmt.excluded.code,
                        "reason": stmt.excluded.reason,
                        "banned_at": stmt.excluded.banned_at,
                        "expires_at": stmt.excluded.expires_at,
                        "strike_count": AutoBannedEntry.strike_count + 1,
                        "would_ban": stmt.excluded.would_ban,
                        "origin_request_id": stmt.excluded.origin_request_id,
                        "classification_at_ban": stmt.excluded.classification_at_ban,
                    },
                )
                await session.execute(stmt)
                await session.commit()
        except Exception as e:
            logger.error(f"AutoBan DB write failed for {pkg_key}|{ip}: {e}")

        # 2) Redis SET (только если enforce — иначе shadow mode)
        if will_enforce and self._redis:
            try:
                await self._redis.set(_redis_key(pkg_key, ip), code, ex=ttl_sec)
                # Удалить negative cache если был
                await self._redis.delete(_neg_cache_key(pkg_key, ip))
                # P7: CF KV edge sync (fire-and-forget — origin Redis уже set)
                await self._cf_kv_write(ip, code, ttl_sec)
            except Exception as e:
                logger.error(f"AutoBan Redis SET failed for {pkg_key}|{ip}: {e}")
                return False

        mode = "ENFORCE" if will_enforce else "SHADOW"
        logger.warning(
            f"AUTOBAN {mode} pkg={pkg_key or '_'} ip={ip} code={code} "
            f"ttl={ttl_sec}s expires={expires_at.isoformat()}"
        )
        return will_enforce

    async def is_banned(self, ip: str, package_name: Optional[str]) -> Tuple[bool, str]:
        """Returns (banned, reason). Если banned=True — caller сразу делает hard-kill.

        Lookup order:
            1. Negative cache (IP был grey недавно) → skip
            2. Redis EXISTS pkg-specific
            3. Redis EXISTS global (для GLOBAL_AUTOBAN_CODES)
            4. DB fallback при Redis miss/down

        Latency: 1-2ms (Redis EXISTS), 5-20ms (DB fallback).
        """
        if not ip or not AUTOBAN_ENFORCE:
            return False, ""
        ip = _norm_ip(ip)

        # 1) Negative cache check — если IP был grey за последний час, skip ban check
        if self._redis:
            try:
                if await self._redis.exists(_neg_cache_key(package_name, ip)):
                    return False, ""
                # Pkg-specific ban
                code = await self._redis.get(_redis_key(package_name, ip))
                if code:
                    return True, code
                # Global ban (другой ключ)
                if package_name:
                    code = await self._redis.get(_redis_key(None, ip))
                    if code:
                        return True, code
            except Exception as e:
                logger.warning(f"AutoBan Redis check failed: {e}")
                # Fall through to DB

        # 2) DB fallback (slow path)
        try:
            now = datetime.utcnow()
            async with async_session() as session:
                # Check pkg-specific и global одним запросом
                stmt = select(AutoBannedEntry).where(
                    AutoBannedEntry.ip == ip,
                    AutoBannedEntry.would_ban == False,  # noqa: E712
                    or_(
                        AutoBannedEntry.expires_at == None,  # noqa: E711
                        AutoBannedEntry.expires_at > now,
                    ),
                    or_(
                        AutoBannedEntry.package_name == package_name,
                        AutoBannedEntry.package_name == None,  # noqa: E711
                    ),
                ).limit(1)
                result = await session.execute(stmt)
                entry = result.scalar()
                if entry:
                    return True, entry.code or "autoban_db"
        except Exception:
            pass
        return False, ""

    async def mark_grey(self, ip: str, package_name: Optional[str]):
        """Положительный сигнал — IP получил grey verdict. Set neg cache на 1h
        чтобы skip ban check для последующих запросов с этого IP. Это safety net
        против ошибочного ban (если IP реально legit — он почти сразу опять grey)."""
        if not ip or not self._redis:
            return
        ip = _norm_ip(ip)
        try:
            await self._redis.set(_neg_cache_key(package_name, ip), "1", ex=AUTOBAN_NEG_CACHE_TTL)
        except Exception:
            pass

    async def unban(self, entry_id: str) -> bool:
        """Удалить ban (из UI). DELETE из Postgres + DEL Redis ключей."""
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(AutoBannedEntry).where(AutoBannedEntry.id == entry_id)
                )
                entry = result.scalar()
                if not entry:
                    return False
                ip, pkg = entry.ip, entry.package_name
                await session.execute(delete(AutoBannedEntry).where(AutoBannedEntry.id == entry_id))
                await session.commit()
            if self._redis:
                await self._redis.delete(_redis_key(pkg, ip), _neg_cache_key(pkg, ip))
                # P7: CF KV edge — удаляем чтобы IP мог снова получить /init
                await self._cf_kv_delete(ip)
            logger.info(f"AutoBan unbanned id={entry_id} pkg={pkg} ip={ip}")
            return True
        except Exception as e:
            logger.error(f"AutoBan unban failed: {e}")
            return False

    async def manual_add(
        self,
        ip: str,
        package_name: Optional[str],
        code: str,
        reason: str,
        ttl_sec: Optional[int],  # None = permanent
        banned_by: str = "admin",
    ) -> bool:
        """Manual ban из UI (Add ban dialog)."""
        if not ip:
            return False
        ip = _norm_ip(ip)
        now = datetime.utcnow()
        expires_at = (now + timedelta(seconds=ttl_sec)) if ttl_sec else None
        try:
            async with async_session() as session:
                stmt = pg_insert(AutoBannedEntry).values(
                    ip=ip,
                    package_name=package_name,
                    code=code or "manual",
                    reason=(reason or "")[:500],
                    banned_at=now,
                    expires_at=expires_at,
                    banned_by=banned_by,
                    source="manual",
                    strike_count=1,
                    would_ban=False,  # Manual = enforce независимо от AUTOBAN_ENFORCE
                )
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_autoban_pkg_ip",
                    set_={
                        "code": stmt.excluded.code,
                        "reason": stmt.excluded.reason,
                        "banned_at": stmt.excluded.banned_at,
                        "expires_at": stmt.excluded.expires_at,
                        "banned_by": stmt.excluded.banned_by,
                        "source": stmt.excluded.source,
                        "would_ban": False,
                    },
                )
                await session.execute(stmt)
                await session.commit()
            if self._redis:
                redis_ttl = ttl_sec if ttl_sec else 86400 * 365  # 1 год для permanent в Redis
                await self._redis.set(_redis_key(package_name, ip), code or "manual", ex=redis_ttl)
                await self._redis.delete(_neg_cache_key(package_name, ip))
                # P7: CF KV — permanent (ttl=None) → 10y clamp; иначе exact ttl
                await self._cf_kv_write(ip, code or "manual", ttl_sec if ttl_sec else CF_KV_PERMANENT_TTL)
            logger.info(f"AutoBan manual_add pkg={package_name} ip={ip} ttl={ttl_sec} by={banned_by}")
            return True
        except Exception as e:
            logger.error(f"AutoBan manual_add failed: {e}")
            return False

    async def extend(self, entry_id: str, additional_sec: int) -> bool:
        """Продлить TTL существующего ban."""
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(AutoBannedEntry).where(AutoBannedEntry.id == entry_id)
                )
                entry = result.scalar()
                if not entry:
                    return False
                base = entry.expires_at or datetime.utcnow()
                new_expires = base + timedelta(seconds=additional_sec)
                entry.expires_at = new_expires
                await session.commit()
                if self._redis:
                    # Reset Redis TTL
                    remaining = max(0, int((new_expires - datetime.utcnow()).total_seconds()))
                    if remaining > 0:
                        await self._redis.set(
                            _redis_key(entry.package_name, entry.ip),
                            entry.code or "manual",
                            ex=remaining,
                        )
                        # P7: CF KV re-PUT с новым TTL
                        await self._cf_kv_write(entry.ip, entry.code or "manual", remaining)
            return True
        except Exception as e:
            logger.error(f"AutoBan extend failed: {e}")
            return False

    async def get_all_paginated(
        self,
        page: int = 1,
        page_size: int = 50,
        search: str = "",
        code: str = "",
        source: str = "",
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        expired_only: bool = False,
        active_only: bool = False,
        shadow_only: bool = False,
    ) -> dict:
        """Server-side pagination для UI. Returns {entries, total, page, totalPages}."""
        try:
            async with async_session() as session:
                base_q = select(AutoBannedEntry)
                count_q = select(func.count(AutoBannedEntry.id))
                now = datetime.utcnow()
                filters = []
                if search:
                    filters.append(AutoBannedEntry.ip.like(f"%{search}%"))
                if code:
                    filters.append(AutoBannedEntry.code == code)
                if source:
                    filters.append(AutoBannedEntry.source == source)
                if date_from:
                    filters.append(AutoBannedEntry.banned_at >= date_from)
                if date_to:
                    filters.append(AutoBannedEntry.banned_at <= date_to)
                if expired_only:
                    filters.append(and_(
                        AutoBannedEntry.expires_at.is_not(None),
                        AutoBannedEntry.expires_at < now,
                    ))
                if active_only:
                    filters.append(or_(
                        AutoBannedEntry.expires_at.is_(None),
                        AutoBannedEntry.expires_at > now,
                    ))
                if shadow_only:
                    filters.append(AutoBannedEntry.would_ban == True)  # noqa: E712
                if filters:
                    base_q = base_q.where(and_(*filters))
                    count_q = count_q.where(and_(*filters))

                total = (await session.execute(count_q)).scalar() or 0
                base_q = base_q.order_by(AutoBannedEntry.banned_at.desc()) \
                    .limit(page_size).offset((page - 1) * page_size)
                entries = (await session.execute(base_q)).scalars().all()
                total_pages = max(1, (total + page_size - 1) // page_size)
                return {
                    "entries": [e.to_dict() for e in entries],
                    "total": total,
                    "page": page,
                    "pageSize": page_size,
                    "totalPages": total_pages,
                }
        except Exception as e:
            logger.error(f"AutoBan paginated query failed: {e}")
            return {"entries": [], "total": 0, "page": 1, "pageSize": page_size, "totalPages": 0}

    async def get_stats(self) -> dict:
        """Summary stats для dashboard cards."""
        try:
            now = datetime.utcnow()
            since_24h = now - timedelta(hours=24)
            async with async_session() as session:
                total = (await session.execute(
                    select(func.count(AutoBannedEntry.id)).where(
                        or_(AutoBannedEntry.expires_at.is_(None),
                            AutoBannedEntry.expires_at > now),
                    )
                )).scalar() or 0
                last_24h = (await session.execute(
                    select(func.count(AutoBannedEntry.id)).where(
                        AutoBannedEntry.banned_at >= since_24h,
                    )
                )).scalar() or 0
                by_source_rows = (await session.execute(
                    select(AutoBannedEntry.source, func.count(AutoBannedEntry.id))
                    .where(or_(AutoBannedEntry.expires_at.is_(None),
                               AutoBannedEntry.expires_at > now))
                    .group_by(AutoBannedEntry.source)
                )).all()
                top_codes_rows = (await session.execute(
                    select(AutoBannedEntry.code, func.count(AutoBannedEntry.id))
                    .where(AutoBannedEntry.banned_at >= since_24h)
                    .group_by(AutoBannedEntry.code)
                    .order_by(func.count(AutoBannedEntry.id).desc())
                    .limit(10)
                )).all()
                return {
                    "totalActive": total,
                    "last24h": last_24h,
                    "bySource": {row[0]: row[1] for row in by_source_rows},
                    "topCodes": [{"code": r[0], "count": r[1]} for r in top_codes_rows],
                }
        except Exception as e:
            logger.error(f"AutoBan stats failed: {e}")
            return {"totalActive": 0, "last24h": 0, "bySource": {}, "topCodes": []}

    async def bulk_unban(self, entry_ids: list) -> int:
        """Bulk delete. Returns count deleted."""
        count = 0
        try:
            async with async_session() as session:
                result = await session.execute(
                    select(AutoBannedEntry).where(AutoBannedEntry.id.in_(entry_ids))
                )
                entries = result.scalars().all()
                redis_keys = []
                for e in entries:
                    redis_keys.append(_redis_key(e.package_name, e.ip))
                    redis_keys.append(_neg_cache_key(e.package_name, e.ip))
                await session.execute(
                    delete(AutoBannedEntry).where(AutoBannedEntry.id.in_(entry_ids))
                )
                await session.commit()
                count = len(entries)
            if self._redis and redis_keys:
                await self._redis.delete(*redis_keys)
                # P7: CF KV — async fire-and-forget per IP (throttle per-call внутри)
                for e_ in entries:
                    await self._cf_kv_delete(e_.ip)
            logger.info(f"AutoBan bulk_unban: {count} entries")
        except Exception as e:
            logger.error(f"AutoBan bulk_unban failed: {e}")
        return count

    async def _warm_from_db(self) -> int:
        """Cold start recovery — warm Redis из активных Postgres entries.
        Batched 1000/batch чтобы не блокировать на > 5s при 100k+ rows.
        """
        if not self._redis:
            return 0
        try:
            now = datetime.utcnow()
            async with async_session() as session:
                result = await session.execute(
                    select(AutoBannedEntry).where(
                        AutoBannedEntry.would_ban == False,  # noqa: E712
                        or_(AutoBannedEntry.expires_at.is_(None),
                            AutoBannedEntry.expires_at > now),
                    )
                )
                entries = result.scalars().all()

            if not entries:
                return 0
            pipe = self._redis.pipeline()
            count = 0
            for e in entries:
                ttl_sec = (
                    int((e.expires_at - now).total_seconds())
                    if e.expires_at else 86400 * 365
                )
                if ttl_sec <= 0:
                    continue
                pipe.set(_redis_key(e.package_name, e.ip), e.code or "warm", ex=ttl_sec)
                count += 1
                if count % 1000 == 0:
                    await pipe.execute()
                    pipe = self._redis.pipeline()
            if count % 1000 != 0:
                await pipe.execute()
            return count
        except Exception as e:
            logger.warning(f"AutoBan warm failed: {e}")
            return 0


# Singleton
auto_ban = AutoBan()
