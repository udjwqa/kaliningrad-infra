import os
import json
import uuid
import hashlib
import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional
import redis.asyncio as aioredis
from models import RequestLogEntry, ScoringResult
from database import async_session
from db_models import RequestLog
from sqlalchemy import select, func, desc, or_, not_

logger = logging.getLogger("request_logger")

# P1-4 (2026-06-21): allowlist headers сохраняемых в raw_payload as-is.
# Раньше писали полный dict включая x-proxy-key, x-client-secret, x-app-token,
# integrity_token plaintext → insider 5 минут exfil всего secret-каталога через
# GET /api/audit/logs. Backup leak = master-key compromise.
HEADER_ALLOWLIST = {
    # CF / geo — нужны для UI feed
    "cf-ipcountry", "cf-ray", "cf-connecting-ip",
    "x-cf-country", "x-cf-asn",
    # Стандартные клиентские (без секретов)
    "user-agent", "accept-language", "accept", "accept-encoding",
    "referer", "referrer", "origin", "host",
    # Кастомные клиентские (наш SDK, без секретов)
    "x-package-name", "x-app-id", "x-device-model", "x-device-codename",
    "x-device-info", "x-graphics-info", "x-gpu-renderer", "x-build-product",
    "x-os-version", "x-instance-id", "x-isp", "x-country", "x-country-code",
    "x-city", "source",
    # 2026-07-10 debug headers для диагностики IP цепочки
    "x-real-user-ip", "x-real-ip", "x-forwarded-for",
}

# Заголовки которые СЛЕДУЕТ хешировать (sha256[:8] для equality-debug без plaintext).
HEADER_SENSITIVE = {
    "x-proxy-key", "x-client-secret", "x-app-token", "x-admin-key",
    "x-integrity-token", "integrity-token", "authorization", "cookie",
    "x-csrf-token", "x-api-key",
}


def _sanitize_headers(headers) -> dict:
    """P1-4: возвращает dict только с allowlisted ключами + sha256[:8] для sensitive.
    Всё что не в allowlist и не в sensitive — дропается (privacy-by-default)."""
    if not headers:
        return {}
    out = {}
    for raw_k, v in dict(headers).items():
        k = (raw_k or "").lower()
        if k in HEADER_ALLOWLIST:
            out[k] = v
        elif k in HEADER_SENSITIVE:
            if v:
                h = hashlib.sha256(str(v).encode("utf-8", errors="ignore")).hexdigest()[:8]
                out[k] = f"sha256:{h}"
        # else: drop entirely
    return out

MAX_MEMORY_ENTRIES = 500
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# P1-2 (2026-06-21): TTL 86400s (24h) был self-inflicted backdoor — один честный PI
# verdict открывал 24h окно реплея с того же IP. Снижено до 180s — достаточно для
# смягчения burst квоты Google PI API, но не для replay protection.
# Для полной replay protection см. nonce-replay (MED-2 уже зафикшен).
PI_CACHE_TTL = 180


class RequestLogger:
    def __init__(self):
        self._recent = deque(maxlen=MAX_MEMORY_ENTRIES)
        self._last_pi: dict[str, dict] = {}
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        return self._redis

    async def _cache_pi(self, ip: str, package_name: str, pi_data: dict):
        key = f"{ip}:{package_name}" if package_name else ip
        self._last_pi[key] = pi_data
        try:
            r = await self._get_redis()
            await r.set(f"pi_cache:{key}", json.dumps(pi_data), ex=PI_CACHE_TTL)
        except Exception:
            pass

    async def _get_cached_pi(self, ip: str, package_name: str = "") -> dict:
        key = f"{ip}:{package_name}" if package_name else ip
        if key in self._last_pi:
            return self._last_pi[key]
        try:
            r = await self._get_redis()
            data = await r.get(f"pi_cache:{key}")
            if data:
                pi = json.loads(data)
                self._last_pi[key] = pi
                return pi
        except Exception:
            pass
        return {}

    async def log(
        self,
        ip: str,
        result: ScoringResult,
        user_agent: str = "",
        accept_language: str = "",
        device_model: str = "",
        os_version: str = "",
        country: str = "",
        country_code: str = "",
        city: str = "",
        headers: Optional[dict] = None,
        js_metrics: Optional[dict] = None,
        extra_payload: Optional[dict] = None,
    ):
        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        source = (headers or {}).get("source", "")
        pi_data = (js_metrics or {}).get("playIntegrity", {})
        pkg = (headers or {}).get("x-package-name", "") or (headers or {}).get("x-app-id", "")

        if source == "play_integrity" and pi_data:
            await self._cache_pi(ip, pkg, pi_data)

        if not pi_data:
            pi_data = await self._get_cached_pi(ip, pkg)

        # P1-4 (2026-06-21): sanitize headers — allowlist + sha256[:8] для sensitive.
        # 2026-06-22: extra_payload — compact trace fields (scoreBuckets, piMode,
        # softEligible, hardKill, classification) для UI обзора клика.
        raw_payload = {
            "headers": _sanitize_headers(headers),
            "scoringDetails": [d.model_dump() for d in result.details],
            "jsMetrics": js_metrics or {},
            "playIntegrity": pi_data,
        }
        if extra_payload:
            # 2026-07-14: mini-clo (source=mini-clo) кладёт PI verdict в extra_payload.pi.
            # main КЛО own /init кладёт в raw_payload.playIntegrity через js_metrics.
            # Панель UI читает только playIntegrity — без alias'а mini-clo клика видны как pi:{} playIntegrity:{}.
            # Alias копирует pi→playIntegrity ТОЛЬКО если playIntegrity ещё пуст (не трогает main КЛО own /init).
            if not pi_data and extra_payload.get('pi'):
                raw_payload['playIntegrity'] = extra_payload.get('pi') or {}
            raw_payload.update(extra_payload)

        memory_entry = RequestLogEntry(
            id=entry_id,
            timestamp=now.isoformat() + "Z",
            ip=ip,
            country=country,
            countryCode=country_code,
            deviceModel=device_model,
            os=os_version,
            score=result.score,
            verdict=result.verdict,
            rejectionCode=result.rejectionCode,
            rawPayload=raw_payload,
        )
        self._recent.appendleft(memory_entry)

        try:
            async with async_session() as session:
                db_entry = RequestLog(
                    id=uuid.UUID(entry_id),
                    timestamp=now,
                    ip=ip,
                    country=country,
                    country_code=country_code,
                    city=city,
                    device_model=device_model,
                    os=os_version,
                    user_agent=user_agent,
                    score=result.score,
                    verdict=result.verdict,
                    rejection_code=result.rejectionCode,
                    package_name=pkg,
                    raw_payload=raw_payload,
                )
                session.add(db_entry)
                await session.commit()
            logger.info(f"DB write ok: id={entry_id[:8]} verdict={result.verdict}")
        except Exception as e:
            import traceback
            logger.error(f"Failed to write to DB: {type(e).__name__}: {e}\n{traceback.format_exc()}")

    async def get_recent(self, limit: int = 50):
        entries = list(self._recent)[:limit]
        if not entries:
            try:
                async with async_session() as session:
                    q = await session.execute(
                        select(RequestLog)
                        .order_by(desc(RequestLog.timestamp))
                        .limit(limit)
                    )
                    rows = q.scalars().all()
                    entries = [RequestLogEntry(**r.to_dict()) for r in rows]
            except Exception as e:
                logger.error(f"get_recent DB fallback error: {e}")
                entries = []

        for entry in entries:
            raw = entry.rawPayload if isinstance(entry.rawPayload, dict) else {}
            pi = raw.get("playIntegrity", {})
            ip = entry.ip if hasattr(entry, "ip") else ""
            if not pi and ip:
                hdrs = raw.get("headers", {})
                pkg = hdrs.get("x-package-name", "") or hdrs.get("x-app-id", "")
                cached = await self._get_cached_pi(ip, pkg)
                if cached:
                    raw["playIntegrity"] = cached
        return entries

    async def get_metrics(self):
        try:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
            async with async_session() as session:
                total_q = await session.execute(
                    select(func.count()).select_from(RequestLog).where(RequestLog.timestamp > cutoff)
                )
                total = total_q.scalar() or 0

                grey_q = await session.execute(
                    select(func.count()).select_from(RequestLog).where(
                        RequestLog.timestamp > cutoff,
                        RequestLog.verdict == "grey",
                    )
                )
                grey = grey_q.scalar() or 0
                white = total - grey

                bans_q = await session.execute(
                    select(func.count()).select_from(RequestLog).where(
                        RequestLog.timestamp > cutoff,
                        RequestLog.score >= 100,
                    )
                )
                bans = bans_q.scalar() or 0

            grey_pct = round(grey / total * 100) if total > 0 else 0
            white_pct = 100 - grey_pct if total > 0 else 0

            from config import config_store as _cs
            active_keys = len([a for a in _cs.apps if _cs.get_proxy_key_for_package(a.package_name)])

            return {
                "requests24h": total,
                "greyTraffic": {"count": grey, "percentage": grey_pct},
                "whiteTraffic": {"count": white, "percentage": white_pct},
                "activeBans24h": bans,
                "currentRps": 0,
                "activeKeys": active_keys,
            }
        except Exception as e:
            logger.error(f"get_metrics error: {e}")
            return {
                "requests24h": 0,
                "greyTraffic": {"count": 0, "percentage": 0},
                "whiteTraffic": {"count": 0, "percentage": 0},
                "activeBans24h": 0,
                "currentRps": 0,
                "activeKeys": 0,
            }

    async def get_traffic_hourly(self):
        try:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
            async with async_session() as session:
                q = await session.execute(
                    select(
                        func.date_trunc("hour", RequestLog.timestamp).label("hour"),
                        RequestLog.verdict,
                        func.count().label("cnt"),
                    )
                    .where(RequestLog.timestamp > cutoff)
                    .group_by("hour", RequestLog.verdict)
                    .order_by("hour")
                )
                rows = q.all()

            hourly: dict[str, dict[str, int]] = {}
            for h in range(24):
                t = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=23 - h)).replace(minute=0, second=0, microsecond=0)
                key = f"{t.hour:02d}:00"
                hourly[key] = {"grey": 0, "white": 0}

            for hour_ts, verdict, cnt in rows:
                key = f"{hour_ts.hour:02d}:00"
                if key in hourly and verdict in ("grey", "white"):
                    hourly[key][verdict] = cnt

            return [
                {"hour": k, "grey": v["grey"], "white": v["white"]}
                for k, v in hourly.items()
            ]
        except Exception as e:
            logger.error(f"get_traffic_hourly error: {e}")
            return []

    async def get_rejections(self):
        labels = {
            "no_client_secret": "Нет клиентского секрета",
            "bot_user_agent": "Бот User-Agent",
            "country_blocked": "Страна заблокирована",
            "device_blocked": "Устройство заблокировано",
            "google_device_combo": "Google-устройство + 2-й признак",
            "emulator_detected": "Эмулятор обнаружен",
            "emulator_gpu": "GPU эмулятора",
            "suspicious_hosting": "Подозрительный хостинг",
            "vpn_detected": "VPN обнаружен",
            "proxy_detected": "Proxy обнаружен",
            "tor_detected": "Tor обнаружен",
            "ipqs_high_fraud": "IPQS высокий fraud",
            "bot_detected": "Бот обнаружен",
            "honeypot": "Honeypot ловушка",
            "honeyfield_bot": "Honeyfield бот",
            "integrity_invalid": "Play Integrity: недействительный",
            "integrity_missing": "Play Integrity: токен отсутствует (require)",
            "device_compromised": "Play Integrity: устройство скомпрометировано",
            "app_tampered": "Play Integrity: приложение модифицировано",
            "ip_range_blocked": "IP в диапазоне датацентров",
            "asn_blocked": "ASN датацентра",
            "static_device": "Статичное устройство",
            "mouse_without_touch": "Мышь без тача",
            "timezone_mismatch": "Несовпадение таймзоны",
            "behavioral_score": "Поведенческий скоринг",
            "velocity_block": "Velocity / burst (бот-частота)",
            "device_spoof": "Подмена фингерпринта (GPU↔модель)",
            "v2_gateway_locked": "v2-gateway закрыт (прила на v3)",
            "country_not_allowed": "Страна не в whitelist прилы",
            "device_velocity": "Device-fingerprint: >30 запросов/час",
        }
        try:
            async with async_session() as session:
                q = await session.execute(
                    select(
                        RequestLog.rejection_code,
                        func.count().label("cnt"),
                    )
                    .where(RequestLog.rejection_code.isnot(None))
                    .group_by(RequestLog.rejection_code)
                    .order_by(desc("cnt"))
                )
                rows = q.all()
            return [
                {"code": code, "label": labels.get(code, code), "count": cnt}
                for code, cnt in rows
            ]
        except Exception as e:
            logger.error(f"get_rejections error: {e}")
            return []

    async def query_logs(
        self,
        search: str = "",
        verdict: str = "all",
        rejection_code: Optional[str] = None,
        country: Optional[str] = None,
        package_name: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        anonymous_type: Optional[str] = None,
        page: int = 1,
        page_size: int = 25,
    ):
        try:
            async with async_session() as session:
                base = select(RequestLog)
                count_base = select(func.count()).select_from(RequestLog)

                conditions = []
                if search:
                    pattern = f"%{search}%"
                    conditions.append(
                        RequestLog.ip.ilike(pattern)
                        | RequestLog.user_agent.ilike(pattern)
                        | RequestLog.device_model.ilike(pattern)
                    )
                if verdict and verdict != "all":
                    conditions.append(RequestLog.verdict == verdict)
                if rejection_code:
                    conditions.append(RequestLog.rejection_code == rejection_code)
                if country:
                    conditions.append(RequestLog.country_code == country.upper())
                if package_name:
                    conditions.append(RequestLog.package_name == package_name)
                if date_from:
                    conditions.append(
                        RequestLog.timestamp >= datetime.fromisoformat(date_from)
                    )
                if date_to:
                    conditions.append(
                        RequestLog.timestamp <= datetime.fromisoformat(date_to) + timedelta(days=1)
                    )
                if anonymous_type:
                    _flag_keys = ("vpn", "proxy", "res_proxy", "tor", "hosting", "relay", "mobile")
                    if anonymous_type == "clean":
                        conditions.append(not_(or_(
                            *[RequestLog.raw_payload["ipinfo"][k].astext == "true"
                              for k in ("vpn", "proxy", "res_proxy", "tor", "hosting", "relay")]
                        )))
                    elif anonymous_type in _flag_keys:
                        conditions.append(
                            RequestLog.raw_payload["ipinfo"][anonymous_type].astext == "true"
                        )

                for cond in conditions:
                    base = base.where(cond)
                    count_base = count_base.where(cond)

                total_q = await session.execute(count_base)
                total = total_q.scalar() or 0

                total_pages = max(1, -(-total // page_size))
                safe_page = min(page, total_pages)
                offset = (safe_page - 1) * page_size

                rows_q = await session.execute(
                    base.order_by(desc(RequestLog.timestamp))
                    .offset(offset)
                    .limit(page_size)
                )
                rows = rows_q.scalars().all()

            entries = []
            for r in rows:
                d = r.to_dict()
                pi = d.get("rawPayload", {}).get("playIntegrity", {})
                if not pi and r.ip:
                    hdrs = d.get("rawPayload", {}).get("headers", {})
                    pkg = hdrs.get("x-package-name", "") or hdrs.get("x-app-id", "")
                    cached = await self._get_cached_pi(r.ip, pkg)
                    if cached:
                        d.setdefault("rawPayload", {})["playIntegrity"] = cached
                entries.append(d)

            return {
                "entries": entries,
                "total": total,
                "page": safe_page,
                "pageSize": page_size,
                "totalPages": total_pages,
            }
        except Exception as e:
            logger.error(f"query_logs error: {e}")
            return {
                "entries": [], "total": 0, "page": 1,
                "pageSize": page_size, "totalPages": 1,
            }


    async def get_app_stats_all(self):
        try:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
            async with async_session() as session:
                q = await session.execute(
                    select(
                        RequestLog.package_name,
                        RequestLog.verdict,
                        func.count().label("cnt"),
                    )
                    .where(RequestLog.timestamp > cutoff, RequestLog.package_name.isnot(None), RequestLog.package_name != "")
                    .group_by(RequestLog.package_name, RequestLog.verdict)
                )
                rows = q.all()

            from config import config_store
            stats: dict[str, dict] = {}
            for pkg, verdict, cnt in rows:
                if pkg not in stats:
                    app = config_store.get_app(pkg)
                    stats[pkg] = {
                        "package_name": pkg,
                        "name": app.name if app else pkg.split(".")[-1],
                        "total": 0, "grey": 0, "white": 0,
                    }
                stats[pkg]["total"] += cnt
                if verdict in ("grey", "white"):
                    stats[pkg][verdict] += cnt

            result = []
            for s in sorted(stats.values(), key=lambda x: x["total"], reverse=True):
                t = s["total"]
                s["greyPct"] = round(s["grey"] / t * 100) if t > 0 else 0
                s["whitePct"] = 100 - s["greyPct"] if t > 0 else 0
                result.append(s)
            return result
        except Exception as e:
            logger.error(f"get_app_stats_all error: {e}")
            return []

    async def get_app_detail(self, package_name: str):
        labels = {
            "no_client_secret": "Нет секрета",
            "bot_user_agent": "Бот UA",
            "country_blocked": "Страна",
            "device_blocked": "Устройство",
            "emulator_detected": "Эмулятор",
            "emulator_gpu": "GPU эмулятора",
            "suspicious_hosting": "Хостинг",
            "vpn_detected": "VPN",
            "proxy_detected": "Proxy",
            "integrity_invalid": "PI: недействительный",
            "device_compromised": "PI: устройство",
            "app_tampered": "PI: приложение",
            "ip_range_blocked": "IP диапазон",
            "behavioral_score": "Поведение",
            "device_spoof": "Подмена фингерпринта",
            "v2_gateway_locked": "v2-gateway закрыт",
            "country_not_allowed": "Страна не в whitelist",
            "device_velocity": "Device velocity",
        }
        try:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
            async with async_session() as session:
                total_q = await session.execute(
                    select(func.count()).select_from(RequestLog)
                    .where(RequestLog.timestamp > cutoff, RequestLog.package_name == package_name)
                )
                total = total_q.scalar() or 0

                grey_q = await session.execute(
                    select(func.count()).select_from(RequestLog)
                    .where(RequestLog.timestamp > cutoff, RequestLog.package_name == package_name, RequestLog.verdict == "grey")
                )
                grey = grey_q.scalar() or 0
                white = total - grey

                bans_q = await session.execute(
                    select(func.count()).select_from(RequestLog)
                    .where(RequestLog.timestamp > cutoff, RequestLog.package_name == package_name, RequestLog.score >= 100)
                )
                bans = bans_q.scalar() or 0

                hourly_q = await session.execute(
                    select(
                        func.date_trunc("hour", RequestLog.timestamp).label("hour"),
                        RequestLog.verdict,
                        func.count().label("cnt"),
                    )
                    .where(RequestLog.timestamp > cutoff, RequestLog.package_name == package_name)
                    .group_by("hour", RequestLog.verdict)
                    .order_by("hour")
                )
                hourly_rows = hourly_q.all()

                rej_q = await session.execute(
                    select(RequestLog.rejection_code, func.count().label("cnt"))
                    .where(
                        RequestLog.timestamp > cutoff,
                        RequestLog.package_name == package_name,
                        RequestLog.rejection_code.isnot(None),
                    )
                    .group_by(RequestLog.rejection_code)
                    .order_by(desc("cnt"))
                )
                rej_rows = rej_q.all()

            hourly: dict[str, dict[str, int]] = {}
            for h in range(24):
                t = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=23 - h)).replace(minute=0, second=0, microsecond=0)
                key = f"{t.hour:02d}:00"
                hourly[key] = {"grey": 0, "white": 0}
            for hour_ts, verdict, cnt in hourly_rows:
                key = f"{hour_ts.hour:02d}:00"
                if key in hourly and verdict in ("grey", "white"):
                    hourly[key][verdict] = cnt

            return {
                "metrics": {"total": total, "grey": grey, "white": white, "bans": bans},
                "hourly": [{"hour": k, "grey": v["grey"], "white": v["white"]} for k, v in hourly.items()],
                "rejections": [{"code": c, "label": labels.get(c, c), "count": n} for c, n in rej_rows],
            }
        except Exception as e:
            logger.error(f"get_app_detail error: {e}")
            return {"metrics": {"total": 0, "grey": 0, "white": 0, "bans": 0}, "hourly": [], "rejections": []}


    async def get_analytics(
        self,
        date_from: str,
        date_to: str,
        package_name: str | None = None,
    ):
        """
        Аналитика per-app + per-day (МСК). date_from/to — 'YYYY-MM-DD' в МСК.
        Диапазон включает оба конца (полный день).

        Возврат:
            {
              "period": {"from": ..., "to": ..., "days": N, "tz": "MSK"},
              "totals": {"clicks": N, "uniq_install": N, "uniq_ip": N,
                         "grey": N, "white": N, "bans": N},
              "per_app": [{"package_name", "name", "clicks", "uniq_install",
                           "uniq_ip", "grey", "white", "grey_pct", "bans"}],
              "per_day": [{"date": "2026-07-09", "clicks", "uniq_install",
                           "uniq_ip", "grey", "white"}],
              "per_app_per_day": [...] — для drill-down (single app)
            }
        """
        from sqlalchemy import text as sql_text
        from config import config_store

        try:
            # Один raw-query. `+3 hours` сдвигает naive UTC в MSK — далее ::date.
            # instance_id живёт в raw_payload->'headers'->>'x-instance-id'.
            from datetime import date as _date
            pkg_filter = ""
            params = {
                "date_from": _date.fromisoformat(date_from),
                "date_to": _date.fromisoformat(date_to),
            }
            if package_name:
                pkg_filter = "AND package_name = :pkg"
                params["pkg"] = package_name

            sql = f"""
                SELECT
                    (timestamp + interval '3 hours')::date AS msk_date,
                    package_name,
                    verdict,
                    count(*) AS clicks,
                    count(DISTINCT ip) AS uniq_ip,
                    count(DISTINCT (raw_payload->'headers'->>'x-instance-id')) AS uniq_install
                FROM request_logs
                WHERE (timestamp + interval '3 hours')::date >= CAST(:date_from AS DATE)
                  AND (timestamp + interval '3 hours')::date <= CAST(:date_to AS DATE)
                  AND package_name IS NOT NULL AND package_name != ''
                  {pkg_filter}
                GROUP BY msk_date, package_name, verdict
                ORDER BY msk_date, package_name
            """
            async with async_session() as session:
                res = await session.execute(sql_text(sql), params)
                rows = res.all()

                # Bans per (msk_date, package_name) из auto_banned_entries
                bans_sql = f"""
                    SELECT
                        (banned_at + interval '3 hours')::date AS msk_date,
                        package_name,
                        count(*) AS bans
                    FROM auto_banned_entries
                    WHERE (banned_at + interval '3 hours')::date >= CAST(:date_from AS DATE)
                      AND (banned_at + interval '3 hours')::date <= CAST(:date_to AS DATE)
                      AND package_name IS NOT NULL
                      {pkg_filter}
                    GROUP BY msk_date, package_name
                """
                bans_res = await session.execute(sql_text(bans_sql), params)
                bans_rows = bans_res.all()

            # Агрегируем в python — БД уже минимально сжала.
            per_app: dict[str, dict] = {}
            per_day: dict[str, dict] = {}
            per_app_per_day: dict[tuple, dict] = {}

            def _new_row():
                return {"clicks": 0, "uniq_install": 0, "uniq_ip": 0,
                        "grey": 0, "white": 0, "bans": 0}

            for msk_date, pkg, verdict, clicks, uniq_ip, uniq_install in rows:
                d = msk_date.isoformat()

                # per_app aggregate (сумма по всем дням)
                if pkg not in per_app:
                    app = config_store.get_app(pkg)
                    per_app[pkg] = _new_row()
                    per_app[pkg]["package_name"] = pkg
                    per_app[pkg]["name"] = app.name if app else pkg.split(".")[-1]
                # ВНИМАНИЕ: distinct-суммы по разным дням не равны distinct за
                # весь период (один install мог логиниться в оба дня). Здесь мы
                # просто складываем — это upper-bound. Для точности per-app
                # общий уник считаем отдельным запросом ниже.
                per_app[pkg]["clicks"] += int(clicks or 0)
                if verdict == "grey":
                    per_app[pkg]["grey"] += int(clicks or 0)
                elif verdict == "white":
                    per_app[pkg]["white"] += int(clicks or 0)

                # per_day aggregate (сумма по всем прил)
                if d not in per_day:
                    per_day[d] = _new_row()
                    per_day[d]["date"] = d
                per_day[d]["clicks"] += int(clicks or 0)
                if verdict == "grey":
                    per_day[d]["grey"] += int(clicks or 0)
                elif verdict == "white":
                    per_day[d]["white"] += int(clicks or 0)

                # per_app_per_day (drill-down)
                key = (pkg, d)
                if key not in per_app_per_day:
                    per_app_per_day[key] = _new_row()
                    per_app_per_day[key]["package_name"] = pkg
                    per_app_per_day[key]["date"] = d
                per_app_per_day[key]["clicks"] += int(clicks or 0)
                per_app_per_day[key]["uniq_install"] += int(uniq_install or 0)
                per_app_per_day[key]["uniq_ip"] += int(uniq_ip or 0)
                if verdict == "grey":
                    per_app_per_day[key]["grey"] += int(clicks or 0)
                elif verdict == "white":
                    per_app_per_day[key]["white"] += int(clicks or 0)

            # Уники (install/ip) корректно за весь период per app и per day —
            # отдельный distinct-count запрос (не сумма по дням).
            uniq_app_sql = f"""
                SELECT
                    package_name,
                    count(DISTINCT ip) AS uniq_ip,
                    count(DISTINCT (raw_payload->'headers'->>'x-instance-id')) AS uniq_install
                FROM request_logs
                WHERE (timestamp + interval '3 hours')::date >= CAST(:date_from AS DATE)
                  AND (timestamp + interval '3 hours')::date <= CAST(:date_to AS DATE)
                  AND package_name IS NOT NULL AND package_name != ''
                  {pkg_filter}
                GROUP BY package_name
            """
            uniq_day_sql = f"""
                SELECT
                    (timestamp + interval '3 hours')::date AS msk_date,
                    count(DISTINCT ip) AS uniq_ip,
                    count(DISTINCT (raw_payload->'headers'->>'x-instance-id')) AS uniq_install
                FROM request_logs
                WHERE (timestamp + interval '3 hours')::date >= CAST(:date_from AS DATE)
                  AND (timestamp + interval '3 hours')::date <= CAST(:date_to AS DATE)
                  AND package_name IS NOT NULL AND package_name != ''
                  {pkg_filter}
                GROUP BY msk_date
            """
            async with async_session() as session:
                for pkg, u_ip, u_inst in (await session.execute(sql_text(uniq_app_sql), params)).all():
                    if pkg in per_app:
                        per_app[pkg]["uniq_ip"] = int(u_ip or 0)
                        per_app[pkg]["uniq_install"] = int(u_inst or 0)
                for d, u_ip, u_inst in (await session.execute(sql_text(uniq_day_sql), params)).all():
                    d_iso = d.isoformat()
                    if d_iso in per_day:
                        per_day[d_iso]["uniq_ip"] = int(u_ip or 0)
                        per_day[d_iso]["uniq_install"] = int(u_inst or 0)

            # Bans → добавляем per_app и per_day
            for msk_date, pkg, bans in bans_rows:
                d = msk_date.isoformat()
                if pkg in per_app:
                    per_app[pkg]["bans"] += int(bans or 0)
                if d in per_day:
                    per_day[d]["bans"] += int(bans or 0)
                key = (pkg, d)
                if key in per_app_per_day:
                    per_app_per_day[key]["bans"] = int(bans or 0)

            # % grey per app
            for a in per_app.values():
                t = a["clicks"]
                a["grey_pct"] = round(a["grey"] / t * 100, 1) if t > 0 else 0.0

            # totals + сортировка
            totals = _new_row()
            for a in per_app.values():
                totals["clicks"] += a["clicks"]
                totals["grey"] += a["grey"]
                totals["white"] += a["white"]
                totals["bans"] += a["bans"]
            # Total uniques (correct — distinct across ALL apps ALL days)
            async with async_session() as session:
                totals_uniq_sql = f"""
                    SELECT
                        count(DISTINCT ip) AS uniq_ip,
                        count(DISTINCT (raw_payload->'headers'->>'x-instance-id')) AS uniq_install
                    FROM request_logs
                    WHERE (timestamp + interval '3 hours')::date >= CAST(:date_from AS DATE)
                      AND (timestamp + interval '3 hours')::date <= CAST(:date_to AS DATE)
                      AND package_name IS NOT NULL AND package_name != ''
                      {pkg_filter}
                """
                row = (await session.execute(sql_text(totals_uniq_sql), params)).first()
                if row:
                    totals["uniq_ip"] = int(row[0] or 0)
                    totals["uniq_install"] = int(row[1] or 0)

            from datetime import date as _date
            d_from = _date.fromisoformat(date_from)
            d_to = _date.fromisoformat(date_to)
            days = (d_to - d_from).days + 1

            return {
                "period": {"from": date_from, "to": date_to, "days": days, "tz": "MSK"},
                "totals": totals,
                "per_app": sorted(per_app.values(), key=lambda x: x["clicks"], reverse=True),
                "per_day": sorted(per_day.values(), key=lambda x: x["date"]),
                "per_app_per_day": sorted(per_app_per_day.values(), key=lambda x: (x["package_name"], x["date"])),
            }
        except Exception as e:
            logger.error(f"get_analytics error: {e}")
            return {
                "period": {"from": date_from, "to": date_to, "days": 0, "tz": "MSK"},
                "totals": {"clicks": 0, "uniq_install": 0, "uniq_ip": 0,
                           "grey": 0, "white": 0, "bans": 0},
                "per_app": [], "per_day": [], "per_app_per_day": [],
                "error": str(e),
            }


request_logger = RequestLogger()
