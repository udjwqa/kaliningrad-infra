"""Health-check endpoints для внешних API.

Используется панелью "Системы защиты" (/dashboard/defense) — клиент жмёт "Health
check" на карточке внешнего API, BFF панели идёт сюда, мы делаем trivial probe
к real-сервису и возвращаем {ok, latency_ms, message, details}.

Защищено AdminAuthMiddleware (X-Admin-Key header).
"""

import time
import logging
from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = logging.getLogger("health_api")

router = APIRouter(prefix="/api/health-ext", tags=["health-ext"])


@router.get("/ipqs")
async def health_ipqs():
    """IPQS lookup для 8.8.8.8 — проверяем что ключ работает и API доступен."""
    from external.ipqs_client import ipqs_client, IPQS_API_KEY

    if not IPQS_API_KEY:
        return {"ok": False, "service": "ipqs", "latency_ms": 0,
                "message": "IPQS_API_KEY не задан в .env (fail-open режим)",
                "details": {"key_configured": False}}

    t0 = time.monotonic()
    try:
        result = await ipqs_client.lookup("8.8.8.8")
        latency = int((time.monotonic() - t0) * 1000)
        if result and result.success:
            return {"ok": True, "service": "ipqs", "latency_ms": latency,
                    "message": f"IPQS работает (fraud_score={result.fraud_score} для 8.8.8.8)",
                    "details": {"key_configured": True, "fraud_score": result.fraud_score,
                                "ISP": result.isp[:60]}}
        return {"ok": False, "service": "ipqs", "latency_ms": latency,
                "message": "IPQS вернул success=false (возможно лимит/неверный ключ)",
                "details": {"raw": (result.raw if result else {})}}
    except Exception as e:
        latency = int((time.monotonic() - t0) * 1000)
        return {"ok": False, "service": "ipqs", "latency_ms": latency,
                "message": f"Ошибка: {str(e)[:200]}", "details": {}}


@router.get("/ipinfo")
async def health_ipinfo():
    """IPinfo lookup для 8.8.8.8."""
    from external.ipinfo_client import ipinfo_client
    import os

    t0 = time.monotonic()
    try:
        result = await ipinfo_client.lookup("8.8.8.8")
        latency = int((time.monotonic() - t0) * 1000)
        if result and result.country:
            return {"ok": True, "service": "ipinfo", "latency_ms": latency,
                    "message": f"IPinfo работает (страна={result.country}, ISP={result.org[:40]})",
                    "details": {"token_configured": bool(os.getenv("IPINFO_TOKEN", "")),
                                "country": result.country, "org": result.org[:60]}}
        return {"ok": False, "service": "ipinfo", "latency_ms": latency,
                "message": "IPinfo вернул пустой результат", "details": {}}
    except Exception as e:
        latency = int((time.monotonic() - t0) * 1000)
        return {"ok": False, "service": "ipinfo", "latency_ms": latency,
                "message": f"Ошибка: {str(e)[:200]}", "details": {}}


@router.get("/play_integrity")
async def health_play_integrity():
    """PI client — проверяем что загружены GCP keys (без real verify)."""
    from external.play_integrity import play_integrity_client

    t0 = time.monotonic()
    try:
        keys_count = len(play_integrity_client._services)
        projects = sorted(play_integrity_client._services.keys())
        latency = int((time.monotonic() - t0) * 1000)
        if keys_count > 0 and play_integrity_client.available:
            return {"ok": True, "service": "play_integrity", "latency_ms": latency,
                    "message": f"Play Integrity готов ({keys_count} GCP ключей загружено)",
                    "details": {"keys_count": keys_count, "projects": projects[:10]}}
        return {"ok": False, "service": "play_integrity", "latency_ms": latency,
                "message": "Play Integrity не инициализирован — нет gcp-key*.json в config/",
                "details": {"keys_count": keys_count}}
    except Exception as e:
        latency = int((time.monotonic() - t0) * 1000)
        return {"ok": False, "service": "play_integrity", "latency_ms": latency,
                "message": f"Ошибка: {str(e)[:200]}", "details": {}}


@router.get("/redis")
async def health_redis():
    """Redis PING."""
    from request_logger import request_logger

    t0 = time.monotonic()
    try:
        r = await request_logger._get_redis()
        pong = await r.ping()
        latency = int((time.monotonic() - t0) * 1000)
        if pong:
            try:
                info = await r.info("memory")
                used_mb = int(info.get("used_memory", 0)) // (1024 * 1024)
            except Exception:
                used_mb = 0
            return {"ok": True, "service": "redis", "latency_ms": latency,
                    "message": f"Redis отвечает (PING={pong}, RAM={used_mb}MB)",
                    "details": {"used_memory_mb": used_mb}}
        return {"ok": False, "service": "redis", "latency_ms": latency,
                "message": "Redis PING вернул false", "details": {}}
    except Exception as e:
        latency = int((time.monotonic() - t0) * 1000)
        return {"ok": False, "service": "redis", "latency_ms": latency,
                "message": f"Ошибка: {str(e)[:200]}", "details": {}}


@router.get("/postgres")
async def health_postgres():
    """Postgres SELECT 1 + row count из request_logs."""
    from database import async_session
    from sqlalchemy import text

    t0 = time.monotonic()
    try:
        async with async_session() as session:
            r1 = await session.execute(text("SELECT 1"))
            assert r1.scalar() == 1

            r2 = await session.execute(text(
                "SELECT COUNT(*), MAX(timestamp) FROM request_logs "
                "WHERE timestamp > NOW() - INTERVAL '1 hour'"))
            row = r2.fetchone()
            recent_count = int(row[0]) if row else 0
            last_ts = row[1].isoformat() if row and row[1] else None

        latency = int((time.monotonic() - t0) * 1000)
        return {"ok": True, "service": "postgres", "latency_ms": latency,
                "message": f"Postgres работает ({recent_count} логов за час)",
                "details": {"recent_logs_1h": recent_count, "last_log_ts": last_ts}}
    except Exception as e:
        latency = int((time.monotonic() - t0) * 1000)
        return {"ok": False, "service": "postgres", "latency_ms": latency,
                "message": f"Ошибка: {str(e)[:200]}", "details": {}}


@router.get("/cf_kv")
async def health_cf_kv():
    """CF KV — мы не можем напрямую проверить из бэкенда (KV биндинг только в воркере).
    Возвращаем статус "informational" (всегда ok=true, message объясняет).
    """
    return {"ok": True, "service": "cf_kv", "latency_ms": 0,
            "message": "CF Workers KV — биндится в воркере, прямая проверка из бэкенда невозможна. Используется для PANIC_MODE / CLIENT_SECRET / BLOCKED_ASNS rotation.",
            "details": {"note": "Health через CF dashboard или wrangler kv:key list"}}
