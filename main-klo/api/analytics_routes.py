"""
Analytics — Keitaro-style per-app / per-day статистика (2026-07-09).

Endpoints:
- GET /api/analytics/apps-stats?date_from=&date_to=&package_name=
  Полный ответ: totals + per_app + per_day + per_app_per_day.
  Кеш в Redis 60 сек по SHA256 params.

Timezone: МСК (UTC+3). date_from/to — 'YYYY-MM-DD' в МСК.
"""
import hashlib
import json
import time
from datetime import date

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from request_logger import request_logger

router = APIRouter()

_CACHE_TTL = 60  # sec


def _redis():
    try:
        return request_logger._get_redis()
    except Exception:
        return None


def _cache_key(date_from: str, date_to: str, pkg: str | None) -> str:
    raw = f"{date_from}|{date_to}|{pkg or ''}"
    return "analytics:v1:" + hashlib.sha256(raw.encode()).hexdigest()[:24]


def _validate_range(date_from: str, date_to: str) -> tuple[bool, str]:
    try:
        d_from = date.fromisoformat(date_from)
        d_to = date.fromisoformat(date_to)
    except ValueError:
        return False, "date_from/date_to must be YYYY-MM-DD"
    if d_to < d_from:
        return False, "date_to must be >= date_from"
    if (d_to - d_from).days > 92:
        return False, "range too large (max 92 days)"
    return True, ""


@router.get("/api/analytics/apps-stats")
async def apps_stats(
    date_from: str = Query(..., description="YYYY-MM-DD (MSK)"),
    date_to: str = Query(..., description="YYYY-MM-DD (MSK)"),
    package_name: str | None = Query(default=None),
):
    ok, err = _validate_range(date_from, date_to)
    if not ok:
        return JSONResponse({"error": err}, status_code=400)

    key = _cache_key(date_from, date_to, package_name)
    r = _redis()
    if r is not None:
        try:
            cached = await r.get(key)
            if cached:
                return JSONResponse(content=json.loads(cached))
        except Exception:
            pass

    t0 = time.monotonic()
    data = await request_logger.get_analytics(date_from, date_to, package_name)
    data["_meta"] = {
        "elapsed_ms": int((time.monotonic() - t0) * 1000),
        "cached": False,
    }

    if r is not None:
        try:
            await r.setex(key, _CACHE_TTL, json.dumps(data))
        except Exception:
            pass

    return data


@router.post("/api/analytics/cache-invalidate")
async def cache_invalidate():
    """Ручной сброс analytics кеша (после ручной правки данных / отладки)."""
    r = _redis()
    if r is None:
        return {"ok": False, "error": "redis unavailable"}
    try:
        # Redis не имеет wildcard DEL; scan-и всё что "analytics:v1:*"
        deleted = 0
        async for k in r.scan_iter(match="analytics:v1:*", count=200):
            await r.delete(k)
            deleted += 1
        return {"ok": True, "deleted": deleted}
    except Exception as e:
        return {"ok": False, "error": str(e)}
