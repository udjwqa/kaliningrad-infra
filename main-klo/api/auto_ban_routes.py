"""Admin API для Smart Auto-Banlist (2026-06-23 P3).

Endpoints:
    GET  /api/bans/auto?page&pageSize&search&code&source&dateFrom&dateTo&activeOnly&expiredOnly
    GET  /api/bans/auto/stats
    POST /api/bans/auto                       — manual add
    DELETE /api/bans/auto/{entry_id}          — unban
    POST /api/bans/auto/{entry_id}/extend     — продлить TTL
    POST /api/bans/auto/bulk-unban            — bulk operation

Protected: prefix `/api/bans` уже в ADMIN_PREFIXES → требует X-Admin-Key.
"""

import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Request, Query
from fastapi.responses import JSONResponse

from auto_ban import auto_ban

logger = logging.getLogger("auto_ban_api")

router = APIRouter(prefix="/api/bans/auto", tags=["bans-auto"])


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


@router.get("")
async def list_bans(
    page: int = Query(1, ge=1),
    pageSize: int = Query(50, ge=1, le=200),
    search: str = "",
    code: str = "",
    source: str = "",
    dateFrom: Optional[str] = None,
    dateTo: Optional[str] = None,
    activeOnly: bool = False,
    expiredOnly: bool = False,
    shadowOnly: bool = False,
):
    """Server-side paginated list для UI."""
    result = await auto_ban.get_all_paginated(
        page=page, page_size=pageSize,
        search=search.strip(), code=code.strip(), source=source.strip(),
        date_from=_parse_iso(dateFrom), date_to=_parse_iso(dateTo),
        active_only=activeOnly, expired_only=expiredOnly, shadow_only=shadowOnly,
    )
    return result


@router.get("/stats")
async def stats():
    """Summary stats для dashboard cards."""
    return await auto_ban.get_stats()


@router.post("")
async def add_ban(request: Request):
    """Manual add ban (из UI dialog)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    ip = (body.get("ip") or "").strip()
    pkg = (body.get("packageName") or body.get("package_name") or "").strip() or None
    code = (body.get("code") or "manual").strip()
    reason = (body.get("reason") or "").strip()
    ttl_sec = body.get("ttlSec") or body.get("ttl_sec")  # None = permanent
    banned_by = (body.get("bannedBy") or body.get("banned_by") or "admin").strip()

    if not ip:
        return JSONResponse({"error": "ip required"}, status_code=400)

    ok = await auto_ban.manual_add(
        ip=ip, package_name=pkg, code=code, reason=reason,
        ttl_sec=int(ttl_sec) if ttl_sec else None,
        banned_by=banned_by,
    )
    if not ok:
        return JSONResponse({"error": "manual_add failed"}, status_code=500)
    return {"success": True, "ip": ip, "packageName": pkg, "code": code}


@router.delete("/{entry_id}")
async def unban(entry_id: str):
    """Удалить ban."""
    ok = await auto_ban.unban(entry_id)
    if not ok:
        return JSONResponse({"error": "not found or delete failed"}, status_code=404)
    return {"success": True, "id": entry_id}


@router.post("/{entry_id}/extend")
async def extend(entry_id: str, request: Request):
    """Продлить TTL ban."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    additional_sec = body.get("additionalSec") or body.get("additional_sec") or 86400
    ok = await auto_ban.extend(entry_id, int(additional_sec))
    if not ok:
        return JSONResponse({"error": "extend failed"}, status_code=404)
    return {"success": True, "id": entry_id, "additionalSec": int(additional_sec)}


@router.post("/bulk-unban")
async def bulk_unban(request: Request):
    """Bulk unban — массовое удаление."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return JSONResponse({"error": "ids required (list)"}, status_code=400)
    count = await auto_ban.bulk_unban(ids[:500])  # cap 500 for safety
    return {"success": True, "deleted": count}
