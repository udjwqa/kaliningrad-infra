"""
Sync API для распределённых mini-КЛО серверов.

Endpoints:
  GET  /api/sync/config  — mini-КЛО скачивает конфиг (apps, bans, gcp keys)
  POST /api/sync/logs    — mini-КЛО пушит логи batch'ем

Auth: X-Sync-Secret header per mini_server_id (mini_server_secrets.json).

Created 2026-07-04 for Пункт 2 (мини-КЛО distributed scoring).
"""
import base64
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from auto_ban import auto_ban
from config import config_store
from request_logger import request_logger

logger = logging.getLogger("sync")

router = APIRouter(prefix="/api/sync", tags=["sync"])

CONFIG_DIR = Path(__file__).parent.parent / "config"
SECRETS_PATH = CONFIG_DIR / "mini_server_secrets.json"


def _load_secrets() -> dict:
    """Загружает {mini_server_id: shared_secret} из файла."""
    if not SECRETS_PATH.exists():
        return {}
    try:
        return json.load(open(SECRETS_PATH))
    except Exception as e:
        logger.error(f"Failed to load secrets: {e}")
        return {}


def _auth(secret_header: Optional[str]) -> str:
    """Валидирует X-Sync-Secret. Возвращает mini_server_id или 403."""
    if not secret_header:
        raise HTTPException(status_code=403, detail="Missing X-Sync-Secret")
    secrets = _load_secrets()
    for mini_id, expected in secrets.items():
        if expected == secret_header:
            return mini_id
    raise HTTPException(status_code=403, detail="Invalid X-Sync-Secret")


@router.get("/config")
async def sync_config(x_sync_secret: Optional[str] = Header(None)):
    """
    Скачивает конфиг для mini-КЛО.

    Возвращает:
      {
        "version": <timestamp>,
        "mini_server_id": "sisal-football",
        "apps": [<apps assigned к этому mini_server_id>],
        "bans": {
          "ip_bans": [{"ip": "1.2.3.4", "code": "instance_burnt", "expires_at": ...}],
        },
        "gcp_keys": {
          "sisal-debriefapp": "<base64(key.json)>",
        }
      }
    """
    mini_id = _auth(x_sync_secret)

    # 1. Filter apps: только те, где mini_server_id совпадает
    apps_all = json.load(open(CONFIG_DIR / "apps.json"))
    apps_filtered = [a for a in apps_all if a.get("mini_server_id") == mini_id]
    if not apps_filtered:
        logger.warning(f"No apps mapped to mini_server_id={mini_id}")

    # 2. Получить активные bans (autoban)
    ip_bans = []
    try:
        bans_result = await auto_ban.get_all_paginated(page=1, page_size=1000, active_only=True)
        for entry in bans_result.get("entries", []):
            ip_bans.append({
                "ip": entry.get("ip"),
                "code": entry.get("code"),
                "package_name": entry.get("package_name"),
                "expires_at": entry.get("expires_at"),
            })
    except Exception as e:
        logger.error(f"Failed to fetch bans: {e}")

    # 3. Собрать GCP keys для нужных проектов
    gcp_projects = set(a.get("gcp_project_id") for a in apps_filtered if a.get("gcp_project_id"))
    gcp_keys = {}
    for key_file in CONFIG_DIR.glob("gcp-key*.json"):
        try:
            key_data = json.load(open(key_file))
            proj = key_data.get("project_id", "")
            if proj in gcp_projects:
                # base64 encode whole file
                raw = key_file.read_bytes()
                gcp_keys[proj] = base64.b64encode(raw).decode("ascii")
        except Exception as e:
            logger.warning(f"Failed to encode {key_file.name}: {e}")

    # 4. google_asn_blocklist (advanced scoring, 2026-07-04)
    google_asn_list = sorted(config_store.google_asn_blocklist) if config_store.google_asn_blocklist else []

    version = int(time.time())
    logger.info(f"sync_config: mini_id={mini_id} apps={len(apps_filtered)} bans={len(ip_bans)} gcp_keys={len(gcp_keys)} google_asn={len(google_asn_list)}")

    return {
        "version": version,
        "mini_server_id": mini_id,
        "apps": apps_filtered,
        "bans": {"ip_bans": ip_bans},
        "gcp_keys": gcp_keys,
        "google_asn_blocklist": google_asn_list,
        # 2026-07-14: sync debug_allow (whitelist IP/instance) to mini-clo boxes
        "debug_allow": {
            "ips": list(config_store.debug_allow.get("ips", [])),
            "instances": list(config_store.debug_allow.get("instances", [])),
        },
    }


@router.post("/logs")
async def sync_logs(request: Request, x_sync_secret: Optional[str] = Header(None)):
    """
    Принимает batch логов от mini-КЛО.

    Body: {"logs": [<log entry>, ...]}
    Каждый log entry содержит поля request_logs table (ip, country, verdict, ...).
    """
    mini_id = _auth(x_sync_secret)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    logs = body.get("logs", [])
    if not isinstance(logs, list):
        raise HTTPException(status_code=400, detail="logs must be array")

    inserted = 0
    for entry in logs:
        try:
            # Reuse existing request_logger — оно уже пишет в request_logs table
            from models import ScoringResult, ScoringDetail

            details = []
            for d in entry.get("details", []):
                details.append(ScoringDetail(
                    check=d.get("check", ""),
                    points=int(d.get("points", 0)),
                    reason=d.get("reason", ""),
                ))
            result = ScoringResult(
                score=int(entry.get("score", 0)),
                verdict=entry.get("verdict", "white"),
                rejectionCode=entry.get("rejection_code"),
                details=details,
            )
            await request_logger.log(
                ip=entry.get("ip", ""),
                result=result,
                user_agent=entry.get("user_agent", ""),
                accept_language=entry.get("accept_language", ""),
                country=entry.get("country", ""),
                country_code=entry.get("country_code", ""),
                city=entry.get("city", ""),
                headers=entry.get("headers", {}),
                js_metrics=None,
                extra_payload=entry.get("extra_payload"),
            )
            inserted += 1
        except Exception as e:
            logger.error(f"Failed to insert log entry: {e}")

    logger.info(f"sync_logs: mini_id={mini_id} received={len(logs)} inserted={inserted}")
    return {"received": len(logs), "inserted": inserted}


@router.get("/health")
async def sync_health(x_sync_secret: Optional[str] = Header(None)):
    """Простой health-check для mini-КЛО."""
    mini_id = _auth(x_sync_secret)
    return {"ok": True, "mini_server_id": mini_id, "version": int(time.time())}
