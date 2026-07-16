"""CF KV ↔ Postgres reconciliation (P7-B3).

Run nightly via cron. Diffs CF KV banlist namespace vs auto_banned_entries.
- Missing from KV (DB has, KV doesn't) → re-PUT (throttled)
- Orphans in KV (KV has, DB doesn't or expired) → DELETE
- Logs drift count for SLO monitoring

Usage:
    cd /opt/scoring-engine && /opt/scoring-engine/venv/bin/python tools/cf_kv_reconcile.py

Cron entry (3am daily):
    0 3 * * * cd /opt/scoring-engine && /opt/scoring-engine/venv/bin/python tools/cf_kv_reconcile.py >> /var/log/cf_kv_reconcile.log 2>&1
"""

import sys
import os
import asyncio
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

import httpx
from sqlalchemy import select, or_
from database import async_session
from db_models import AutoBannedEntry
from api.cf_sync import (
    put_kv, delete_kv, banlist_key, normalize_ip,
    CF_API_TOKEN, CF_ACCOUNT_ID, CF_API_BASE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("cf_kv_reconcile")

BANLIST_NS = os.getenv("CF_KV_BANLIST_NAMESPACE_ID", "")
THROTTLE_SLEEP_SEC = 0.1  # 600/min — safe ниже cap 1000


async def list_kv_keys(prefix: str = "ban:ip:") -> set:
    """List all keys в banlist namespace via CF API. Returns set of keys."""
    if not BANLIST_NS:
        return set()
    keys = set()
    cursor = None
    base_url = f"{CF_API_BASE}/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{BANLIST_NS}/keys"
    async with httpx.AsyncClient(timeout=15.0) as client:
        while True:
            params = {"prefix": prefix, "limit": 1000}
            if cursor:
                params["cursor"] = cursor
            resp = await client.get(
                base_url,
                params=params,
                headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
            )
            if resp.status_code != 200:
                logger.error(f"KV list failed: {resp.status_code} {resp.text[:200]}")
                break
            data = resp.json()
            for item in data.get("result", []):
                keys.add(item["name"])
            cursor = data.get("result_info", {}).get("cursor", "")
            if not cursor:
                break
    return keys


async def fetch_active_db_bans() -> dict:
    """Returns {banlist_key: (code, ttl_remaining_sec)} for all active enforce-mode bans."""
    out = {}
    now = datetime.utcnow()
    async with async_session() as session:
        stmt = select(AutoBannedEntry).where(
            AutoBannedEntry.would_ban == False,  # noqa: E712  -- enforce only
            or_(
                AutoBannedEntry.expires_at.is_(None),
                AutoBannedEntry.expires_at > now,
            ),
        )
        result = await session.execute(stmt)
        for entry in result.scalars().all():
            try:
                key = banlist_key(entry.ip)
            except ValueError:
                continue  # invalid IP skipped
            ttl = (
                315_360_000  # permanent → 10y
                if entry.expires_at is None
                else max(60, int((entry.expires_at - now).total_seconds()))
            )
            out[key] = (entry.code or "warm", ttl)
    return out


async def main():
    if not BANLIST_NS:
        print("ERROR: CF_KV_BANLIST_NAMESPACE_ID not set in .env — nothing to reconcile")
        sys.exit(1)
    if not CF_API_TOKEN or not CF_ACCOUNT_ID:
        print("ERROR: CF_API_TOKEN / CF_ACCOUNT_ID not configured")
        sys.exit(1)

    logger.info(f"Reconcile start: ns={BANLIST_NS[:8]}..")

    edge_keys = await list_kv_keys("ban:ip:")
    db_bans = await fetch_active_db_bans()

    missing_in_kv = set(db_bans.keys()) - edge_keys
    orphans_in_kv = edge_keys - set(db_bans.keys())

    logger.info(
        f"State: DB active={len(db_bans)} | KV={len(edge_keys)} | "
        f"drift: missing={len(missing_in_kv)} orphans={len(orphans_in_kv)}"
    )

    # Re-PUT missing
    put_ok, put_fail = 0, 0
    for key in sorted(missing_in_kv):
        code, ttl = db_bans[key]
        ok = await put_kv(key, code, ttl_sec=ttl, namespace_id=BANLIST_NS)
        if ok:
            put_ok += 1
        else:
            put_fail += 1
        await asyncio.sleep(THROTTLE_SLEEP_SEC)

    # Delete orphans
    del_ok, del_fail = 0, 0
    for key in sorted(orphans_in_kv):
        ok = await delete_kv(key, namespace_id=BANLIST_NS)
        if ok:
            del_ok += 1
        else:
            del_fail += 1
        await asyncio.sleep(THROTTLE_SLEEP_SEC)

    total_drift = len(missing_in_kv) + len(orphans_in_kv)
    logger.info(
        f"Reconcile done: PUT {put_ok}/{put_ok+put_fail}, DEL {del_ok}/{del_ok+del_fail}, "
        f"total_drift={total_drift}"
    )

    # SLO alert (printed to stdout — cron picks via email или log scrape)
    if total_drift > 100:
        print(f"WARNING: drift={total_drift} (>100). KV may be lagging — investigate DLQ + throttle.")


if __name__ == "__main__":
    asyncio.run(main())
