"""
Config sync — pull config from main КЛО.

Runs at startup (blocking initial download) and periodically via systemd timer.
Downloads: apps.json (filtered), gcp keys (base64), bans list.
"""
import asyncio
from config import config_store
import base64
import json
import logging
import os
import sys
import time
from pathlib import Path

import httpx

logger = logging.getLogger("sync")

BASE_DIR = Path(__file__).parent
CONFIG_DIR = BASE_DIR / "config"
SECRET_FILE = CONFIG_DIR / "mini_server_secret"
SYNC_URL_FILE = CONFIG_DIR / "sync_url"
SYNC_STATE_FILE = CONFIG_DIR / "sync_state.json"

HTTP_TIMEOUT_SEC = 20


def _read_secret() -> str:
    if not SECRET_FILE.exists():
        raise RuntimeError(f"Secret file not found: {SECRET_FILE}")
    return SECRET_FILE.read_text().strip()


def _read_sync_url() -> str:
    if not SYNC_URL_FILE.exists():
        raise RuntimeError(f"Sync URL file not found: {SYNC_URL_FILE}")
    return SYNC_URL_FILE.read_text().strip().rstrip("/")


def _read_local_version() -> int:
    if not SYNC_STATE_FILE.exists():
        return 0
    try:
        return int(json.load(open(SYNC_STATE_FILE)).get("version", 0))
    except Exception:
        return 0


def _write_state(version: int):
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(SYNC_STATE_FILE, "w") as f:
        json.dump({"version": version, "last_sync_ts": int(time.time())}, f)


async def sync_config() -> bool:
    """Скачивает config from main КЛО. Возвращает True на успех."""
    try:
        secret = _read_secret()
        sync_url = _read_sync_url()
    except Exception as e:
        logger.error(f"Config missing: {e}")
        return False

    logger.info(f"Syncing config from {sync_url}...")

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC) as client:
            r = await client.get(
                f"{sync_url}/api/sync/config",
                headers={"X-Sync-Secret": secret},
            )
            if r.status_code != 200:
                logger.error(f"Sync failed: HTTP {r.status_code} {r.text[:200]}")
                return False
            data = r.json()
    except Exception as e:
        logger.error(f"Sync exception: {e}")
        return False

    version = data.get("version", 0)
    local_version = _read_local_version()

    # Всегда записываем на первом запуске (local_version=0). Для subsequent
    # запусков — только если новее.
    if local_version > 0 and version <= local_version:
        logger.info(f"Config up-to-date (local={local_version} remote={version})")
        return True

    # Save apps.json
    apps = data.get("apps", [])
    with open(CONFIG_DIR / "apps.json", "w") as f:
        json.dump(apps, f, indent=2)

    # Save GCP keys
    gcp_keys = data.get("gcp_keys", {})
    for i, (proj_id, b64_key) in enumerate(gcp_keys.items()):
        try:
            key_data = base64.b64decode(b64_key).decode()
            key_path = CONFIG_DIR / f"gcp-key-{proj_id}.json"
            key_path.write_text(key_data)
            os.chmod(key_path, 0o600)
        except Exception as e:
            logger.warning(f"Failed to write GCP key {proj_id}: {e}")

    # Save bans (простой JSON file)
    bans = data.get("bans", {})
    with open(CONFIG_DIR / "bans.json", "w") as f:
        json.dump(bans, f, indent=2)

    # Save google_asn_blocklist (advanced scoring, 2026-07-04)
    google_asn = data.get("google_asn_blocklist", [])
    if google_asn:
        with open(CONFIG_DIR / "google_asn_blocklist.json", "w") as f:
            json.dump(google_asn, f)

    _write_state(version)
    # 2026-07-14: save debug_allow.json (whitelist IP/instance)
    debug_allow = data.get("debug_allow", {"ips": [], "instances": []})
    try:
        with open(CONFIG_DIR / "debug_allow.json", "w") as f:
            json.dump(debug_allow, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save debug_allow.json: {e}")
    logger.info(
        f"Sync done: version={version} apps={len(apps)} "
        f"gcp_keys={len(gcp_keys)} ip_bans={len(bans.get('ip_bans', []))} "
        f"google_asn={len(google_asn)}"
    )
    return True


async def initial_sync():
    """Blocking sync at startup — если config пуст, ждём success."""
    apps_path = CONFIG_DIR / "apps.json"
    if not apps_path.exists() or apps_path.stat().st_size < 10:
        # 2026-07-15: auto-reload config_store after sync — apps.json changes take effect immediately
        try:
            config_store.reload()
        except Exception as _e:
            logger.warning(f'config_store.reload() failed: {_e}')
        logger.info("No local config — waiting for initial sync...")
        for attempt in range(5):
            if await sync_config():
                return
            logger.warning(f"Initial sync attempt {attempt + 1}/5 failed")
            await asyncio.sleep(3)
        raise RuntimeError("Could not perform initial sync — check config/mini_server_secret + sync_url")
    else:
        # Best-effort refresh on startup
        await sync_config()


if __name__ == "__main__":
    # Standalone mode (called by systemd timer)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ok = asyncio.run(sync_config())
    sys.exit(0 if ok else 1)
