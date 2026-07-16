"""
mini-КЛО — distributed scoring engine на mini-server.

Заменяет main КЛО в hot path. Скачивает config от main КЛО, делает PI decode
локально (google keys синхронизированы), возвращает scoring через тот же
protocol что main КЛО (/init).

Architecture:
    prила → CF → mini-server nginx → mini-кло FastAPI :8100 → response
                                                      │
                                                      ▼
                                    Play Integrity API / IPQS / IPinfo
                                    (сервер-к-серверу, легит traffic)

Никаких вызовов к api.threeamigosteam.com. Main КЛО остаётся ТОЛЬКО для
config sync + logs shipping (async, не в hot path).
"""
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Setup logging first
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("mini-clo")

# Ensure config dir exists
os.makedirs(os.path.join(os.path.dirname(__file__), "config"), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), "logs"), exist_ok=True)

# Local imports (после logging setup)
from init_routes import router as init_router
from log_shipper import log_shipper
from sync import initial_sync
from config import config_store
from external.play_integrity import play_integrity_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initial config sync + PI keys load + log_shipper. Shutdown: flush pending logs."""
    logger.info("=== mini-КЛО starting up ===")

    # 1. Initial config sync from main КЛО (blocks на первом запуске)
    try:
        await initial_sync()
    except Exception as e:
        logger.error(f"Initial sync failed (using cached config): {e}")

    # 2. Load config from local files
    config_store.reload()
    logger.info(f"Loaded {len(config_store.apps)} apps")

    # 3. Play Integrity keys
    play_integrity_client.init()
    logger.info(f"Play Integrity: {len(play_integrity_client._services)} keys loaded")

    # 4. Warm auto_ban list into Redis (advanced scoring, 2026-07-04)
    try:
        from redis_client import warm_autoban, get_redis
        import json
        from pathlib import Path
        r = await get_redis()
        if r is not None:
            bans_path = Path(__file__).parent / "config" / "bans.json"
            if bans_path.exists():
                bans = json.load(open(bans_path))
                # bans schema: {"ip_bans": [{"ip", "package_name", "reason"}, ...]}
                loaded = await warm_autoban(bans.get("ip_bans", []))
                logger.info(f"auto_ban warm: loaded {loaded} bans into Redis")
    except Exception as e:
        logger.warning(f"auto_ban warm failed (non-fatal): {e}")

    # 5. Start log_shipper background task
    shipper_task = asyncio.create_task(log_shipper.run())
    logger.info("Log shipper started")

    yield  # server ready

    logger.info("=== mini-КЛО shutting down ===")
    shipper_task.cancel()
    try:
        await log_shipper.flush_pending()
    except Exception as e:
        logger.warning(f"Flush pending failed: {e}")


app = FastAPI(
    title="mini-КЛО",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(init_router)


@app.get("/health")
async def health():
    """Simple health check."""
    return {
        "ok": True,
        "apps_count": len(config_store.apps),
        "pi_keys": len(play_integrity_client._services),
    }
