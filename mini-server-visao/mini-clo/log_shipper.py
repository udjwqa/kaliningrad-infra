"""
Async log shipper — batch push логов к main КЛО (/api/sync/logs).

Использует asyncio.Queue как buffer. Batch flush каждые 30 сек или когда
queue > 100. При failure — append batch в logs/pending.jsonl, retry на
следующем flush.
"""
import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("log_shipper")

BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
PENDING_FILE = LOGS_DIR / "pending.jsonl"
SECRET_FILE = BASE_DIR / "config" / "mini_server_secret"
SYNC_URL_FILE = BASE_DIR / "config" / "sync_url"

FLUSH_INTERVAL_SEC = 30
FLUSH_QUEUE_THRESHOLD = 100
MAX_QUEUE_SIZE = 5000
HTTP_TIMEOUT_SEC = 10


class LogShipper:
    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        self._secret: Optional[str] = None
        self._sync_url: Optional[str] = None

    def _load_secret(self):
        if self._secret is None and SECRET_FILE.exists():
            self._secret = SECRET_FILE.read_text().strip()
        if self._sync_url is None and SYNC_URL_FILE.exists():
            self._sync_url = SYNC_URL_FILE.read_text().strip().rstrip("/")

    async def enqueue(self, entry: dict):
        """Non-blocking enqueue. Drops entry если queue full."""
        try:
            self._queue.put_nowait(entry)
        except asyncio.QueueFull:
            logger.warning("Log queue full, dropping entry")

    async def _read_pending(self) -> list:
        """Читает pending.jsonl, возвращает entries."""
        if not PENDING_FILE.exists():
            return []
        try:
            entries = []
            for line in PENDING_FILE.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
            return entries
        except Exception as e:
            logger.error(f"Failed to read pending: {e}")
            return []

    def _write_pending(self, entries: list):
        """Записывает entries в pending.jsonl (append)."""
        try:
            LOGS_DIR.mkdir(exist_ok=True)
            with open(PENDING_FILE, "a") as f:
                for e in entries:
                    f.write(json.dumps(e) + "\n")
        except Exception as e:
            logger.error(f"Failed to write pending: {e}")

    def _clear_pending(self):
        if PENDING_FILE.exists():
            try:
                PENDING_FILE.unlink()
            except Exception:
                pass

    async def _flush_batch(self, entries: list) -> bool:
        """Отправляет batch к main КЛО. Returns True на успех."""
        if not entries:
            return True
        self._load_secret()
        if not self._secret or not self._sync_url:
            logger.error("Cannot flush: secret or sync_url not configured")
            return False

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC) as client:
                r = await client.post(
                    f"{self._sync_url}/api/sync/logs",
                    headers={"X-Sync-Secret": self._secret},
                    json={"logs": entries},
                )
                if r.status_code == 200:
                    result = r.json()
                    logger.info(f"Flushed {result.get('inserted', 0)}/{len(entries)} logs")
                    return True
                logger.error(f"Flush failed: HTTP {r.status_code} {r.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Flush exception: {e}")
            return False

    async def run(self):
        """Main loop — batch flush каждые FLUSH_INTERVAL_SEC."""
        logger.info(f"log_shipper.run starting (interval={FLUSH_INTERVAL_SEC}s)")
        while True:
            await asyncio.sleep(FLUSH_INTERVAL_SEC)
            await self._flush_once()

    async def _flush_once(self):
        """Один цикл flush: pending + queue."""
        # Collect batch: pending + current queue
        batch = await self._read_pending()
        while not self._queue.empty() and len(batch) < 1000:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        if not batch:
            return

        success = await self._flush_batch(batch)
        if success:
            self._clear_pending()
        else:
            # Не смогли отправить — сохраняем pending
            self._clear_pending()
            self._write_pending(batch)

    async def flush_pending(self):
        """Called on shutdown — write current queue to pending file."""
        pending = []
        while not self._queue.empty():
            try:
                pending.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if pending:
            self._write_pending(pending)
            logger.info(f"Saved {len(pending)} pending logs on shutdown")


log_shipper = LogShipper()
