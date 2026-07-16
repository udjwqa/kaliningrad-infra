import asyncio
import os
import logging
from typing import Optional, List
from pathlib import Path
from models import BlockList

logger = logging.getLogger("lists_manager")

BASE_DIR = Path(__file__).parent
LISTS_DIR = BASE_DIR / "lists"

LIST_DEFINITIONS = [
    {
        "id": "countries_block",
        "name": "Блокировка стран",
        "filename": "countries_block.txt",
        "description": "Коды стран, трафик из которых блокируется",
    },
    {
        "id": "cities_block",
        "name": "Блокировка городов модерации",
        "filename": "cities_block.txt",
        "description": "Города, связанные с модерацией Google/Apple",
    },
    {
        "id": "user_agents_block",
        "name": "Стоп-лист ботов",
        "filename": "user_agents_block.txt",
        "description": "Подстроки User-Agent для блокировки",
    },
    {
        "id": "device_models_block",
        "name": "Модели устройств (Pixel/Google)",
        "filename": "device_models_block.txt",
        "description": "Модели устройств, используемых для модерации",
    },
    {
        "id": "codenames_block",
        "name": "Кодовые имена эмуляторов",
        "filename": "codenames_block.txt",
        "description": "Кодовые имена устройств-эмуляторов и виртуальных машин",
    },
    {
        "id": "isp_block",
        "name": "Запрещённые провайдеры",
        "filename": "isp_block.txt",
        "description": "ISP/хостинг-провайдеры, связанные с ботами и краулерами",
    },
    {
        "id": "test_builds_block",
        "name": "Build-свойства тестовых устройств",
        "filename": "test_builds_block.txt",
        "description": "Build-свойства эмуляторов и тестовых устройств Google",
    },
    {
        "id": "gpu_block",
        "name": "Драйверы GPU эмуляторов",
        "filename": "gpu_block.txt",
        "description": "GPU-рендереры, характерные для эмуляторов и виртуальных машин",
    },
    {
        # F12 (2026-06-22): актуальный Tor exit list
        # Обновляется cron'ом /usr/local/bin/update_tor_list.sh каждые 6h
        # с https://check.torproject.org/torbulkexitlist
        "id": "tor_exits",
        "name": "Tor exit nodes (auto-update)",
        "filename": "tor_exits.txt",
        "description": "IPs из https://check.torproject.org/torbulkexitlist (cron 6h)",
    },
]


class ListsManager:
    def __init__(self):
        self._lists: dict = {}
        self._mtimes: dict = {}
        self._watcher_task: Optional[asyncio.Task] = None

    def _file_path(self, filename: str) -> Path:
        return LISTS_DIR / filename

    def _read_file(self, filepath: Path) -> List[str]:
        if not filepath.exists():
            return []
        text = filepath.read_text(encoding="utf-8").strip()
        if not text:
            return []
        return [line.strip() for line in text.splitlines() if line.strip()]

    def _write_file(self, filepath: Path, items: List[str]):
        filepath.write_text("\n".join(items) + "\n", encoding="utf-8")

    async def load_all(self):
        LISTS_DIR.mkdir(parents=True, exist_ok=True)
        for defn in LIST_DEFINITIONS:
            filepath = self._file_path(defn["filename"])
            items = self._read_file(filepath)
            self._lists[defn["id"]] = BlockList(
                id=defn["id"],
                name=defn["name"],
                filename=defn["filename"],
                description=defn["description"],
                items=items,
            )
            if filepath.exists():
                self._mtimes[defn["id"]] = os.path.getmtime(filepath)
            else:
                self._mtimes[defn["id"]] = 0
        logger.info(f"Loaded {len(self._lists)} block lists")

    async def check_updates(self):
        for defn in LIST_DEFINITIONS:
            filepath = self._file_path(defn["filename"])
            if not filepath.exists():
                continue
            current_mtime = os.path.getmtime(filepath)
            if current_mtime != self._mtimes.get(defn["id"], 0):
                items = self._read_file(filepath)
                self._lists[defn["id"]].items = items
                self._mtimes[defn["id"]] = current_mtime
                logger.info(
                    f"Hot-reloaded {defn['filename']} ({len(items)} items)"
                )

    async def start_watcher(self, interval: int = 5):
        async def _watch():
            while True:
                await asyncio.sleep(interval)
                try:
                    await self.check_updates()
                except Exception as e:
                    logger.error(f"Lists watcher error: {e}")

        self._watcher_task = asyncio.create_task(_watch())
        logger.info(f"Lists watcher started (interval={interval}s)")

    def stop_watcher(self):
        if self._watcher_task:
            self._watcher_task.cancel()

    def get_all(self) -> List[BlockList]:
        return list(self._lists.values())

    def get_list(self, list_id: str) -> Optional[BlockList]:
        return self._lists.get(list_id)

    def update_list(self, list_id: str, items: List[str]) -> bool:
        bl = self._lists.get(list_id)
        if not bl:
            return False
        bl.items = items
        filepath = self._file_path(bl.filename)
        self._write_file(filepath, items)
        self._mtimes[list_id] = os.path.getmtime(filepath)
        logger.info(f"Updated {bl.filename} ({len(items)} items)")
        return True

    def lookup(self, list_id: str, value: str) -> bool:
        bl = self._lists.get(list_id)
        if not bl:
            return False
        return value in bl.items


lists_manager = ListsManager()
