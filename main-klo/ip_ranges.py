import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger("ip_ranges")

LISTS_DIR = Path(__file__).parent / "lists"
RANGES_FILE = LISTS_DIR / "ip_ranges_block.txt"


class IPRangeChecker:
    def __init__(self):
        self._networks = []
        self._loaded = False

    def load(self):
        if not RANGES_FILE.exists():
            logger.warning(f"{RANGES_FILE} not found")
            return
        lines = RANGES_FILE.read_text(encoding="utf-8").strip().splitlines()
        self._networks = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                self._networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError as e:
                logger.warning(f"Invalid CIDR: {line} — {e}")
        self._loaded = True
        logger.info(f"Loaded {len(self._networks)} IP ranges from {RANGES_FILE.name}")

    def is_blocked(self, ip_str):
        if not self._loaded:
            self.load()
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for net in self._networks:
            if addr in net:
                return True
        return False


ip_range_checker = IPRangeChecker()
