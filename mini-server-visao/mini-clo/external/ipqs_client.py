import os
import time
import logging
import httpx
from typing import Optional, Dict, Any

logger = logging.getLogger("ipqs")

IPQS_API_KEY = os.getenv("IPQS_API_KEY", "")
TIMEOUT = int(os.getenv("IPQS_REQUEST_TIMEOUT_SECONDS", "5"))


class IPQSResult:
    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.success = data.get("success", False)
        self.fraud_score = data.get("fraud_score", 0)
        self.vpn = data.get("vpn", False)
        self.proxy = data.get("proxy", False)
        self.tor = data.get("tor", False)
        self.bot_status = data.get("bot_status", False)
        self.is_crawler = data.get("is_crawler", False)
        self.isp = data.get("ISP", "")
        self.country_code = data.get("country_code", "")
        self.city = data.get("city", "")
        self.host = data.get("host", "")


class IPQSClient:
    def __init__(self):
        self._cache: Dict[str, tuple] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT)
        return self._client

    async def lookup(self, ip: str) -> Optional[IPQSResult]:
        if not IPQS_API_KEY:
            return None

        if ip in ("127.0.0.1", "0.0.0.0", "::1", "localhost"):
            return None

        cached = self._cache.get(ip)
        if cached:
            result, ts = cached
            if time.time() - ts < 3600:
                return result

        try:
            client = await self._get_client()
            resp = await client.get(
                f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}",
                params={
                    "strictness": 1,
                    "allow_public_access_points": "true",
                    "lighter_penalties": "false",
                },
            )
            resp.raise_for_status()
            data = resp.json()

            result = IPQSResult(data)
            self._cache[ip] = (result, time.time())

            if len(self._cache) > 10000:
                oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]

            logger.info(
                f"IPQS {ip}: fraud_score={result.fraud_score} "
                f"vpn={result.vpn} proxy={result.proxy} tor={result.tor} "
                f"bot={result.bot_status}"
            )
            return result

        except Exception as e:
            logger.warning(f"IPQS lookup failed for {ip}: {e}")
            return None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


ipqs_client = IPQSClient()
