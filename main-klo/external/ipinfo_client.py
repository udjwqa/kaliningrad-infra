"""
IPinfo v2 API client (2026-07-04 — Max API tier).

Endpoint: GET https://api.ipinfo.io/lookup/{ip}
Auth: Authorization: Bearer <token>

Backward compat: exposes .vpn/.proxy/.hosting/.tor/.relay attributes matching
the v1 IPInfoResult shape used by scoring_engine.py — только источник обновлён.
"""
import os
import re
import time
import logging
import httpx
from typing import Optional, Dict, Any

_ASN_RE = re.compile(r'AS(\d+)\b')

logger = logging.getLogger("ipinfo")

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
CACHE_TTL = int(os.getenv("IPINFO_CACHE_TTL_SECONDS", "86400"))
TIMEOUT = int(os.getenv("IPINFO_REQUEST_TIMEOUT_SECONDS", "5"))
FAIL_OPEN = os.getenv("IPINFO_FAIL_OPEN", "true").lower() == "true"


class IPInfoResult:
    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.ip = data.get("ip", "")

        geo = data.get("geo") or {}
        self.country = geo.get("country_code", "") or ""
        self.city = geo.get("city", "") or ""
        self.region = geo.get("region", "") or ""
        self.timezone = geo.get("timezone", "") or ""

        as_block = data.get("as") or {}
        asn_str = as_block.get("asn", "") or ""
        as_name = as_block.get("name", "") or ""
        self.org = f"{asn_str} {as_name}".strip() if asn_str else as_name
        self.asn_type = as_block.get("type", "") or ""

        anon = data.get("anonymous") or {}
        self.vpn = bool(anon.get("is_vpn", False))
        self.proxy = bool(anon.get("is_proxy", False))
        self.res_proxy = bool(anon.get("is_res_proxy", False))
        self.tor = bool(anon.get("is_tor", False))
        self.relay = bool(anon.get("is_relay", False))
        self.anonymous_name = anon.get("name", "") or ""
        self.anonymous_last_seen = anon.get("last_seen", "") or ""

        self.hosting = bool(data.get("is_hosting", False))
        self.is_mobile = bool(data.get("is_mobile", False))
        self.is_anycast = bool(data.get("is_anycast", False))
        self.is_satellite = bool(data.get("is_satellite", False))
        self.is_anonymous = bool(data.get("is_anonymous", False))

    @property
    def isp(self) -> str:
        org = self.org
        if org and " " in org:
            return org.split(" ", 1)[1]
        return org

    @property
    def asn(self) -> int:
        """Parses ASN integer from 'AS9009 ...' → 9009."""
        if not self.org:
            return 0
        m = _ASN_RE.match(self.org.strip())
        return int(m.group(1)) if m else 0


class IPInfoClient:
    def __init__(self):
        self._cache: Dict[str, tuple] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT)
        return self._client

    def _cache_get(self, ip: str) -> Optional[IPInfoResult]:
        entry = self._cache.get(ip)
        if entry is None:
            return None
        result, ts = entry
        if time.time() - ts > CACHE_TTL:
            del self._cache[ip]
            return None
        return result

    def _cache_set(self, ip: str, result: IPInfoResult):
        self._cache[ip] = (result, time.time())
        if len(self._cache) > 10000:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

    async def lookup(self, ip: str) -> Optional[IPInfoResult]:
        if not IPINFO_TOKEN:
            logger.debug("No IPINFO_TOKEN, skipping lookup")
            return None

        if ip in ("127.0.0.1", "0.0.0.0", "::1", "localhost"):
            return None

        cached = self._cache_get(ip)
        if cached:
            logger.debug(f"Cache hit for {ip}")
            return cached

        try:
            client = await self._get_client()
            resp = await client.get(
                f"https://api.ipinfo.io/lookup/{ip}",
                headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
            )
            resp.raise_for_status()
            data = resp.json()

            result = IPInfoResult(data)
            self._cache_set(ip, result)
            logger.info(
                f"IPinfo {ip}: country={result.country} city={result.city} "
                f"vpn={result.vpn} proxy={result.proxy} res_proxy={result.res_proxy} "
                f"tor={result.tor} relay={result.relay} hosting={result.hosting} "
                f"mobile={result.is_mobile} name={result.anonymous_name or '-'} "
                f"org={result.org}"
            )
            return result

        except Exception as e:
            logger.warning(f"IPinfo lookup failed for {ip}: {e}")
            if FAIL_OPEN:
                return None
            return IPInfoResult({"anonymous": {"is_vpn": True}, "is_hosting": True})

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


ipinfo_client = IPInfoClient()
