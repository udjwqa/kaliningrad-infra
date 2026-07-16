"""Cloudflare KV sync helpers.

2026-06-23 (P7): расширено для banlist namespace.
- put_kv(key, value, ttl_sec=, namespace_id=) — TTL clamp 60s..10y per CF docs
- delete_kv(key, namespace_id=) — для unban hooks
- normalize_ip(ip) — RFC 5952 canonical форма (IPv6 compact, IPv4 dotted-quad). Исп. в обоих write/read.
"""

import os
import ipaddress
import logging
import httpx
from fastapi import APIRouter

logger = logging.getLogger("cf_sync")

router = APIRouter()

CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID", "")
CF_KV_NAMESPACE_ID = os.getenv("CF_KV_NAMESPACE_ID", "")
CF_KV_BANLIST_NAMESPACE_ID = os.getenv("CF_KV_BANLIST_NAMESPACE_ID", "")

CF_API_BASE = "https://api.cloudflare.com/client/v4"

# CF KV docs: min 60s, no upper bound. Use 10y for "permanent".
CF_KV_TTL_MIN = 60
CF_KV_TTL_MAX = 315_360_000  # ~10 years
CF_API_TIMEOUT = 5.0


def normalize_ip(ip: str) -> str:
    """Canonical RFC 5952 lowercase. Raises ValueError on invalid input.
    Fixes IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4) and expanded IPv6 (2001:db8:0:0:0:0:0:1 → 2001:db8::1).
    Strict mode catches injection (\\r\\n, SQL, oversize, leading zeros)."""
    if not ip or not isinstance(ip, str):
        raise ValueError("ip must be non-empty str")
    s = ip.strip()
    if len(s) > 64:  # max IPv6 string is 39 chars; 64 leaves margin for ::ffff: prefix
        raise ValueError(f"ip too long: {len(s)}")
    addr = ipaddress.ip_address(s)  # raises ValueError on invalid
    # IPv4-mapped IPv6 → unwrap to IPv4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return addr.compressed


def banlist_key(ip: str) -> str:
    """KV key shape для IP banlist. Namespaced для будущего расширения (ban:pkg:* etc)."""
    return f"ban:ip:{normalize_ip(ip)}"


async def put_kv(key, value, ttl_sec=None, namespace_id=None):
    """PUT в CF KV. ttl_sec=None → without expiration (forever). Returns bool ok.
    namespace_id=None → default CF_KV_NAMESPACE_ID (CONFIG). Pass CF_KV_BANLIST_NAMESPACE_ID для banlist."""
    ns = namespace_id or CF_KV_NAMESPACE_ID
    if not CF_API_TOKEN or not CF_ACCOUNT_ID or not ns:
        logger.warning("CF credentials/namespace not set, skipping KV put")
        return False

    url = f"{CF_API_BASE}/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{ns}/values/{key}"
    params = {}
    if ttl_sec is not None:
        clamped = max(CF_KV_TTL_MIN, min(int(ttl_sec), CF_KV_TTL_MAX))
        params["expiration_ttl"] = clamped

    try:
        async with httpx.AsyncClient(timeout=CF_API_TIMEOUT) as client:
            resp = await client.put(
                url,
                params=params,
                content=value,
                headers={
                    "Authorization": f"Bearer {CF_API_TOKEN}",
                    "Content-Type": "text/plain",
                },
            )
            if resp.status_code == 200:
                logger.debug(f"KV put: {key} (ns={ns[:8]}.., ttl={params.get('expiration_ttl')})")
                return True
            logger.error(f"KV put failed: {key} → {resp.status_code} {resp.text[:200]}")
            return False
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.error(f"KV put exception: {key} → {type(e).__name__}: {e}")
        return False


async def delete_kv(key, namespace_id=None):
    """DELETE из CF KV. Returns bool ok. 404 (already gone) treated as success."""
    ns = namespace_id or CF_KV_NAMESPACE_ID
    if not CF_API_TOKEN or not CF_ACCOUNT_ID or not ns:
        return False
    url = f"{CF_API_BASE}/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{ns}/values/{key}"
    try:
        async with httpx.AsyncClient(timeout=CF_API_TIMEOUT) as client:
            resp = await client.delete(
                url, headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
            )
            if resp.status_code in (200, 404):
                logger.debug(f"KV delete: {key} → {resp.status_code}")
                return True
            logger.error(f"KV delete failed: {key} → {resp.status_code} {resp.text[:200]}")
            return False
    except (httpx.TimeoutException, httpx.HTTPError) as e:
        logger.error(f"KV delete exception: {key} → {type(e).__name__}: {e}")
        return False


@router.put("/api/cf/sync")
async def sync_to_cloudflare():
    from config import config_store
    from lists_manager import lists_manager

    results = {}

    countries = lists_manager.get_list("countries_block")
    if countries:
        ok = await put_kv("BLOCKED_COUNTRIES", ",".join(countries.items))
        results["countries"] = ok

    ua = lists_manager.get_list("user_agents_block")
    if ua:
        ok = await put_kv("BLOCKED_UA", ",".join(ua.items))
        results["user_agents"] = ok

    blocked_asns = "15169,16591,396982,8075,714,16509,14618,13335,14061,24940,63949,16276,136907,32934,36459,20473"
    ok = await put_kv("BLOCKED_ASNS", blocked_asns)
    results["asns"] = ok

    ok = await put_kv("DESKTOP_UA", "Windows NT,Macintosh,X11,Linux x86_64,CrOS")
    results["desktop_ua"] = ok

    ok = await put_kv("CLIENT_SECRET", os.getenv("CF_CLIENT_SECRET", ""))
    results["client_secret"] = ok

    offers = config_store.offers
    ok = await put_kv("SAFE_URL", offers.safeUrl)
    results["safe_url"] = ok

    ok = await put_kv("WHITE_FLOW_TYPE", offers.whiteFlowType)
    results["white_flow_type"] = ok

    if not CF_API_TOKEN:
        return {
            "synced": False,
            "message": "CF_API_TOKEN not configured. Set in .env to enable sync.",
            "results": results,
        }

    return {"synced": True, "results": results}


@router.put("/api/cf/panic")
async def set_panic_mode(enabled: bool = True):
    ok = await put_kv("PANIC_MODE", "true" if enabled else "false")
    return {"success": ok, "panic_mode": enabled}
