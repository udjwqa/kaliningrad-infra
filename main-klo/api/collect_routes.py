import logging
import time
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from scoring_engine import scoring_engine
from request_logger import request_logger
from config import config_store
from external.ipinfo_client import ipinfo_client
from auto_ban import auto_ban

logger = logging.getLogger("collect")

router = APIRouter()

# P1-3 (2026-06-21): defense-in-depth body-size cap. nginx режет на 64k (главный barrier),
# но на случай direct gateway access (через VPN/админскую сеть) — second wall.
_MAX_COLLECT_BODY_BYTES = 65_536


async def _detect_cloak_bypass(ip: str, package_name: str, collect_country: str, iid: str):
    """2026-06-23 (cloak-bypass P2): detect multi-network attack pattern.
    /init проходит с IP_A (country PT), browser opens redirect URL с IP_B (country CN).
    Мы видим IP_B здесь (tracker callback). Если IP_B не был в /init recent → burn.

    Steps:
    1. Если есть iid + есть saved state для него — compare country: mismatch → burn instance + auto_ban tracker IP
    2. Если tracker IP_B не был в /init recent для этого pkg (10min window) — fallback /24 subnet check для legit network switch
    3. Если ни IP ни subnet не были в /init recent — bypass detected → auto_ban tracker IP

    Все ошибки fail-open.
    """
    try:
        r = await request_logger._get_redis()
        if not r or not package_name:
            return

        # Check 1: instance state comparison (требует iid из tracker, optional)
        if iid:
            state_key = f"iid_state:{package_name}:{iid}"
            state = await r.hgetall(state_key)
            if state:
                init_country = (state.get("country") or "").upper()
                if init_country and collect_country and init_country != collect_country:
                    # Burn instance + escalate tracker IP to auto-ban
                    from api.init_routes import _mark_instance_burnt
                    await _mark_instance_burnt(iid, package_name,
                        f"country_switch: /init={init_country} /collect={collect_country}")
                    await auto_ban.emit(
                        ip=ip, package_name=package_name, code="instance_burnt",
                        reason=f"cloak_bypass country_switch /init={init_country} /collect={collect_country} iid={iid[:8]}",
                        ttl_sec=86400,
                    )
                    logger.warning(
                        f"COLLECT cloak_bypass country_switch iid={iid[:8]} "
                        f"{init_country}→{collect_country} ip={ip} pkg={package_name}"
                    )
                    return

        # Check 2: IP correlation — tracker IP должен был в /init recent
        ip_recent = await r.get(f"init_ip_recent:{package_name}:{ip}")
        if ip_recent:
            return  # OK — same IP was в /init

        # Check 3: subnet fallback (real users могут switch wifi→mobile)
        from api.init_routes import _subnet_key
        subnet = _subnet_key(ip)
        subnet_recent = await r.get(f"init_subnet_recent:{package_name}:{subnet}")
        if subnet_recent:
            return  # OK — same /24 (or /64 IPv6) was в /init

        # Bypass detected — tracker IP не был в /init recent даже по subnet.
        # Это или multi-network attack или crawler/scanner hitting tracker direct.
        await auto_ban.emit(
            ip=ip, package_name=package_name, code="instance_burnt",
            reason=f"cloak_bypass ip_orphan: tracker IP {ip} (cc={collect_country}) not in /init recent for pkg",
            ttl_sec=86400,
        )
        logger.warning(
            f"COLLECT cloak_bypass ip_orphan ip={ip} cc={collect_country} pkg={package_name}"
        )
    except Exception as e:
        logger.warning(f"Cloak bypass detection failed: {e}")


@router.post("/api/collect")
@router.post("/api/analytics/event")
async def collect_metrics(request: Request):
    # P1-3: read body raw чтобы проверить размер ДО парсинга JSON.
    raw_body = await request.body()
    if len(raw_body) > _MAX_COLLECT_BODY_BYTES:
        logger.warning(f"[collect] body too large: {len(raw_body)} bytes (max={_MAX_COLLECT_BODY_BYTES})")
        return JSONResponse(status_code=413, content={"error": "Payload too large"})
    try:
        import json as _json
        data = _json.loads(raw_body) if raw_body else {}
        if not isinstance(data, dict):
            return JSONResponse(status_code=400, content={"error": "Expected JSON object"})
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )

    package_name = request.headers.get("x-package-name", "") or request.headers.get("x-app-id", "")
    js_result = await scoring_engine.score_js_metrics(data, ip, package_name)

    geo = await ipinfo_client.lookup(ip)
    geo_country = geo.country if geo else ""
    geo_city = geo.city if geo else ""

    # 2026-06-23 (cloak-bypass P2): detect multi-network attack — tracker IP/country
    # vs saved /init state. Burns instance + auto_ban tracker IP on mismatch.
    iid = request.headers.get("x-instance-id", "") or data.get("instance_id", "")
    if package_name:
        await _detect_cloak_bypass(ip, package_name, (geo_country or "").upper(), iid)

    await request_logger.log(
        ip=ip,
        result=js_result,
        user_agent=data.get("userAgent", ""),
        device_model=data.get("hardware", {}).get("platform", ""),
        os_version="",
        country=geo_country,
        country_code=geo_country,
        city=geo_city,
        headers={"source": "js-tracker"},
        js_metrics=data,
    )

    logger.info(f"[{ip}] JS metrics: score={js_result.score} verdict={js_result.verdict}")

    # Только подтверждение приёма. score/verdict/details НЕ отдаём — иначе модер
    # видит свой вердикт в DevTools. tracker.js ответ не читает (onloadend).
    return {"received": True}
