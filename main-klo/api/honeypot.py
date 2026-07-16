import logging
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from honeypot_ban import honeypot_ban
from honeypot_allowlist import is_allowlisted, is_bot_signal
from request_logger import request_logger
from external.ipinfo_client import ipinfo_client
from models import ScoringResult, ScoringDetail

logger = logging.getLogger("honeypot")

router = APIRouter()

# P1-7 (2026-06-21): убраны /api/v1, /api/v2 — collision с будущим SDK v3 (auto-ban
# legitimate apps при апгрейде). Если нужно — добавить /api/v0 и /admin-api/.
HONEYPOT_PATHS = {
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/.env", "/.env.local", "/.env.production",
    "/config.php", "/config.yml", "/config.json",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/phpmyadmin", "/pma", "/myadmin",
    "/xmlrpc.php", "/wp-content", "/wp-includes",
    "/login", "/signin", "/register",
    "/debug", "/debug/vars", "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd",
    "/backup", "/dump.sql", "/db.sql",
    "/cgi-bin", "/shell", "/cmd",
}

FAKE_ROBOTS = """User-agent: *
Disallow: /api/
Disallow: /admin/
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
"""

FAKE_SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
</urlset>"""

FAKE_WP_LOGIN = """<!DOCTYPE html>
<html><head><title>Log In</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found.</p></body>
</html>"""


def get_ip(request):
    """P1-7 (2026-06-21): читает ТОЛЬКО cf-connecting-ip.
    Раньше fallback на x-forwarded-for (spoofable) + request.client.host (sidecar IP)
    давал 2 amplifier:
    1. Insider: spoof XFF=<payment-gateway> + honeypot path → бан payment gateway на 365 дней
    2. Self-ban: пустой XFF → request.client.host = наш sidecar IP → бан собственного sidecar
    Если cf-connecting-ip отсутствует → skip ban (return '')."""
    return (request.headers.get("cf-connecting-ip", "") or "").strip()


async def trap(request, path):
    ip = get_ip(request)
    ua = request.headers.get("user-agent", "")

    # P1-7: skip ban если IP пустой (запрос не через CF — health probe и т.п.)
    if not ip:
        logger.info(f"honeypot: no cf-connecting-ip for {path}, skipping ban")
        return

    # P1-7: allowlist (наши VPS / Google crawlers / Stripe / UptimeRobot / CF self)
    allowed, reason = is_allowlisted(ip)
    if allowed:
        logger.info(f"honeypot: allowlisted {ip} ({reason}) for {path}, no ban")
        return

    # P1-7: bot_signal gate — если browser-like (полные accept headers, real UA)
    # отдаём silent 404 без ban (легитимный crawler/юзер случайно зашёл).
    if not is_bot_signal(request):
        logger.info(f"honeypot: {ip} no bot signal for {path}, 404 only, no ban")
        return

    await honeypot_ban.ban(ip, f"honeypot:{path}")

    result = ScoringResult(
        score=100,
        verdict="white",
        rejectionCode="honeypot",
        details=[ScoringDetail(
            check="honeypot_trap",
            points=100,
            reason=f"Honeypot: запрос на {path}",
        )],
    )

    geo = await ipinfo_client.lookup(ip)
    geo_country = geo.country if geo else ""
    geo_city = geo.city if geo else ""

    await request_logger.log(
        ip=ip,
        result=result,
        user_agent=ua,
        country=geo_country,
        country_code=geo_country,
        city=geo_city,
        headers={"source": "honeypot", "path": path},
    )

    logger.warning(f"HONEYPOT: {ip} → {path} (UA: {ua[:60]})")


@router.get("/robots.txt")
async def robots(request: Request):
    await trap(request, "/robots.txt")
    return PlainTextResponse(FAKE_ROBOTS, media_type="text/plain")


@router.get("/sitemap.xml")
@router.get("/sitemap_index.xml")
async def sitemap(request: Request):
    await trap(request, "/sitemap.xml")
    return PlainTextResponse(FAKE_SITEMAP, media_type="application/xml")


@router.get("/wp-admin")
@router.get("/wp-login.php")
@router.get("/wp-content/{path:path}")
@router.get("/wp-includes/{path:path}")
@router.get("/xmlrpc.php")
async def wp_trap(request: Request):
    await trap(request, request.url.path)
    return HTMLResponse(FAKE_WP_LOGIN, status_code=404)


@router.get("/admin")
@router.get("/administrator")
@router.get("/login")
@router.get("/signin")
@router.get("/register")
@router.get("/phpmyadmin")
@router.get("/pma")
@router.get("/myadmin")
async def admin_trap(request: Request):
    await trap(request, request.url.path)
    return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)


@router.get("/.env")
@router.get("/.env.local")
@router.get("/.env.production")
@router.get("/config.php")
@router.get("/config.yml")
@router.get("/.git/config")
@router.get("/.git/HEAD")
@router.get("/.gitignore")
@router.get("/.htaccess")
@router.get("/.htpasswd")
async def config_trap(request: Request):
    await trap(request, request.url.path)
    return PlainTextResponse("", status_code=403)


@router.get("/debug")
@router.get("/debug/vars")
@router.get("/server-status")
@router.get("/server-info")
@router.get("/cgi-bin/{path:path}")
@router.get("/shell")
@router.get("/cmd")
# P1-7 (2026-06-21): убраны /api/v1, /api/v2 — collision с будущим SDK v3 (auto-ban
# legitimate apps при апгрейде SDK на v3+). Если очень нужно — добавь /api/v0.
@router.get("/backup")
@router.get("/dump.sql")
@router.get("/db.sql")
async def generic_trap(request: Request):
    await trap(request, request.url.path)
    return JSONResponse({"error": "Not Found"}, status_code=404)


@router.post("/api/form")
async def form_honeyfield(request: Request):
    ip = get_ip(request)

    try:
        body = await request.body()
        from urllib.parse import parse_qs
        data = parse_qs(body.decode("utf-8", errors="ignore"))
    except Exception:
        data = {}

    security_confirm = data.get("security_confirm", [""])[0]
    email_verify = data.get("email_verify", [""])[0]
    hp_ts = data.get("__hp_ts", [""])[0]

    is_bot = False
    reasons = []

    if security_confirm:
        is_bot = True
        reasons.append(f"honeyfield 'security_confirm' filled: '{security_confirm[:30]}'")

    if email_verify:
        is_bot = True
        reasons.append(f"honeyfield 'email_verify' filled: '{email_verify[:30]}'")

    if not hp_ts:
        is_bot = True
        reasons.append("timestamp field empty (no JS execution)")

    if hp_ts:
        try:
            ts = int(hp_ts)
            import time
            now = int(time.time() * 1000)
            if now - ts < 500:
                is_bot = True
                reasons.append(f"form submitted in {now - ts}ms (too fast for human)")
        except ValueError:
            is_bot = True
            reasons.append("invalid timestamp value")

    if is_bot:
        reason_str = "; ".join(reasons)
        await honeypot_ban.ban(ip, f"honeyfield:{reason_str[:100]}")

        result = ScoringResult(
            score=100,
            verdict="white",
            rejectionCode="honeyfield_bot",
            details=[ScoringDetail(
                check="honeyfield",
                points=100,
                reason=f"Honeyfield: {reason_str}",
            )],
        )
        geo = await ipinfo_client.lookup(ip)
        geo_country = geo.country if geo else ""
        geo_city = geo.city if geo else ""

        await request_logger.log(
            ip=ip,
            result=result,
            user_agent=request.headers.get("user-agent", ""),
            country=geo_country,
            country_code=geo_country,
            city=geo_city,
            headers={"source": "honeyfield", "reasons": reason_str},
        )
        logger.warning(f"HONEYFIELD BOT: {ip} — {reason_str}")

    return HTMLResponse(
        "<h1>Thank you!</h1><p>Your submission has been received.</p>",
        status_code=200,
    )


@router.get("/api/bans/honeypot")
async def get_honeypot_bans():
    bans = await honeypot_ban.get_all_banned()
    return bans


@router.delete("/api/bans/honeypot/{ip}")
async def unban_honeypot(ip: str):
    await honeypot_ban.unban(ip)
    return {"success": True, "ip": ip, "unbanned": True}
