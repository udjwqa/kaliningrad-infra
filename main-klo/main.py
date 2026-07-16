from dotenv import load_dotenv
load_dotenv()

import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import config_store
from lists_manager import lists_manager
from api.health import router as health_router
from api.health_routes import router as health_ext_router
from api.config_routes import router as config_router
from api.lists_routes import router as lists_router
from api.gateway import router as gateway_router
from api.dashboard_routes import router as dashboard_router
from api.audit_routes import router as audit_router
from api.collect_routes import router as collect_router
from api.cf_sync import router as cf_sync_router
from api.sync_routes import router as sync_router
from database import init_db
from ip_ranges import ip_range_checker
from rate_limiter import rate_limiter
from honeypot_ban import honeypot_ban
from external.play_integrity import play_integrity_client
from pathlib import Path
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client
from auto_ban import auto_ban
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response, JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting server...")
    config_store.load()
    logger.info(f"Config loaded (scoreThreshold={config_store.engine.scoreThreshold})")
    await init_db()
    await lists_manager.load_all()
    await lists_manager.start_watcher(interval=5)
    ip_range_checker.load()
    await rate_limiter.connect()
    await honeypot_ban.connect()
    await auto_ban.connect()
    play_integrity_client.init()

    # P7: background DLQ drain — retry failed CF KV writes every 30s
    async def _dlq_drain_loop():
        while True:
            try:
                await asyncio.sleep(30)
                await auto_ban.drain_dlq(max_items=50)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"DLQ drain loop error: {e}")
    dlq_task = asyncio.create_task(_dlq_drain_loop())

    logger.info("Server ready")
    yield
    dlq_task.cancel()
    try:
        await dlq_task
    except asyncio.CancelledError:
        pass
    lists_manager.stop_watcher()
    await rate_limiter.close()
    await honeypot_ban.close()
    await auto_ban.close()
    await ipinfo_client.close()
    await ipqs_client.close()
    logger.info("Server stopped")


app = FastAPI(
    title="API Service",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://threeamigosteam.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # P1-3 (2026-06-21): убрали /api/collect и /api/integrity (целиком) из skip_paths —
        # они были DoS vector (900KB JSON × 1M req = 900GB/сутки в Postgres).
        # F2/F3 (2026-06-22 fix): убрали /init и /api/integrity/nonce из skip_paths —
        # они были unlimited (DoS Postgres/Redis через leaked proxy_key или массовый flood).
        # Теперь /init имеет per-proxy-key лимит (check_init), /api/integrity/nonce —
        # жёсткий per-IP (check_nonce). Базовый per-IP rate-limit (check) применяется ко всему остальному.
        skip_paths = ("/api/health", "/api/bans", "/api/config", "/api/lists",
                      "/api/offers", "/api/cf/", "/api/dashboard", "/api/audit",
                      "/api/form", "/api/integrity/status",
                      "/api/integrity/reload", "/api/security/token",
                      "/api/apps")
        if any(request.url.path.startswith(p) for p in skip_paths):
            return await call_next(request)

        # F2/F3 (2026-06-22): IP resolution с fallback цепью для rate-limit.
        # Раньше только cf-connecting-ip — direct origin hit (без CF) полностью bypass'ил
        # rate-limit. Теперь fallback на x-forwarded-for[0] и client.host. Для НЕ-CF трафика
        # (direct origin attack) IP всё равно есть через socket — rate-limit срабатывает.
        cf_ip = (request.headers.get("cf-connecting-ip", "") or "").strip()
        xff = (request.headers.get("x-forwarded-for", "") or "").split(",")[0].strip()
        client_ip = (request.client.host if request.client else "")
        ip = cf_ip or xff or client_ip

        if not ip:
            # Совсем нет IP (вряд ли возможно) — skip
            return await call_next(request)

        # honeypot_ban check работает только для CF-IP (как и раньше — XFF spoof
        # не должен банить произвольные IP)
        if cf_ip and await honeypot_ban.is_banned(cf_ip):
            safe_url = config_store.offers.safeUrl
            return RedirectResponse(url=safe_url, status_code=302)

        path = request.url.path

        # F3: жёсткий лимит на /api/integrity/nonce (10/мин/IP)
        if path.startswith("/api/integrity/nonce"):
            allowed, count = await rate_limiter.check_nonce(ip)
            if not allowed:
                logger.warning(f"Nonce rate limit: {ip} ({count} req/min)")
                return JSONResponse({"detail": "Too Many Requests"}, status_code=429)
            return await call_next(request)

        # F2: per-proxy-key лимит на /init (100/мин/key)
        if path == "/init" or path.startswith("/init?"):
            proxy_key = (request.headers.get("x-proxy-key", "") or
                         request.query_params.get("proxy_key", ""))
            allowed, count = await rate_limiter.check_init(proxy_key, ip)
            if not allowed:
                logger.warning(f"Init rate limit: key={proxy_key[:12]} ip={ip} ({count} req/min)")
                # Возвращаем 200 + safe URL (не палим что rate-limited)
                safe_url = config_store.offers.safeUrl
                return JSONResponse({"url": safe_url}, status_code=200)
            return await call_next(request)

        # Базовый per-IP лимит для всего остального
        allowed, count = await rate_limiter.check(ip)
        if not allowed:
            safe_url = config_store.offers.safeUrl
            logger.warning(f"Rate limit exceeded: {ip} ({count} req/min)")
            return RedirectResponse(url=safe_url, status_code=302)

        response = await call_next(request)
        return response

app.add_middleware(RateLimitMiddleware)


# === F1 (2026-06-22): Edge HMAC verification middleware ===
# Закрывает XFF/X-Real-IP/X-CF-* spoofing для direct origin hits.
# CF Worker подписывает (timestamp|ip|country|asn) через HMAC-SHA256(EDGE_SECRET) и
# инжектит как X-Edge-Signature + X-Edge-Timestamp. Gateway verify подпись и rejects
# спуфленные XFF (signature mismatch) или old replays (>5 min skew).
#
# Если EDGE_SECRET пустой — middleware **пропускает всё** (fail-open для phased rollout).
# После убедительного deploy CF Worker — поставить EDGE_SECRET в env (gateway), Worker
# secret будет тот же. Тогда middleware начнёт enforce'ить.
#
# Применяется к public endpoints где IP-spoofing критичен: /init, /web_content, /api/collect.
# Admin endpoints защищены X-Admin-Key и не нуждаются в этой проверке.
EDGE_SECRET = os.getenv("EDGE_SECRET", "")
EDGE_TIMESTAMP_SKEW = 300  # 5 минут окно
EDGE_PROTECTED_PATHS = ("/init", "/web_content", "/api/collect", "/api/integrity/verify")


class EdgeAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Fail-open если secret не настроен (phased rollout)
        if not EDGE_SECRET:
            return await call_next(request)

        path = request.url.path
        # Только защищаем критичные endpoints где IP-trust используется
        if not any(path.startswith(p) for p in EDGE_PROTECTED_PATHS):
            return await call_next(request)

        sig = (request.headers.get("x-edge-signature", "") or "").strip()
        ts = (request.headers.get("x-edge-timestamp", "") or "").strip()

        # Нет HMAC headers = запрос НЕ через CF Worker (direct origin bypass)
        if not sig or not ts:
            logger.warning(f"Edge-auth: missing HMAC for {path} from {request.client.host if request.client else '?'}")
            # НЕ блокируем сразу — возвращаем safe URL (не палим что cloak)
            safe_url = config_store.offers.safeUrl
            if path == "/init":
                return JSONResponse({"url": safe_url}, status_code=200)
            return RedirectResponse(url=safe_url, status_code=302)

        # Timestamp skew check (защита от старых HMAC replay)
        try:
            ts_int = int(ts)
            import time as _t
            now = int(_t.time())
            if abs(now - ts_int) > EDGE_TIMESTAMP_SKEW:
                logger.warning(f"Edge-auth: timestamp skew {now - ts_int}s for {path}")
                safe_url = config_store.offers.safeUrl
                if path == "/init":
                    return JSONResponse({"url": safe_url}, status_code=200)
                return RedirectResponse(url=safe_url, status_code=302)
        except (ValueError, TypeError):
            safe_url = config_store.offers.safeUrl
            if path == "/init":
                return JSONResponse({"url": safe_url}, status_code=200)
            return RedirectResponse(url=safe_url, status_code=302)

        # Verify HMAC
        import hmac as _hmac
        import hashlib as _hashlib
        xff = (request.headers.get("x-forwarded-for", "") or "").split(",")[0].strip()
        country = (request.headers.get("x-cf-country", "") or "").strip()
        asn = (request.headers.get("x-cf-asn", "") or "").strip()
        msg = f"{ts}|{xff}|{country}|{asn}"
        expected = _hmac.new(EDGE_SECRET.encode(), msg.encode(), _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            logger.warning(f"Edge-auth: HMAC mismatch for {path} (xff={xff} country={country} asn={asn})")
            safe_url = config_store.offers.safeUrl
            if path == "/init":
                return JSONResponse({"url": safe_url}, status_code=200)
            return RedirectResponse(url=safe_url, status_code=302)

        return await call_next(request)


app.add_middleware(EdgeAuthMiddleware)


# Админ-API закрыто секретным заголовком X-Admin-Key. Публичные пути (SDK/трекер/
# gateway) НЕ затрагиваются. Нет/неверный ключ на админ-пути → 404 (не палим, что путь есть).
ADMIN_KEY = os.getenv("ADMIN_KEY", "")
ADMIN_PREFIXES = (
    "/api/apps", "/api/config", "/api/offers", "/api/debug-allow",
    "/api/lists", "/api/dashboard", "/api/audit", "/api/cf",
    "/api/bans", "/api/honeypot", "/api/integrity/status", "/api/integrity/reload",
    "/api/health-ext", "/api/init-trace", "/api/reports", "/api/gh-doc",
    "/api/analytics",
)


class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if ADMIN_KEY:
            path = request.url.path
            if any(path.startswith(p) for p in ADMIN_PREFIXES):
                if request.headers.get("x-admin-key") != ADMIN_KEY:
                    return JSONResponse({"detail": "Not Found"}, status_code=404)
        return await call_next(request)


app.add_middleware(AdminAuthMiddleware)

app.include_router(health_router)
app.include_router(health_ext_router)
app.include_router(config_router)
app.include_router(lists_router)
app.include_router(dashboard_router)
app.include_router(audit_router)
app.include_router(collect_router)
app.include_router(cf_sync_router)
app.include_router(sync_router)

from api.integrity_routes import router as integrity_router
app.include_router(integrity_router)

from api.apps_routes import router as apps_router
app.include_router(apps_router)

from api.reports_routes import router as reports_router
app.include_router(reports_router)

from api.gh_doc_routes import router as gh_doc_router
app.include_router(gh_doc_router)

from api.analytics_routes import router as analytics_router
app.include_router(analytics_router)

from api.honeypot import router as honeypot_router
app.include_router(honeypot_router)

from api.auto_ban_routes import router as auto_ban_router
app.include_router(auto_ban_router)

from api.init_routes import router as init_router
app.include_router(init_router)

app.include_router(gateway_router)

from fastapi.responses import FileResponse

JS_SCRIPTS_DIR = Path(__file__).parent.parent / "js-scripts"

@app.get("/tracker.js")
@app.get("/analytics.js")
async def serve_tracker():
    obf = JS_SCRIPTS_DIR / "tracker.min.js"
    src = JS_SCRIPTS_DIR / "tracker.js"
    path = obf if obf.exists() else src
    return FileResponse(
        path,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=3600"},
    )
