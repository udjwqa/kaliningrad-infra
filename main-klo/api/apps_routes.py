import time
import uuid
import re
import httpx
from urllib.parse import urlparse

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from config import config_store
from models import AppEntryCreate

router = APIRouter()

_DAL_HEALTH_TIMEOUT = 5.0
_DAL_RELATION = "delegate_permission/common.handle_all_urls"
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
_OKHTTP_UA = "okhttp/4.12.0"


def _norm_sha(s: str) -> str:
    return re.sub(r"[^A-Fa-f0-9]", "", (s or "")).upper()


def _endpoint_host(url: str) -> str:
    try:
        return urlparse(url.strip()).netloc
    except Exception:
        return ""


@router.get("/api/apps")
async def get_apps():
    result = []
    for a in config_store.apps:
        d = a.model_dump()
        if not d.get("proxy_key"):
            d["proxy_key"] = config_store.get_proxy_key_for_package(a.package_name)
        result.append(d)
    return result


@router.post("/api/apps")
async def create_app(body: AppEntryCreate):
    existing = config_store.get_app(body.package_name)
    if existing:
        return JSONResponse(
            {"error": f"App with package '{body.package_name}' already exists"},
            status_code=409,
        )
    app = config_store.add_app(
        name=body.name,
        package_name=body.package_name,
        cert_sha256=body.cert_sha256,
        gcp_project_id=body.gcp_project_id,
        safe_url=body.safe_url,
        target_url=body.target_url,
        white_flow_type=body.white_flow_type,
        excluded_countries=body.excluded_countries,
        excluded_cities=body.excluded_cities,
        allowed_countries=body.allowed_countries,
        disable_lang_check=body.disable_lang_check,
        require_integrity=body.require_integrity,
        block_v2_gateway=body.block_v2_gateway,
        # P1-9 (2026-06-21): раньше silently drops — новые apps создавались
        # с дефолтными soft_pi_countries=[] и block_google_asn=True.
        soft_pi_countries=body.soft_pi_countries,
        # NG-relax (2026-06-21): per-country exemption от mobile_asn_whitelist.
        soft_pi_countries_any_asn=body.soft_pi_countries_any_asn,
        block_google_asn=body.block_google_asn,
        # VPN-blocklist (2026-06-21): hard-block commercial VPN/datacenter ASN.
        block_vpn_asn=body.block_vpn_asn,
        # 2026-06-22: PI v3 + IPQS hard-kill toggles.
        block_pi_unevaluated_combo=body.block_pi_unevaluated_combo,
        block_ipqs=body.block_ipqs,
        # P1-1 (2026-06-21): cloak_consumed одноразовость, opt-in per app.
        cloak_consumed_enabled=body.cloak_consumed_enabled,
        proxy_key=body.proxy_key,
        auth_token=body.auth_token,
        # DAL-alignment (2026-07-09): SERVICE_URL + SERVICE_PATH из assetlinks.json.
        endpoint=body.endpoint,
        sdk_path=body.sdk_path,
    )
    return app.model_dump()


@router.put("/api/apps/{app_id}")
async def update_app(app_id: str, body: dict):
    app = config_store.update_app(app_id, body)
    if not app:
        return JSONResponse({"error": "App not found"}, status_code=404)
    return app.model_dump()


@router.delete("/api/apps/{app_id}")
async def delete_app(app_id: str):
    if config_store.delete_app(app_id):
        return {"success": True, "id": app_id}
    return JSONResponse({"error": "App not found"}, status_code=404)


@router.put("/api/apps/{app_id}/panic")
async def toggle_panic(app_id: str):
    app = config_store.get_app_by_id(app_id)
    if not app:
        return JSONResponse({"error": "App not found"}, status_code=404)
    config_store.update_app(app_id, {"panic_mode": not app.panic_mode})
    return {"success": True, "panic_mode": not app.panic_mode}


@router.post("/api/apps/{app_id}/health-check")
async def health_check(app_id: str):
    """SDK health check — POST на {endpoint}{sdk_path} с фейковыми headers,
    имитирующими реальный SDK-запрос. Проверяет что nginx на mini-server
    поднял location = {sdk_path} и он корректно проксирует в mini-КЛО.
    """
    app = config_store.get_app_by_id(app_id)
    if not app:
        return JSONResponse({"error": "App not found"}, status_code=404)

    endpoint = (app.endpoint or "").strip().rstrip("/")
    sdk_path = (app.sdk_path or "/init").strip()
    if not sdk_path.startswith("/"):
        sdk_path = "/" + sdk_path

    if not endpoint:
        return {
            "ok": False,
            "error": "endpoint not set for this app",
            "endpoint": "",
            "sdk_path": sdk_path,
        }

    url = f"{endpoint}{sdk_path}"
    headers = {
        "X-App-Id": app.package_name,
        "X-Instance-Id": str(uuid.uuid4()),
        "X-App-Version": "healthcheck-1.0",
        "X-Locale": "en",
        "X-Tz": "Europe/Rome",
        "X-Ts": str(int(time.time() * 1000)),
        "user-agent": _OKHTTP_UA,
        "content-type": "application/octet-stream",
    }
    if app.auth_token:
        headers["X-Sid"] = app.auth_token

    started = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=_DAL_HEALTH_TIMEOUT, follow_redirects=False) as c:
            r = await c.post(url, headers=headers, content=b"")
        latency_ms = int((time.monotonic() - started) * 1000)
        body = r.text[:500]
        content_type = r.headers.get("content-type", "")
        is_json = "application/json" in content_type.lower()
        has_url_field = False
        if is_json:
            try:
                import json as _json
                data = _json.loads(r.text)
                has_url_field = isinstance(data, dict) and isinstance(data.get("url"), str)
            except Exception:
                pass
        ok = (r.status_code == 200) and is_json and has_url_field
        return {
            "ok": ok,
            "url": url,
            "status_code": r.status_code,
            "latency_ms": latency_ms,
            "content_type": content_type,
            "is_json": is_json,
            "has_url_field": has_url_field,
            "response_snippet": body,
        }
    except httpx.TimeoutException:
        return {
            "ok": False,
            "url": url,
            "error": f"timeout after {_DAL_HEALTH_TIMEOUT}s",
            "latency_ms": int((time.monotonic() - started) * 1000),
        }
    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "error": f"{type(e).__name__}: {str(e)[:200]}",
            "latency_ms": int((time.monotonic() - started) * 1000),
        }


@router.post("/api/apps/{app_id}/dal-check")
async def dal_check(app_id: str):
    """Digital Asset Links check — тянет /.well-known/assetlinks.json c домена
    мини-сервера, находит запись для package_name прилы, сверяет sha256_cert
    с app.cert_sha256, отдельно GET-ит {sdk_path} браузерным UA (должен
    вернуть 200 HTML — лендинг). Это ровно то, что делает Google Play scanner.
    """
    app = config_store.get_app_by_id(app_id)
    if not app:
        return JSONResponse({"error": "App not found"}, status_code=404)

    endpoint = (app.endpoint or "").strip().rstrip("/")
    sdk_path = (app.sdk_path or "/init").strip()
    if not sdk_path.startswith("/"):
        sdk_path = "/" + sdk_path

    if not endpoint:
        return {
            "ok": False,
            "error": "endpoint not set for this app",
            "assetlinks_reachable": False,
            "package_registered": False,
            "sha_match": False,
            "path_accessible": False,
        }

    assetlinks_url = f"{endpoint}/.well-known/assetlinks.json"
    landing_url = f"{endpoint}{sdk_path}"

    result = {
        "ok": False,
        "assetlinks_url": assetlinks_url,
        "landing_url": landing_url,
        "assetlinks_reachable": False,
        "package_registered": False,
        "sha_match": False,
        "path_accessible": False,
        "path_html_size": 0,
        "path_content_type": "",
        "path_status_code": 0,
        "expected_sha256": _norm_sha(app.cert_sha256),
        "actual_sha256s": [],
        "errors": [],
    }

    try:
        async with httpx.AsyncClient(timeout=_DAL_HEALTH_TIMEOUT, follow_redirects=True) as c:
            try:
                r = await c.get(assetlinks_url, headers={"user-agent": _BROWSER_UA})
                if r.status_code == 200:
                    result["assetlinks_reachable"] = True
                    try:
                        import json as _json
                        entries = _json.loads(r.text)
                        if not isinstance(entries, list):
                            entries = [entries]
                        for e in entries:
                            target = (e or {}).get("target", {}) or {}
                            if target.get("package_name") == app.package_name:
                                result["package_registered"] = True
                                shas = target.get("sha256_cert_fingerprints") or []
                                normed = [_norm_sha(s) for s in shas]
                                result["actual_sha256s"] = normed
                                if result["expected_sha256"] and result["expected_sha256"] in normed:
                                    result["sha_match"] = True
                                break
                    except Exception as e:
                        result["errors"].append(f"assetlinks json parse: {type(e).__name__}: {str(e)[:120]}")
                else:
                    result["errors"].append(f"assetlinks HTTP {r.status_code}")
            except httpx.TimeoutException:
                result["errors"].append(f"assetlinks timeout {_DAL_HEALTH_TIMEOUT}s")
            except Exception as e:
                result["errors"].append(f"assetlinks fetch: {type(e).__name__}: {str(e)[:120]}")

            try:
                r2 = await c.get(landing_url, headers={"user-agent": _BROWSER_UA})
                result["path_status_code"] = r2.status_code
                ct = r2.headers.get("content-type", "")
                result["path_content_type"] = ct
                result["path_html_size"] = len(r2.text or "")
                if r2.status_code == 200 and "text/html" in ct.lower():
                    result["path_accessible"] = True
            except httpx.TimeoutException:
                result["errors"].append(f"landing timeout {_DAL_HEALTH_TIMEOUT}s")
            except Exception as e:
                result["errors"].append(f"landing fetch: {type(e).__name__}: {str(e)[:120]}")
    except Exception as e:
        result["errors"].append(f"outer: {type(e).__name__}: {str(e)[:200]}")

    result["ok"] = (
        result["assetlinks_reachable"]
        and result["package_registered"]
        and result["sha_match"]
        and result["path_accessible"]
    )
    return result
