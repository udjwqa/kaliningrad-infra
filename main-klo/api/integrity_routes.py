import os
import secrets
import hashlib
import logging
import redis.asyncio as aioredis
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from external.play_integrity import play_integrity_client
from external.ipinfo_client import ipinfo_client
from config import config_store
from request_logger import request_logger
from models import ScoringResult, ScoringDetail

logger = logging.getLogger("integrity")

router = APIRouter()

AUTOBAN_SCORE = 100
NONCE_TTL = int(os.getenv("NONCE_TTL", "300"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
EXPECTED_CERT_SHA256 = os.getenv(
    "CERT_SHA256",
    "5QabPPipWBDaB1A2ZBvB+m318YgjjIEoAbZ4XToKJUs=",
)

_redis = None


async def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis


@router.get("/api/integrity/nonce")
@router.get("/api/security/token")
async def generate_nonce(request: Request):
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )

    raw = secrets.token_hex(32)
    nonce = hashlib.sha256(raw.encode()).hexdigest()

    try:
        r = await get_redis()
        await r.set(f"nonce:{nonce}", ip, ex=NONCE_TTL)
        logger.info(f"Nonce generated for {ip}: {nonce[:16]}... (TTL={NONCE_TTL}s)")
    except Exception as e:
        logger.error(f"Redis nonce write failed: {e}")

    return {"nonce": nonce, "ttl": NONCE_TTL}


class IntegrityRequest(BaseModel):
    # P1-3 (2026-06-21): max_length для защиты от DoS через giant JWE payload.
    # Реальный PI токен 1-2KB, 4096 безопасно. nonce sha256-hex = 64 chars, 128 запас.
    # extra='forbid' — отвергаем неизвестные поля (защита от schema injection).
    model_config = ConfigDict(extra='forbid')
    integrityToken: str = Field(max_length=4096)
    nonce: str = Field(default="", max_length=128)


@router.post("/api/integrity/verify")
@router.post("/api/security/validate")
async def verify_integrity(body: IntegrityRequest, request: Request):
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )

    # === NONCE VALIDATION ===
    if body.nonce:
        try:
            r = await get_redis()
            nonce_ip = await r.get(f"nonce:{body.nonce}")

            if nonce_ip is None:
                logger.warning(f"[{ip}] Nonce unknown or expired: {body.nonce[:16]}...")
                return JSONResponse({
                    "verified": False,
                    "error": "Invalid or expired nonce (possible replay attack)",
                    "score": AUTOBAN_SCORE,
                    "verdict": "white",
                    "rejectionCode": "integrity_invalid",
                }, status_code=403)

            if nonce_ip != ip:
                logger.warning(f"[{ip}] Nonce-IP mismatch: nonce issued to {nonce_ip}")
                await r.delete(f"nonce:{body.nonce}")
                return JSONResponse({
                    "verified": False,
                    "error": "Nonce-IP mismatch (possible token theft)",
                    "score": AUTOBAN_SCORE,
                    "verdict": "white",
                    "rejectionCode": "integrity_invalid",
                }, status_code=403)

            await r.delete(f"nonce:{body.nonce}")
            logger.info(f"[{ip}] Nonce consumed: {body.nonce[:16]}...")

        except Exception as e:
            logger.error(f"Redis nonce check failed: {e}")
            return JSONResponse({
                "verified": False,
                "error": "Nonce validation unavailable",
                "score": 0,
                "verdict": "grey",
            }, status_code=503)
    else:
        logger.warning(f"[{ip}] No nonce provided in integrity verify request")

    # === PLAY INTEGRITY ===
    if not play_integrity_client.available:
        return JSONResponse({
            "verified": False,
            "error": "Play Integrity not configured",
            "score": 0,
            "verdict": "grey",
        })

    package_name = request.headers.get("x-package-name", "") or request.headers.get("x-app-id", "")
    verdict = await play_integrity_client.verify_token(body.integrityToken, package_name)

    if not verdict:
        return JSONResponse({
            "verified": False,
            "error": "Verification failed",
            "score": AUTOBAN_SCORE,
            "verdict": "white",
            "rejectionCode": "integrity_invalid",
        })

    # === NONCE MATCH CHECK ===
    if body.nonce and verdict.nonce and verdict.nonce != body.nonce:
        logger.warning(
            f"[{ip}] Nonce mismatch: sent={body.nonce[:16]} token={verdict.nonce[:16]}"
        )
        return JSONResponse({
            "verified": False,
            "error": "Nonce mismatch (token tampered)",
            "score": AUTOBAN_SCORE,
            "verdict": "white",
            "rejectionCode": "integrity_invalid",
        }, status_code=403)

    # === PI TIMESTAMP FRESHNESS ===
    import time as _time
    try:
        _age_ms = int(_time.time() * 1000) - int(verdict.timestamp_millis)
        if _age_ms > 120_000:
            logger.warning(f"[{ip}] PI token stale: {_age_ms // 1000}s old")
            return JSONResponse({
                "verified": False,
                "error": "Token too old (possible replay)",
                "score": AUTOBAN_SCORE,
                "verdict": "white",
                "rejectionCode": "integrity_stale",
            }, status_code=403)
    except (ValueError, TypeError):
        pass

    # === SCORING ===
    cfg = config_store.engine
    details = []
    total = 0
    rejection_code = None

    if verdict.is_empty_device:
        # 2026-07-15 device_compromised DISABLED (client) — pts=0, no rejection
        total += 0
        # rejection_code = "device_compromised"  # DISABLED
        details.append(ScoringDetail(
            check="play_integrity_empty",
            points=0,
            reason="Device integrity: пустой вердикт (soft-log, no hard-kill)",
        ))

    if verdict.is_virtual_only:
        # 2026-07-15 device_compromised DISABLED (client)
        total += 0
        # rejection_code = rejection_code or "device_compromised"  # DISABLED
        details.append(ScoringDetail(
            check="play_integrity_virtual",
            points=0,
            reason=f"Device integrity: {verdict.device_recognition} — VIRTUAL only (soft-log)",
        ))

    if not verdict.meets_basic and not verdict.is_empty_device:
        # 2026-07-15 device_compromised DISABLED (client)
        total += 0
        # rejection_code = rejection_code or "device_compromised"  # DISABLED
        details.append(ScoringDetail(
            check="play_integrity_basic",
            points=0,
            reason=f"Device integrity: {verdict.device_recognition} — no BASIC (soft-log)",
        ))

    if not verdict.meets_device and verdict.meets_basic:
        pts = 50
        total += pts
        details.append(ScoringDetail(
            check="play_integrity_device",
            points=pts,
            reason=f"Device integrity: {verdict.device_recognition} — BASIC есть, DEVICE нет",
        ))

    # App recognition check
    if verdict.app_recognition == "UNEVALUATED":
        total += AUTOBAN_SCORE
        rejection_code = rejection_code or "app_tampered"
        details.append(ScoringDetail(
            check="play_integrity_app",
            points=AUTOBAN_SCORE,
            reason=f"App recognition: UNEVALUATED — проверка не выполнена",
        ))
    elif verdict.app_recognition == "UNRECOGNIZED_VERSION":
        pts = 30
        total += pts
        details.append(ScoringDetail(
            check="play_integrity_app_version",
            points=pts,
            reason=f"App recognition: UNRECOGNIZED_VERSION — sideload/тест",
        ))
    elif not verdict.is_recognized_app:
        total += AUTOBAN_SCORE
        rejection_code = rejection_code or "app_tampered"
        details.append(ScoringDetail(
            check="play_integrity_app",
            points=AUTOBAN_SCORE,
            reason=f"App recognition: {verdict.app_recognition} — приложение модифицировано",
        ))

    # Certificate SHA-256 mismatch — APK переподписан
    def normalize_b64(s: str) -> str:
        return s.replace("+", "-").replace("/", "_").rstrip("=")

    app = config_store.get_app(verdict.package_name)
    expected_cert = app.cert_sha256 if app and app.cert_sha256 else EXPECTED_CERT_SHA256
    if expected_cert and verdict.certificate_sha256:
        expected_norm = normalize_b64(expected_cert)
        got_norms = [normalize_b64(c) for c in verdict.certificate_sha256]
        if expected_norm not in got_norms:
            total += AUTOBAN_SCORE
            rejection_code = rejection_code or "cert_mismatch"
            details.append(ScoringDetail(
                check="play_integrity_cert",
                points=AUTOBAN_SCORE,
                reason=f"Certificate SHA-256 не совпадает — APK переподписан (got: {verdict.certificate_sha256})",
            ))

    if verdict.app_licensing == "UNLICENSED":
        total += 30
        details.append(ScoringDetail(
            check="play_integrity_license",
            points=30,
            reason=f"App licensing: {verdict.app_licensing}",
        ))

    threshold = cfg.scoreThreshold
    final_verdict = "white" if total >= threshold else "grey"
    if final_verdict == "grey":
        rejection_code = None

    result = ScoringResult(
        score=total,
        verdict=final_verdict,
        rejectionCode=rejection_code,
        details=details,
    )

    geo = await ipinfo_client.lookup(ip)
    geo_country = geo.country if geo else ""
    geo_city = geo.city if geo else ""

    await request_logger.log(
        ip=ip,
        result=result,
        country=geo_country,
        country_code=geo_country,
        city=geo_city,
        headers={
            "source": "play_integrity",
            "x-app-id": package_name,
            "app_recognition": verdict.app_recognition,
            "device_recognition": str(verdict.device_recognition),
            "app_licensing": verdict.app_licensing,
            "nonce_verified": "true",
        },
        js_metrics={"playIntegrity": verdict.raw},
    )

    return {
        "verified": True,
        "score": total,
        "verdict": final_verdict,
        "rejectionCode": rejection_code,
        "integrity": {
            "deviceRecognition": verdict.device_recognition,
            "appRecognition": verdict.app_recognition,
            "appLicensing": verdict.app_licensing,
            "meetsBasic": verdict.meets_basic,
            "meetsDevice": verdict.meets_device,
            "meetsStrong": verdict.meets_strong,
        },
        "details": [d.model_dump() for d in details],
    }


@router.get("/api/integrity/status")
async def integrity_status():
    return {
        "available": play_integrity_client.available,
        "packageName": play_integrity_client._available and "configured" or "not set",
    }


@router.post("/api/integrity/reload")
async def integrity_reload():
    """Hot-reload всех GCP-ключей без рестарта движка.
    Вызывать после загрузки нового gcp-key*.json через панель."""
    projects = play_integrity_client.reload()
    return {"loaded_projects": projects, "count": len(projects)}
