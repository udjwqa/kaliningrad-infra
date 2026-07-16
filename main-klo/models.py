from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Literal, List, Optional, Dict, Any
from datetime import datetime


class ScoringWeights(BaseModel):
    vpnProxyTor: int = 25
    suspiciousCity: int = 15
    englishWebView: int = 10
    suspiciousHosting: int = 20
    mouseWithoutTouch: int = 30
    timezoneMismatch: int = 15


class EngineConfig(BaseModel):
    scoreThreshold: int = 1
    ipqsFailOpen: bool = False
    minPlayIntegrity: Literal[
        "MEETS_BASIC_INTEGRITY",
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_STRONG_INTEGRITY",
    ] = "MEETS_DEVICE_INTEGRITY"
    batteryChargeTimeout: int = 1800
    accelerometerIdleTime: int = 300
    clickSpeedLimit: int = 10
    timezoneDriftHours: int = 2
    weights: ScoringWeights = ScoringWeights()


class BlockList(BaseModel):
    id: str
    name: str
    filename: str
    description: str
    items: List[str]


class BlockListUpdate(BaseModel):
    items: List[str]


class OfferConfig(BaseModel):
    safeUrl: str = "https://play.google.com/store/apps/details?id=com.example.safe"
    targetUrl: str = "https://api.example.com/offer/target"
    whiteFlowType: Literal[
        "show_403", "show_404", "redirect_safe", "fake_html"
    ] = "redirect_safe"


class AppEntry(BaseModel):
    id: str = ""
    name: str = ""
    package_name: str = ""
    cert_sha256: str = ""
    gcp_project_id: str = ""
    safe_url: str = ""
    target_url: str = ""
    white_flow_type: Literal[
        "show_403", "show_404", "redirect_safe", "fake_html"
    ] = "redirect_safe"
    panic_mode: bool = False
    excluded_countries: List[str] = []
    excluded_cities: List[str] = []
    allowed_countries: List[str] = []
    disable_lang_check: bool = False
    require_integrity: bool = False
    block_v2_gateway: bool = False
    soft_pi_countries: List[str] = []
    # NG-relax (2026-06-21): для стран в этом списке Soft-PI пропускает юзеров
    # с ЛЮБЫМ ASN (не требует mobile_asn_whitelist). Защита остаётся через
    # ipinfo vpn/proxy/hosting, IPQS, UA-эмулятор, Pixel, velocity, ASN ротацию.
    # Default [] — opt-in per app per country (например ['NG'] для Stake).
    soft_pi_countries_any_asn: List[str] = []
    block_google_asn: bool = True
    # VPN-blocklist (2026-06-21): hard-block commercial VPN/datacenter ASN
    # (M247, NordVPN, Surfshark, ExpressVPN, Vultr, OVH, Hetzner, и др).
    # Default True — это generic защита для protected apps. Только для
    # require_integrity=True срабатывает (см. init_routes._resolve).
    block_vpn_asn: bool = True
    # 2026-06-22: PI v3 advanced — блокировать combo deviceActivityLevel=UNEVALUATED
    # + playProtectVerdict=UNEVALUATED/NO_DATA на ПЕРВОМ /init этого instance_id.
    # Это signature свежего scanner/Robo Test Lab (real юзер активного телефона
    # никогда не имеет оба UNEVALUATED одновременно). Default True — защита включена.
    block_pi_unevaluated_combo: bool = True
    # 2026-06-22: IPQS hard-kill для protected apps (vpn/proxy/tor/bot/fraud_score≥85).
    # Fail-open если IPQS_API_KEY пустой или API down. Default True.
    block_ipqs: bool = True
    # P1-1 (2026-06-21): одноразовая выдача grey verdict для instance_id.
    # Защита от Google deep-review: первый запрос с нового instance_id видит grey,
    # 2-й+ за 24h с того же instance_id → safe (re-scan видит чистую пустышку).
    # Default False — opt-in per protected app (Snai/Stake/Sisal/etc).
    cloak_consumed_enabled: bool = False
    # 2026-07-10 P7: per-app kill switch для pi_nonce_replay check. Нужно для
    # прил с v3 SDK (Classic PI) которые кэшируют один integrity_token и переиспользуют.
    # Legit US юзер с SDK v3 присылает тот же nonce → мы ловим как replay attack → false positive.
    # Bot-pool credential stuffing защищён velocity_check.
    skip_nonce_replay: bool = False
    proxy_key: str = ""
    auth_token: str = ""
    # DAL-alignment (2026-07-09): URL мини-сервера прилы + path,
    # ЗАЯВЛЕННЫЙ в assetlinks.json на этом домене. Google Play scanner
    # проверяет DAL — если SDK бьёт на другой path, чем в DAL → палево → бан.
    # endpoint = https://<brand-domain> без слеша в конце.
    # sdk_path = /<path> — точно как в assetlinks.json (пример /betsson_live, /total_play).
    # Default "/init" сохраняет обратную совместимость (работает через nginx fallback).
    endpoint: str = ""
    sdk_path: str = "/init"
    created_at: str = ""


class AppEntryCreate(BaseModel):
    name: str
    package_name: str
    cert_sha256: str = ""
    gcp_project_id: str = ""
    safe_url: str = ""
    target_url: str = ""
    white_flow_type: str = "redirect_safe"
    excluded_countries: List[str] = []
    excluded_cities: List[str] = []
    allowed_countries: List[str] = []
    disable_lang_check: bool = False
    require_integrity: bool = False
    block_v2_gateway: bool = False
    soft_pi_countries: List[str] = []
    soft_pi_countries_any_asn: List[str] = []
    block_google_asn: bool = True
    block_vpn_asn: bool = True
    block_pi_unevaluated_combo: bool = True
    block_ipqs: bool = True
    cloak_consumed_enabled: bool = False
    # 2026-07-10 P7: per-app kill switch для pi_nonce_replay check. Нужно для
    # прил с v3 SDK (Classic PI) которые кэшируют один integrity_token и переиспользуют.
    # Legit US юзер с SDK v3 присылает тот же nonce → мы ловим как replay attack → false positive.
    # Bot-pool credential stuffing защищён velocity_check.
    skip_nonce_replay: bool = False
    proxy_key: str = ""
    auth_token: str = ""
    # DAL-alignment (2026-07-09): см. AppEntry.endpoint / sdk_path.
    endpoint: str = ""
    sdk_path: str = "/init"


class ScoringDetail(BaseModel):
    check: str
    points: int
    reason: str


class ScoringResult(BaseModel):
    score: int = 0
    verdict: Literal["grey", "white"] = "grey"
    rejectionCode: Optional[str] = None
    details: List[ScoringDetail] = []


class RequestLogEntry(BaseModel):
    id: str
    timestamp: str
    ip: str
    country: str = ""
    countryCode: str = ""
    deviceModel: str = ""
    os: str = ""
    score: int = 0
    verdict: Literal["grey", "white"] = "grey"
    rejectionCode: Optional[str] = None
    rawPayload: Dict[str, Any] = {}
