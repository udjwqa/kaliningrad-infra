import json
import logging
from pathlib import Path
from typing import Optional
from models import ScoringResult, ScoringDetail
from config import config_store
from lists_manager import lists_manager
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client
from ip_ranges import ip_range_checker

logger = logging.getLogger("scoring")

_GPU_MAP_FILE = Path(__file__).parent / "config" / "gpu_model_map.json"


def _load_gpu_model_map() -> dict:
    if not _GPU_MAP_FILE.exists():
        logger.warning("gpu_model_map.json not found — GPU-model check disabled")
        return {}
    try:
        raw = json.loads(_GPU_MAP_FILE.read_text(encoding="utf-8"))
        return {k: v for k, v in raw.items() if isinstance(v, list) and not k.startswith("_")}
    except Exception as e:
        logger.error(f"Failed to load gpu_model_map.json: {e}")
        return {}


_gpu_model_map = _load_gpu_model_map()

AUTOBAN_SCORE = 100

# 2026-07-05 (fix конверт): CGNAT-heavy countries где IPinfo Max массово
# classifies mobile carrier ASN как residential proxy (ProxyScrape/SOAX pools).
# Для этих стран res_proxy = SOFT signal (~15 pts) вместо hard-kill (100 pts).
# Duplicated из init_routes.py:30 — стоит переехать в shared constants модуль.
CGNAT_HEAVY_COUNTRIES = frozenset({
    # Africa (CGNAT + mobile-only ISP)
    "CI", "NG", "BD", "IN", "ZA", "PH", "ID", "PK", "VN", "NP",
    "SN", "GH",
    # EU tier-1 (T-Mobile/WIND/Orange/Vodafone CGNAT pools)
    "PL", "IT", "RO", "HU", "BG", "RS", "HR", "SI", "SK", "CZ",
    "LV", "LT", "EE",
    # LATAM (2026-07-05 добавлено — Movistar/Claro/Telefónica/Personal/Vivo/TIM CGNAT
    # массово classifies IPinfo как res_proxy; убивает Betsson/Stake/Betclic LATAM трафик)
    "AR", "CL", "MX", "PE", "BR", "CO", "UY", "EC", "VE", "PY", "BO", "DO",
    # 2026-07-07: Western Europe target geos (Betclic/gesr/LamDep/NV) where IPinfo Max
    # mass FP-flags Telekom DE / Orange FR / Movistar ES / MEO PT as res_proxy.
    "DE", "FR", "ES", "PT", "BE", "NL", "AT", "CH", "LU", "IE",
    "DK", "SE", "NO", "FI", "GR", "CY", "MT",
})

RES_PROXY_SOFT_POINTS = 15  # soft signal (не hard-kill) для CGNAT countries

# Маркеры устройств Google (Pixel/Nexus/Google dev/Chromebook). Отделяют
# Google-устройства от прочих в device_models_block (Honor/Galaxy/SM-S928 — не Google).
GOOGLE_DEVICE_MARKERS = ("pixel", "nexus", "google", "chromebook")

# 2026-06-21: Language-Country hard-kill mapping для /init flow.
# Если Accept-Language юзера НЕ совпадает со страной IP → hard-kill (AUTOBAN).
# Это ловит модера который сидит в US/RU + VPN на IT/PL/FR.
# Per-app можно отключить через `disable_lang_check=True` (для тестовых apps).
# Если язык НЕ в карте — НЕ блокируем (избегаем false positives на редких языках).

# English говорят во многих странах + дефолтный язык на Android в большинстве OEM →
# enable wide whitelist чтобы не резать default-en девайсы.
# 2026-06-23: расширено до EU/LATAM (FP fix — Portuguese user с en-system был blocked).
LANG_HARDKILL_ENGLISH_COUNTRIES = {
    # Native English
    "US", "GB", "AU", "CA", "NZ", "IE",
    # EU/EEA — все, потому что en часто default lang на Android OEMs в Европе
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IS", "IT", "LV", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO",
    "SK", "SI", "ES", "SE", "CH", "LI",
    # French overseas (где Betclic/Sisal/etc taргетируют)
    "MQ", "GP", "GF", "RE", "YT", "PF", "NC", "BL", "MF", "PM", "WF",
    # Africa English-speaking (NG/CI/SN trafic):
    "NG", "GH", "KE", "UG", "ZA", "ZM", "BW", "TZ", "ZW", "MW",
    "SL", "LR", "GM", "ET", "RW", "NA", "CI", "SN",
    # Asian English-speaking:
    "PH", "IN", "PK", "BD", "SG", "MY", "HK", "ID", "VN", "TH",
    # Caribbean / LATAM
    "JM", "TT", "BS", "BR", "AR", "MX", "CL", "PE", "CO", "VE", "EC", "UY",
    "PY", "BO", "GT", "HN", "SV", "NI", "CR", "PA", "DO", "CU", "PR",
    # Other big mobile audiences
    "TR", "RU", "UA", "BY", "MD", "AM", "AZ", "GE", "KZ", "UZ", "KG", "TJ",
    "IL", "AE", "SA", "EG", "MA", "DZ", "TN",
}

LANG_HARDKILL_MAP = {
    "ru": {"RU", "BY", "KZ", "KG", "UA", "UZ", "TJ", "MD", "AM", "AZ", "GE"},
    "tr": {"TR", "CY", "AZ"},
    "uk": {"UA"},
    "kk": {"KZ"},
    "uz": {"UZ"},
    "az": {"AZ"},
    "de": {"DE", "AT", "CH", "LI", "LU"},
    "fr": {"FR", "BE", "CH", "CA", "LU", "MC", "MQ", "GP", "RE", "GF",
           "CI", "SN", "ML", "CM", "CG", "CD", "MG", "HT", "TN", "DZ", "MA",
           "BF", "BJ", "TG", "NE", "GA", "GN", "MR"},
    "es": {"ES", "MX", "AR", "CO", "CL", "PE", "VE", "EC", "UY", "PY",
           "BO", "GT", "HN", "SV", "NI", "CR", "PA", "DO", "CU", "PR"},
    "pt": {"BR", "PT", "AO", "MZ", "CV", "GW", "ST", "TL"},
    "it": {"IT", "CH", "VA", "SM", "MT"},
    "pl": {"PL"},
    "nl": {"NL", "BE", "SR"},
    "sv": {"SE", "FI"},
    "no": {"NO"},
    "fi": {"FI"},
    "da": {"DK"},
    "is": {"IS"},
    "cs": {"CZ"},
    "sk": {"SK"},
    "hu": {"HU"},
    "ro": {"RO", "MD"},
    "bg": {"BG"},
    "hr": {"HR"},
    "sl": {"SI"},
    "sr": {"RS"},
    "el": {"GR", "CY"},
    "lt": {"LT"},
    "lv": {"LV"},
    "et": {"EE"},
    "sq": {"AL", "XK"},
    "mk": {"MK"},
    "bs": {"BA"},
    "ka": {"GE"},
    "hy": {"AM"},
    "ar": {"SA", "AE", "EG", "IQ", "JO", "KW", "QA", "BH", "OM", "LB",
           "SY", "YE", "LY", "TN", "DZ", "MA", "SD", "MR"},
    "he": {"IL"},
    "fa": {"IR", "AF", "TJ"},
    "ur": {"PK", "IN"},
    "hi": {"IN"},
    "vi": {"VN"},
    "th": {"TH"},
    "id": {"ID"},
    "ms": {"MY", "SG", "BN", "ID"},
    "ja": {"JP"},
    "ko": {"KR"},
    "zh": {"CN", "TW", "HK", "SG", "MO"},
}


def _check_lang_country_mismatch(accept_language: str, country: str) -> Optional[str]:
    """2026-06-21: Hard-kill если ни один язык юзера не совпадает со страной по IP.
    Парсит ВСЕ языки из Accept-Language (например 'en-US,it;q=0.9,fr;q=0.8') и
    проверяет каждый. Если хотя бы один совпадает → OK. Только если ВСЕ
    распознанные языки указывают на чужие страны → AUTOBAN.

    Это ловит модера с lang='ru-RU' на IT IP, но не режет легитимного
    IT юзера с системой на английском (lang='en-US,it;q=0.9' — это OK,
    потому что 'it' совпадает с country=IT).

    Возвращает None если OK, иначе reason string.
    Skip (None) если:
    - accept_language пустой (okhttp SDK)
    - country пустой
    - все языки НЕ в LANG_HARDKILL_MAP (редкие/неизвестные)
    """
    if not accept_language or not country:
        return None
    country_upper = country.upper()
    # Парсим все языки. Accept-Language: "ru-RU,en-US;q=0.9,fr;q=0.8"
    # → ['ru-RU', 'en-US;q=0.9', 'fr;q=0.8'] → ['ru', 'en', 'fr']
    lang_codes = []
    for part in accept_language.split(","):
        primary = part.strip().split(";")[0]
        code = primary.split("-")[0].lower().strip()
        if code and len(code) == 2 and code not in lang_codes:
            lang_codes.append(code)
    if not lang_codes:
        return None
    # Проверяем каждый язык — если хотя бы один совпадает → OK
    any_recognized = False
    failed_langs = []
    for code in lang_codes:
        expected = (LANG_HARDKILL_ENGLISH_COUNTRIES if code == "en"
                    else LANG_HARDKILL_MAP.get(code, set()))
        if not expected:
            continue  # язык не в карте — пропускаем (не подтверждение и не отказ)
        any_recognized = True
        if country_upper in expected:
            return None  # один из языков совпал → OK
        failed_langs.append(code)
    if not any_recognized:
        return None  # все языки редкие/неизвестные — не блокируем (false positive risk)
    return f"ни один из языков {failed_langs} не соответствует стране '{country_upper}'"

# Перманентный бан устройств (по запросу клиента): Galaxy S24 Ultra, OnePlus 8 Pro.
# Совпадение в device_model или User-Agent → мгновенный автобан (white).
HARDBAN_DEVICE_MARKERS = (
    "oneplus 8 pro", "oneplus8pro", "oneplus 8pro",
    "in2020", "in2021", "in2023", "in2025",
    "s24 ultra", "sm-s928", "galaxy s24 ultra",
)


class ScoringEngine:

    async def score_request(
        self,
        user_agent: str = "",
        accept_language: str = "",
        client_secret: Optional[str] = None,
        device_model: str = "",
        device_codename: str = "",
        gpu_renderer: str = "",
        build_product: str = "",
        country: str = "",
        city: str = "",
        isp: str = "",
        ip: str = "",
        asn: str = "",
        package_name: str = "",
        referer: str = "",
        instance_id: str = "",
        has_integrity: bool = False,
    ) -> ScoringResult:
        cfg = config_store.engine
        details = []
        total = 0
        rejection_code = None
        google_device = False
        device_pts = 0

        BLOCKED_ASNS = {
            "15169", "16591", "396982",
            "8075", "714",
            "16509", "14618",
            "13335",
            "14061", "24940", "63949", "16276",
            "136907", "32934", "36459", "20473",
        }

        if asn and asn in BLOCKED_ASNS:
            pts = AUTOBAN_SCORE
            total += pts
            rejection_code = rejection_code or "asn_blocked"
            details.append(ScoringDetail(
                check="asn_block", points=pts,
                reason=f"ASN {asn} в чёрном списке датацентров",
            ))

        # === БЛОК 1: Статические заголовки ===

        if not client_secret:
            pts = AUTOBAN_SCORE
            total += pts
            rejection_code = rejection_code or "no_client_secret"
            details.append(ScoringDetail(
                check="client_secret", points=pts,
                reason="Отсутствует X-Client-Secret заголовок",
            ))

        # === LANG-COUNTRY HARD-KILL (2026-06-21) ===
        # Модер с VPN на IT/PL/FR с языком устройства ru/de/zh → AUTOBAN.
        # Реальный юзер из IT обычно имеет Accept-Language: it-IT / it / en-US,it;q=0.9.
        # Per-app `disable_lang_check=True` отключает (для тестовых apps).
        # Skip если Accept-Language пустой (okhttp SDK calls) или язык не в карте.
        _app_for_lang = config_store.get_app(package_name) if package_name else None
        _skip_lang = _app_for_lang.disable_lang_check if _app_for_lang else False
        if not _skip_lang:
            _lang_mismatch = _check_lang_country_mismatch(accept_language, country)
            if _lang_mismatch:
                # 2026-07-05 (fix конверт): soft 20 pts вместо AUTOBAN.
                # 2 июля SDK v4 начал слать X-Locale header — активировал этот hard-kill
                # для всего SDK трафика. Легит multi-lingual юзеры (UA беженцы в PL,
                # DE туристы в IT, RU-speaking в LV/EE) с device locale != IP country
                # получали AUTOBAN. Soft: модер с VPN всё равно ловится по совокупности
                # (res_proxy_soft 15 + hosting + это 20 = 50+ через total_score threshold).
                pts = 20
                total += pts
                details.append(ScoringDetail(
                    check="lang_country_mismatch_soft", points=pts,
                    reason=f"Language-Country soft: {_lang_mismatch}",
                ))

        if user_agent:
            ua_lower = user_agent.lower()
            ua_list = lists_manager.get_list("user_agents_block")
            if ua_list:
                for bot in ua_list.items:
                    if bot.lower() in ua_lower:
                        pts = AUTOBAN_SCORE
                        total += pts
                        rejection_code = rejection_code or "bot_user_agent"
                        details.append(ScoringDetail(
                            check="user_agent_block", points=pts,
                            reason=f"User-Agent содержит '{bot}'",
                        ))
                        break

        # === Перманентный бан устройств: Galaxy S24 Ultra, OnePlus 8 Pro ===
        # Видно в браузерном UA / заголовке X-Device-Model (не в okhttp-резолве —
        # там их добивает require_integrity). Совпадение → мгновенный white.
        dev_str = f"{device_model} {user_agent}".lower()
        if any(m in dev_str for m in HARDBAN_DEVICE_MARKERS):
            total += AUTOBAN_SCORE
            rejection_code = rejection_code or "device_blocked"
            details.append(ScoringDetail(
                check="device_hardban", points=AUTOBAN_SCORE,
                reason="Перманентный бан устройства (Galaxy S24 Ultra / OnePlus 8 Pro)",
            ))

        # UA-based device detection (для SDK v3 где device_model не передаётся)
        if user_agent and not device_model:
            ua_lower = user_agent.lower()
            dm_list = lists_manager.get_list("device_models_block")
            if dm_list:
                for model in dm_list.items:
                    if model.lower() in ua_lower:
                        pts = 40
                        total += pts
                        device_pts = pts
                        google_device = any(m in model.lower() for m in GOOGLE_DEVICE_MARKERS)
                        rejection_code = rejection_code or "device_blocked"
                        details.append(ScoringDetail(
                            check="ua_device_block", points=pts,
                            reason=f"UA содержит модель '{model}'",
                        ))
                        break

        if device_model:
            dm_list = lists_manager.get_list("device_models_block")
            if dm_list:
                for model in dm_list.items:
                    if model.lower() in device_model.lower():
                        pts = 40
                        total += pts
                        device_pts = pts
                        google_device = any(m in model.lower() for m in GOOGLE_DEVICE_MARKERS)
                        rejection_code = rejection_code or "device_blocked"
                        details.append(ScoringDetail(
                            check="device_model_block", points=pts,
                            reason=f"Модель '{device_model}' совпала с '{model}'",
                        ))
                        break

        if device_codename:
            if lists_manager.lookup("codenames_block", device_codename):
                pts = AUTOBAN_SCORE
                total += pts
                rejection_code = rejection_code or "emulator_detected"
                details.append(ScoringDetail(
                    check="codename_block", points=pts,
                    reason=f"Кодовое имя '{device_codename}' — эмулятор",
                ))

        if gpu_renderer:
            gpu_list = lists_manager.get_list("gpu_block")
            if gpu_list:
                gpu_lower = gpu_renderer.lower()
                for gpu in gpu_list.items:
                    if gpu.lower() in gpu_lower:
                        pts = AUTOBAN_SCORE
                        total += pts
                        rejection_code = rejection_code or "emulator_gpu"
                        details.append(ScoringDetail(
                            check="gpu_block", points=pts,
                            reason=f"GPU '{gpu_renderer}' — эмулятор ({gpu})",
                        ))
                        break

        # === Несоответствие GPU ↔ модель = подмена фингерпринта ===
        # Карта ~100 семейств устройств → допустимые GPU (из JSON-файла, обновляется без правки кода).
        if (device_model or device_codename) and gpu_renderer:
            _devkey = f"{device_model} {device_codename}".lower()
            _gpulow = gpu_renderer.lower()
            for _fam, _allowed in _gpu_model_map.items():
                if _fam in _devkey and not any(a in _gpulow for a in _allowed):
                    total += AUTOBAN_SCORE
                    rejection_code = rejection_code or "device_spoof"
                    details.append(ScoringDetail(
                        check="device_gpu_mismatch", points=AUTOBAN_SCORE,
                        reason=f"GPU '{gpu_renderer}' невозможен для модели '{device_model}' — подмена фингерпринта",
                    ))
                    break

        # === Ротация GPU с одного IP = антидетект-ферма ===
        # Физическое устройство = один GPU навсегда. Если с одного IP по одной приле
        # для одной модели прилетает 2+ разных GPU за час — фингерпринт рандомизируется
        # (cloud-phone/antidetect). Ловит спуфер даже когда конкретный GPU правдоподобен.
        if ip and gpu_renderer and device_model and package_name:
            try:
                from request_logger import request_logger as _rl
                _r = await _rl._get_redis()
                _fpk = f"fp:{package_name}:{ip}:{device_model.lower()[:40]}"
                await _r.sadd(_fpk, gpu_renderer.lower()[:48])
                await _r.expire(_fpk, 3600)
                if await _r.scard(_fpk) >= 2:
                    total += AUTOBAN_SCORE
                    rejection_code = rejection_code or "device_spoof"
                    details.append(ScoringDetail(
                        check="gpu_rotation", points=AUTOBAN_SCORE,
                        reason=f"IP {ip}: модель '{device_model}' меняет GPU за час — антидетект/рандомизатор",
                    ))
            except Exception:
                pass

        if build_product:
            builds_list = lists_manager.get_list("test_builds_block")
            if builds_list:
                bp_lower = build_product.lower()
                for build in builds_list.items:
                    if build.lower() in bp_lower:
                        pts = AUTOBAN_SCORE
                        total += pts
                        rejection_code = rejection_code or "test_build_detected"
                        details.append(ScoringDetail(
                            check="test_build_block", points=pts,
                            reason=f"Build '{build_product}' — тестовое устройство ({build})",
                        ))
                        break

        # Referer — служебный трафик Google
        if referer:
            GOOGLE_REFERERS = [
                "google.com/", "accounts.google.com", "support.google.com",
                "play.google.com/console", "admin.google.com",
            ]
            ref_lower = referer.lower()
            for gr in GOOGLE_REFERERS:
                if gr in ref_lower:
                    pts = AUTOBAN_SCORE
                    total += pts
                    rejection_code = rejection_code or "google_referer"
                    details.append(ScoringDetail(
                        check="referer_block", points=pts,
                        reason=f"Referer '{referer[:60]}' — служебный трафик Google",
                    ))
                    break

        # IP в CIDR-диапазонах ботов/датацентров
        if ip and ip_range_checker.is_blocked(ip):
            pts = AUTOBAN_SCORE
            total += pts
            rejection_code = rejection_code or "ip_range_blocked"
            details.append(ScoringDetail(
                check="ip_range_block", points=pts,
                reason=f"IP '{ip}' в диапазоне ботов/датацентров",
            ))

        # F12 (2026-06-22): Tor exit list — независимый источник от IPQS.
        # Обновляется cron'ом раз в 6 часов с https://check.torproject.org/torbulkexitlist.
        # IPQS иногда пропускает свежие Tor exits — этот список покрывает gap.
        # AUTOBAN потому что Tor на Android = zero false positives.
        if ip and lists_manager.lookup("tor_exits", ip):
            pts = AUTOBAN_SCORE
            total += pts
            rejection_code = rejection_code or "tor_exit"
            details.append(ScoringDetail(
                check="tor_exit_list", points=pts,
                reason=f"IP '{ip}' в Tor exit list (check.torproject.org)",
            ))

        # === БЛОК 2: Внешние API (IPinfo + IPQS) ===

        effective_country = country
        effective_city = city
        effective_isp = isp

        ipinfo_data = await ipinfo_client.lookup(ip)
        if ipinfo_data:
            effective_country = ipinfo_data.country or effective_country
            effective_city = ipinfo_data.city or effective_city
            effective_isp = ipinfo_data.isp or effective_isp

            if ipinfo_data.vpn:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "vpn_detected"
                details.append(ScoringDetail(
                    check="ipinfo_vpn", points=pts,
                    reason=f"IPinfo: VPN обнаружен ({ip})",
                ))

            if ipinfo_data.proxy:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "proxy_detected"
                details.append(ScoringDetail(
                    check="ipinfo_proxy", points=pts,
                    reason=f"IPinfo: Proxy обнаружен ({ip})",
                ))

            if ipinfo_data.tor:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "tor_detected"
                details.append(ScoringDetail(
                    check="ipinfo_tor", points=pts,
                    reason=f"IPinfo: Tor обнаружен ({ip})",
                ))

            if ipinfo_data.hosting:
                pts = cfg.weights.suspiciousHosting
                total += pts
                rejection_code = rejection_code or "suspicious_hosting"
                details.append(ScoringDetail(
                    check="ipinfo_hosting", points=pts,
                    reason=f"IPinfo: Hosting IP ({ipinfo_data.org})",
                ))

            # 2026-07-04 (Max API): residential proxy detection.
            # BrightData/Oxylabs/IPRoyal — основной инструмент модеров.
            # 2026-07-05 (fix конверт): SOFT signal для CGNAT-heavy countries где
            # IPinfo Max массово FP-flag'ит T-Mobile PL / Play / Orange PL / etc как ProxyScrape.
            # Без этого fix'а грей% упал с 41% до 20% за 2 дня. Non-CGNAT countries
            # — оставляем hard-kill (реально ловит модеров с BrightData/Oxylabs пулами).
            if ipinfo_data.res_proxy:
                cc = (ipinfo_data.country or "").upper()
                # 2026-07-08: res_proxy = ВСЕГДА soft (+15), hard-kill убран. IPinfo Max
                # флагает 99.9% трафика (ложно метит мобильных операторов) — как hard-kill
                # бесполезен и режет живых в не-CGNAT целевых гео (MQ/GF/US/LB). Мусор из
                # не-целевых стран ловит гео-проверка; реальных ботов — PI/velocity.
                pts = RES_PROXY_SOFT_POINTS
                total += pts
                details.append(ScoringDetail(
                    check="ipinfo_res_proxy_soft", points=pts,
                    reason=f"IPinfo: Residential proxy soft ({ipinfo_data.anonymous_name or 'unknown'}) cc={cc}",
                ))

        # Язык vs страна — НЕ проверяем на gateway (мягкий признак)
        # Проверяется в score_js_metrics (этап 3 — датчики)

        # 2026-06-22 (FIX duplicate path): IPQS теперь tiered scoring,
        # не unconditional AUTOBAN. Hard-kill для vpn/tor/fraud>=90 происходит
        # выше в init_routes._resolve (TUNED). Здесь — взвешенный вклад в score.
        # scoreThreshold=70 гарантирует что один proxy=true или bot=true сигнал
        # НЕ флипает verdict (real CGNAT юзеры Fastweb/Bouygues/MTN/Airtel проходят).
        # Логика подтверждена workflow w93ve44ls (40 агентов pentest).
        ipqs_data = await ipqs_client.lookup(ip)
        if ipqs_data and ipqs_data.success:
            # VPN/Tor — hard-kill (zero FP на Android: никто не запускает exit на телефоне)
            if ipqs_data.vpn or ipqs_data.tor:
                flags = []
                if ipqs_data.vpn:
                    flags.append("VPN")
                if ipqs_data.tor:
                    flags.append("Tor")
                pts = cfg.weights.vpnProxyTor  # 100
                total += pts
                rejection_code = rejection_code or "vpn_detected"
                details.append(ScoringDetail(
                    check="ipqs_vpn_tor", points=pts,
                    reason=f"IPQS: {', '.join(flags)} обнаружен",
                ))

            # fraud_score: tiered (high band уже отработан hard-kill в init_routes)
            if ipqs_data.fraud_score >= 90:
                pts = 50
                total += pts
                # БЕЗ rejection_code (hard-kill уже в init_routes)
                details.append(ScoringDetail(
                    check="ipqs_fraud_high", points=pts,
                    reason=f"IPQS fraud_score={ipqs_data.fraud_score} (>=90)",
                ))
            elif ipqs_data.fraud_score >= 75:
                pts = 10  # soft signal — не флипает 70 threshold в одиночку
                total += pts
                details.append(ScoringDetail(
                    check="ipqs_fraud_mid", points=pts,
                    reason=f"IPQS fraud_score={ipqs_data.fraud_score} (75-89)",
                ))

            # Proxy — soft signal (CGNAT FP protection).
            # Real Fastweb/Bouygues/MTN/Airtel часто помечены proxy=true из-за
            # shared NAT (тысячи юзеров за одним IP). НЕ block в одиночку.
            # Skip если уже сработал vpn/tor (избегаем double-counting).
            if ipqs_data.proxy and not (ipqs_data.vpn or ipqs_data.tor):
                pts = 15
                total += pts
                # БЕЗ rejection_code (это soft signal, hard-kill не нужен)
                details.append(ScoringDetail(
                    check="ipqs_proxy_soft", points=pts,
                    reason="IPQS: proxy=true (soft signal, CGNAT pollution protection)",
                ))

            # bot_status — soft signal (CGNAT FP protection).
            # MTN/Airtel NG часто получают bot=true из-за abuse history на shared NAT.
            if ipqs_data.bot_status:
                pts = 25
                total += pts
                # БЕЗ rejection_code
                details.append(ScoringDetail(
                    check="ipqs_bot_soft", points=pts,
                    reason="IPQS: bot_status=true (soft signal, не AUTOBAN)",
                ))

        # === БЛОК 3: Гео-проверки ===

        app = config_store.get_app(package_name) if package_name else None
        excluded_countries = [c.upper() for c in (app.excluded_countries if app else [])]

        # === Гео-whitelist (allow-list стран) ===
        # Если у прилы задан allowed_countries — оффер ТОЛЬКО из этих стран. Любая другая
        # страна (или нераспознанная гео) → white. Режет модеров/ботов из чужих гео в ноль.
        allowed_countries = [c.upper() for c in (getattr(app, "allowed_countries", []) if app else [])]
        if allowed_countries:
            cc = (effective_country or "").upper()
            # cc пусто (гео не определилось) → НЕ режем по гео: пусть решают PI/остальной скоринг.
            # Иначе сбой ipinfo = весь трафик в white. Режем только при ИЗВЕСТНОЙ чужой стране.
            if cc and cc not in allowed_countries:
                total += AUTOBAN_SCORE
                rejection_code = rejection_code or "country_not_allowed"
                details.append(ScoringDetail(
                    check="country_not_allowed", points=AUTOBAN_SCORE,
                    reason=f"Страна '{effective_country}' не в whitelist прилы ({', '.join(allowed_countries)})",
                ))

        if effective_country:
            if effective_country.upper() not in excluded_countries:
                if lists_manager.lookup("countries_block", effective_country.upper()):
                    pts = AUTOBAN_SCORE
                    total += pts
                    rejection_code = rejection_code or "country_blocked"
                    details.append(ScoringDetail(
                        check="country_block", points=pts,
                        reason=f"Страна '{effective_country}' в чёрном списке",
                    ))

        excluded_cities = [c.lower() for c in (app.excluded_cities if app else [])]

        if effective_city:
            if effective_city.lower() not in excluded_cities:
                cities_list = lists_manager.get_list("cities_block")
                if cities_list:
                    for c in cities_list.items:
                        if c.lower() == effective_city.lower():
                            pts = cfg.weights.suspiciousCity
                            total += pts
                            details.append(ScoringDetail(
                                check="city_block", points=pts,
                                reason=f"Город '{effective_city}' — город модерации",
                            ))
                            break

        if effective_isp:
            isp_list = lists_manager.get_list("isp_block")
            if isp_list:
                isp_lower = effective_isp.lower()
                for provider in isp_list.items:
                    if provider.lower() in isp_lower:
                        pts = cfg.weights.suspiciousHosting
                        total += pts
                        rejection_code = rejection_code or "suspicious_hosting"
                        details.append(ScoringDetail(
                            check="isp_block", points=pts,
                            reason=f"ISP '{effective_isp}' — подозрительный ({provider})",
                        ))
                        break

        # === БЛОК 4: PI кеш — устройство скомпрометировано ===
        if ip and package_name:
            from request_logger import request_logger
            cached_pi = await request_logger._get_cached_pi(ip, package_name)
            if cached_pi:
                tp = cached_pi.get("tokenPayloadExternal", {})
                dev_verdict = tp.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
                if isinstance(dev_verdict, list) and len(dev_verdict) == 0:
                    # 2026-07-15 device_compromised DISABLED (client)
                    pts = 0
                    total += pts
                    # rejection_code = rejection_code or "device_compromised"  # DISABLED
                    details.append(ScoringDetail(
                        check="pi_cache_device_soft", points=pts,
                        reason="PI кеш: пустой deviceRecognitionVerdict (soft-log)",
                    ))

        # === Per-device velocity: fingerprint = model+gpu+build+package ===
        # Реальный юзер = 1-5 запросов/час. Модер-скрипт = 50+. Порог 30 — без ложняков.
        if device_model and package_name:
            try:
                from request_logger import request_logger as _rl2
                _r2 = await _rl2._get_redis()
                _dfp = f"dfv:{package_name}:{device_model}:{gpu_renderer}:{build_product}".lower()[:120]
                _dc = await _r2.incr(_dfp)
                if _dc == 1:
                    await _r2.expire(_dfp, 3600)
                if _dc > 30:
                    total += AUTOBAN_SCORE
                    rejection_code = rejection_code or "device_velocity"
                    details.append(ScoringDetail(
                        check="device_velocity", points=AUTOBAN_SCORE,
                        reason=f"Один device-fingerprint: {_dc} запросов/час — автоматизация",
                    ))
            except Exception:
                pass

        # === WebView/SDK UA check ===
        # Модер открывает URL в обычном Chrome (без прилы). У прилы UA либо WebView ('wv)'),
        # либо OkHttp (SDK). Chrome Custom Tabs — это полноценный Chrome без маркера 'wv)',
        # но запрос всё равно идёт из прилы — об этом сигналят x-instance-id и x-integrity-token.
        # Штрафуем только если UA = голый браузер И НЕТ SDK-маркеров (= модер/бот пришёл напрямую).
        if user_agent and client_secret:
            _ual = user_agent.lower()
            _is_webview = "wv)" in _ual
            _is_okhttp = "okhttp" in _ual
            _has_sdk_markers = bool(instance_id) or has_integrity
            if not _is_webview and not _is_okhttp and not _has_sdk_markers:
                pts = 40
                total += pts
                details.append(ScoringDetail(
                    check="not_webview", points=pts,
                    reason="UA без маркера WebView/OkHttp + нет SDK-сигналов — прямой браузерный заход",
                ))

        # Google-устройство (Pixel/Nexus) в одиночку = 40 (проходит), но в связке
        # с любым вторым признаком — автобан.
        if google_device and (total - device_pts) > 0:
            total = max(total, AUTOBAN_SCORE)
            rejection_code = rejection_code or "google_device_combo"
            details.append(ScoringDetail(
                check="google_device_combo", points=AUTOBAN_SCORE,
                reason="Google-устройство (Pixel/Nexus) + второй признак — автобан",
            ))

        # === Финальный вердикт ===
        threshold = cfg.scoreThreshold
        verdict = "white" if total >= threshold else "grey"

        if verdict == "grey":
            rejection_code = None

        logger.info(
            f"[{ip}] score={total} threshold={threshold} verdict={verdict} "
            f"rejection={rejection_code} checks={len(details)}"
        )

        return ScoringResult(
            score=total,
            verdict=verdict,
            rejectionCode=rejection_code,
            details=details,
        )


    async def score_js_metrics(self, data: dict, ip: str = "", package_name: str = "") -> ScoringResult:
        from external.timezone_utils import compare_timezones

        cfg = config_store.engine
        details = []
        hard_score = 0
        soft_score = 0
        rejection_code = None
        has_hard_ban = False

        MOTION_THRESHOLD = 0.08
        JS_SENSOR_THRESHOLD = 50

        app = config_store.get_app(package_name) if package_name else None

        # =============================================
        # ЖЁСТКИЕ ПРОВЕРКИ (один признак = мгновенный бан)
        # GPU эмулятора, страна, ISP, VPN/proxy
        # =============================================

        # IP в CIDR-диапазонах ботов/датацентров → instant ban
        if ip and ip_range_checker.is_blocked(ip):
            hard_score += AUTOBAN_SCORE
            has_hard_ban = True
            rejection_code = rejection_code or "ip_range_blocked"
            details.append(ScoringDetail(
                check="js_ip_range_block", points=AUTOBAN_SCORE,
                reason=f"IP '{ip}' в диапазоне ботов/датацентров",
            ))

        # GPU эмулятора в стоп-листе → instant ban
        webgl = data.get("webgl", {})
        renderer = webgl.get("renderer", "")
        vendor = webgl.get("vendor", "")
        webgl_combined = f"{vendor} {renderer}".lower()
        if webgl_combined.strip():
            gpu_list = lists_manager.get_list("gpu_block")
            if gpu_list:
                for gpu in gpu_list.items:
                    if gpu.lower() in webgl_combined:
                        hard_score += AUTOBAN_SCORE
                        has_hard_ban = True
                        rejection_code = rejection_code or "emulator_gpu"
                        details.append(ScoringDetail(
                            check="js_webgl_gpu", points=AUTOBAN_SCORE,
                            reason=f"WebGL '{renderer}' (vendor: {vendor}) — эмулятор ({gpu})",
                        ))
                        break

        # IPinfo гео-проверки → instant ban
        ipinfo_data = await ipinfo_client.lookup(ip)

        if ipinfo_data:
            if ipinfo_data.country:
                if lists_manager.lookup("countries_block", ipinfo_data.country.upper()):
                    hard_score += AUTOBAN_SCORE
                    has_hard_ban = True
                    rejection_code = rejection_code or "country_blocked"
                    details.append(ScoringDetail(
                        check="js_country_block", points=AUTOBAN_SCORE,
                        reason=f"Страна '{ipinfo_data.country}' в чёрном списке (IPinfo)",
                    ))

            js_excluded_cities = [c.lower() for c in (app.excluded_cities if app else [])]
            if ipinfo_data.city and ipinfo_data.city.lower() not in js_excluded_cities:
                cities_list = lists_manager.get_list("cities_block")
                if cities_list:
                    for c in cities_list.items:
                        if c.lower() == ipinfo_data.city.lower():
                            hard_score += AUTOBAN_SCORE
                            has_hard_ban = True
                            rejection_code = rejection_code or "city_blocked"
                            details.append(ScoringDetail(
                                check="js_city_block", points=AUTOBAN_SCORE,
                                reason=f"Город '{ipinfo_data.city}' — город модерации (IPinfo)",
                            ))
                            break

            if ipinfo_data.isp:
                isp_list = lists_manager.get_list("isp_block")
                if isp_list:
                    isp_lower = ipinfo_data.isp.lower()
                    for provider in isp_list.items:
                        if provider.lower() in isp_lower:
                            hard_score += AUTOBAN_SCORE
                            has_hard_ban = True
                            rejection_code = rejection_code or "suspicious_hosting"
                            details.append(ScoringDetail(
                                check="js_isp_block", points=AUTOBAN_SCORE,
                                reason=f"ISP '{ipinfo_data.isp}' — подозрительный (IPinfo)",
                            ))
                            break

            if ipinfo_data.vpn:
                hard_score += AUTOBAN_SCORE
                has_hard_ban = True
                rejection_code = rejection_code or "vpn_detected"
                details.append(ScoringDetail(
                    check="js_ipinfo_vpn", points=AUTOBAN_SCORE,
                    reason=f"IPinfo: VPN обнаружен ({ip})",
                ))
            if ipinfo_data.proxy:
                hard_score += AUTOBAN_SCORE
                has_hard_ban = True
                rejection_code = rejection_code or "proxy_detected"
                details.append(ScoringDetail(
                    check="js_ipinfo_proxy", points=AUTOBAN_SCORE,
                    reason=f"IPinfo: Proxy обнаружен ({ip})",
                ))
            if ipinfo_data.hosting:
                hard_score += AUTOBAN_SCORE
                has_hard_ban = True
                rejection_code = rejection_code or "suspicious_hosting"
                details.append(ScoringDetail(
                    check="js_ipinfo_hosting", points=AUTOBAN_SCORE,
                    reason=f"IPinfo: Hosting IP ({ipinfo_data.org})",
                ))
            if ipinfo_data.res_proxy:
                # 2026-07-05 (fix конверт): CGNAT countries → soft signal, else hard-kill.
                cc = (ipinfo_data.country or "").upper()
                # 2026-07-08: res_proxy = ВСЕГДА soft (hard-kill убран, см. init-path выше).
                details.append(ScoringDetail(
                    check="js_ipinfo_res_proxy_soft", points=RES_PROXY_SOFT_POINTS,
                    reason=f"IPinfo: Residential proxy soft ({ipinfo_data.anonymous_name or 'unknown'}) cc={cc}",
                ))

        # =============================================
        # МЯГКИЕ ПРОВЕРКИ — ДАТЧИКИ (накопление баллов)
        # Банят только если совокупность >= JS_SENSOR_THRESHOLD
        # Это решающий финальный этап
        # =============================================

        input_data = data.get("input", {})

        # Акселерометр
        accel = data.get("accelerometer", {})
        avg_deviation = accel.get("averageDeviation", -1)
        samples = accel.get("samples", 0)
        if samples > 0 and 0 <= avg_deviation < MOTION_THRESHOLD:
            pts = cfg.weights.mouseWithoutTouch
            soft_score += pts
            details.append(ScoringDetail(
                check="js_static_device", points=pts,
                reason=f"Акселерометр: deviation={avg_deviation} m/s² < {MOTION_THRESHOLD} "
                       f"({samples} samples) — статичное устройство",
            ))

        # Мышь без тача
        mouse = input_data.get("mouseClicks", 0)
        touch_events = input_data.get("touchEvents", 0)
        if mouse > 0 and touch_events == 0:
            pts = cfg.weights.mouseWithoutTouch
            soft_score += pts
            details.append(ScoringDetail(
                check="js_mouse_no_touch", points=pts,
                reason=f"Клики мышью ({mouse}) без тач-событий",
            ))

        # Фейковая батарея
        battery = data.get("battery", {})
        level = battery.get("level")
        charging_time = battery.get("chargingTime")
        if level is not None and level == 1.0 and charging_time == 0:
            soft_score += 50
            details.append(ScoringDetail(
                check="js_fake_battery", points=50,
                reason="Батарея: level=100%, chargingTime=0 — паттерн эмулятора",
            ))

        # Таймзона
        js_tz = data.get("timezone", "")
        if js_tz:
            ip_tz = ipinfo_data.timezone if ipinfo_data else ""
            if ip_tz:
                tz_diff = compare_timezones(js_tz, ip_tz)
                tolerance = cfg.timezoneDriftHours
                if tz_diff > tolerance:
                    pts = cfg.weights.timezoneMismatch
                    soft_score += pts
                    details.append(ScoringDetail(
                        check="js_timezone_mismatch", points=pts,
                        reason=f"Таймзона JS={js_tz} vs IP={ip_tz}, "
                               f"разница {tz_diff:.1f}ч > допуск {tolerance}ч",
                    ))
            else:
                known_suspicious = ["Etc/UTC", "UTC", "Etc/GMT"]
                if js_tz in known_suspicious:
                    pts = cfg.weights.timezoneMismatch
                    soft_score += pts
                    details.append(ScoringDetail(
                        check="js_timezone_suspicious", points=pts,
                        reason=f"Подозрительная таймзона: {js_tz}",
                    ))

        # Bot speed: >10 actions/sec = автоматизация
        max_actions_per_sec = input_data.get("maxActionsPerSec", 0)
        if max_actions_per_sec > 10:
            pts = 40
            soft_score += pts
            details.append(ScoringDetail(
                check="js_bot_speed", points=pts,
                reason=f"Скорость действий {max_actions_per_sec} actions/sec > 10 — автоматизация",
            ))

        # Touch не поддерживается
        touch_supported = input_data.get("touchSupported", True)
        if not touch_supported:
            soft_score += 20
            details.append(ScoringDetail(
                check="js_no_touch_support", points=20,
                reason="Устройство не поддерживает тач (десктоп/эмулятор)",
            ))

        # === ЯЗЫКОВАЯ ЭВРИСТИКА (модераторский паттерн) ===
        app = config_store.get_app(package_name) if package_name else None
        skip_lang = app.disable_lang_check if app else False

        js_lang = data.get("language", "")
        js_languages = data.get("languages", [])
        ip_country = ipinfo_data.country.upper() if ipinfo_data and ipinfo_data.country else ""

        ENGLISH_COUNTRIES = {"US", "GB", "AU", "CA", "NZ", "IE"}
        LANG_COUNTRY_MAP = {
            "ru": {"RU", "BY", "KZ", "KG", "UA", "UZ", "TJ", "MD"},
            "tr": {"TR", "CY"},
            "uk": {"UA"},
            "kk": {"KZ"},
            "uz": {"UZ"},
            "de": {"DE", "AT", "CH"},
            "fr": {"FR", "BE", "CH", "CA", "CI", "SN", "ML", "CM", "CG", "CD", "MG", "HT", "TN", "DZ", "MA"},
            "es": {"ES", "MX", "AR", "CO", "CL", "PE", "VE"},
            "pt": {"BR", "PT"},
            "ar": {"SA", "AE", "EG", "IQ", "JO", "KW", "QA", "BH", "OM", "LB"},
            "hi": {"IN"},
            "vi": {"VN"},
            "th": {"TH"},
            "id": {"ID"},
            "ja": {"JP"},
            "ko": {"KR"},
            "zh": {"CN", "TW", "HK", "SG"},
        }

        # 1. Язык устройства не совпадает со страной IP
        if not skip_lang and js_lang and ip_country:
            lang_code = js_lang[:2].lower()
            expected_countries = LANG_COUNTRY_MAP.get(lang_code, set())
            if lang_code == "en":
                expected_countries = ENGLISH_COUNTRIES

            if expected_countries and ip_country not in expected_countries:
                pts = cfg.weights.englishWebView
                soft_score += pts
                details.append(ScoringDetail(
                    check="js_lang_country_mismatch", points=pts,
                    reason=f"Язык '{js_lang}' не типичен для страны IP '{ip_country}'",
                ))

        # 2. Множество языков на устройстве (3+) — паттерн модератора
        if not skip_lang and len(js_languages) >= 3:
            pts = 15
            soft_score += pts
            details.append(ScoringDetail(
                check="js_multi_language", points=pts,
                reason=f"Множество языков на устройстве ({len(js_languages)}): {', '.join(js_languages[:5])}",
            ))

        # 3. Язык устройства — экзотический для целевого трафика
        if not skip_lang and js_lang and ip_country:
            exotic_langs = {"ar", "vi", "th", "hi", "bn", "ta", "te", "ml", "ko", "ja", "zh"}
            lang_code = js_lang[:2].lower()
            if lang_code in exotic_langs and ip_country in {"US", "GB", "DE", "FR"}:
                pts = 20
                soft_score += pts
                details.append(ScoringDetail(
                    check="js_exotic_lang_from_moderator_country", points=pts,
                    reason=f"Экзотический язык '{js_lang}' из страны модерации '{ip_country}'",
                ))

        # =============================================
        # ВЕРДИКТ
        # Жёсткие → мгновенный бан
        # Мягкие → бан только если совокупность >= 50
        # =============================================
        total = hard_score + soft_score

        if has_hard_ban:
            verdict = "white"
        elif soft_score >= JS_SENSOR_THRESHOLD:
            verdict = "white"
            rejection_code = rejection_code or "behavioral_score"
        else:
            verdict = "grey"
            rejection_code = None

        logger.info(
            f"[{ip}] JS hard={hard_score} soft={soft_score} total={total} "
            f"verdict={verdict} checks={len(details)}"
        )

        return ScoringResult(
            score=total,
            verdict=verdict,
            rejectionCode=rejection_code,
            details=details,
        )


scoring_engine = ScoringEngine()
