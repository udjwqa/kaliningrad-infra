import logging
import re
import time
import ipaddress
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from scoring_engine import scoring_engine
from request_logger import request_logger
from config import config_store
from external.play_integrity import play_integrity_client
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client
from models import ScoringResult, ScoringDetail

logger = logging.getLogger("init")

router = APIRouter()


def _subnet_key(ip: str) -> str:
    """P1-5 (2026-06-21): canonical /24 для IPv4 и /64 для IPv6 (через стандартный
    модуль ipaddress). Раньше naive split по ':' давал коллапс для non-canonical
    IPv6 (например '2a02:8084::' → ':' subnet — почти любой IPv6 попадал в один
    bucket, велосити-пул bypass). Невалидный IP → fallback на raw (старое
    поведение, не нарушаем regression)."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            net = ipaddress.IPv6Network((addr, 64), strict=False)
        else:
            net = ipaddress.IPv4Network((addr, 24), strict=False)
        return str(net.network_address)
    except (ValueError, TypeError):
        return ip

STUB_HTML = (Path(__file__).parent.parent / "templates" / "stub.html").read_text(encoding="utf-8")

AUTOBAN_SCORE = 100

# --- Smart Soft PI helpers ---------------------------------------------------

_ASN_RE = re.compile(r'AS(\d+)\b')

_EMULATOR_UA_MARKERS = (
    'sdk_gphone', 'android sdk built', 'emulator', 'genymotion',
    'aosp_atd', 'goldfish', 'ranchu',
)
_GOOGLE_DEVICE_UA_MARKERS = ('pixel ', 'nexus ', 'google sdk')


def _parse_asn(org: str) -> int:
    """'AS29465 MTN Nigeria Communications Ltd' -> 29465. 0 если не парсится."""
    if not org:
        return 0
    m = _ASN_RE.match(org.strip())
    return int(m.group(1)) if m else 0


def _ua_smells_emulator(ua: str) -> bool:
    if not ua:
        return False
    lo = ua.lower()
    return any(m in lo for m in _EMULATOR_UA_MARKERS)


def _ua_is_google_device(ua: str) -> bool:
    if not ua:
        return False
    lo = ua.lower()
    return any(m in lo for m in _GOOGLE_DEVICE_UA_MARKERS)


def _is_soft_pi_eligible(app, geo, ipqs_res) -> tuple[bool, str]:
    """Возвращает (eligible, reason). eligible=True ТОЛЬКО если:
    - app.soft_pi_countries не пуст
    - geo.country (uppercase) ∈ app.soft_pi_countries
    - ASN из geo.org ∈ whitelist для этой страны
    - НЕТ vpn/proxy/tor/hosting по ipinfo
    - IPQS fraud_score < 75, НЕ bot, НЕ vpn/proxy/tor (если IPQS доступен)
    """
    if not app or not getattr(app, 'soft_pi_countries', None):
        return False, "no_soft_pi_countries"
    if not geo:
        return False, "no_geo"
    country = (geo.country or '').upper()
    # P1-5 (2026-06-21): fail-CLOSED на пустой country/asn (раньше при ipinfo timeout
    # country=""/asn=0 могли совпасть с пустой entry в whitelist и пропускать).
    if not country:
        return False, "empty_country"
    soft_list = [c.upper() for c in app.soft_pi_countries]
    if country not in soft_list:
        return False, f"country_{country}_not_in_soft"
    # NG-relax (2026-06-21): для стран в soft_pi_countries_any_asn пропускаем
    # ASN whitelist check — нужно для NG где 73% юзеров на малых ISP/без PI
    # токена (sideloaded APK). Защита остаётся через ipinfo VPN/proxy/hosting +
    # IPQS + UA эмулятор + Pixel device + velocity + ASN ротация.
    any_asn_countries = [c.upper() for c in (getattr(app, 'soft_pi_countries_any_asn', []) or [])]
    asn = geo.asn
    if country not in any_asn_countries:
        # Обычный strict-режим: требуем ASN в whitelist мобильных операторов.
        if not asn or asn <= 0:
            return False, "empty_asn"
        whitelist = config_store.mobile_asn_whitelist.get(country, [])
        if asn not in whitelist:
            return False, f"asn_{asn}_not_in_whitelist_{country}"
    if getattr(geo, 'vpn', False) or getattr(geo, 'proxy', False) \
       or getattr(geo, 'tor', False) or getattr(geo, 'hosting', False):
        return False, "ipinfo_flagged"
    if ipqs_res and getattr(ipqs_res, 'success', False):
        if getattr(ipqs_res, 'fraud_score', 0) > 75:
            return False, f"ipqs_fraud_{ipqs_res.fraud_score}"
        if getattr(ipqs_res, 'bot_status', False):
            return False, "ipqs_bot"
        if getattr(ipqs_res, 'vpn', False) or getattr(ipqs_res, 'proxy', False) \
           or getattr(ipqs_res, 'tor', False):
            return False, "ipqs_vpn"
    return True, "ok"


async def _mark_instance_burnt(instance_id: str, package_name: str, reason: str):
    """F-burnt (2026-06-23): пометить instance как скомпрометированный на 24h.

    Вызывается из _verify_integrity когда сработал hard-kill signal который
    говорит "это точно атакер" — pi_nonce_replay, pi_unlicensed, pi_capturing,
    pi_controlling. Также из _resolve после soft_pi_extra (Pixel в Лагосе и т.п.).

    На следующих /init этого instance — `_resolve` сразу делает hard_kill_reason =
    instance_burnt и не дойдёт до scoring/PI verify.

    Закрывает CA IPv6 attack pattern (22.06): grey без PI токена между white с replay
    PI токеном. До фикса 50% запросов получали grey/offer. После — instant block 24h.

    Fail-open при Redis недоступности.
    """
    if not instance_id:
        return
    try:
        r = await request_logger._get_redis()
        key = f"instance_burnt:{package_name}:{instance_id}"
        await r.set(key, reason, ex=86400)
    except Exception:
        pass


async def _is_instance_burnt(instance_id: str, package_name: str) -> str:
    """Returns reason если instance burnt, иначе пустая строка."""
    if not instance_id:
        return ""
    try:
        r = await request_logger._get_redis()
        val = await r.get(f"instance_burnt:{package_name}:{instance_id}")
        return val or ""
    except Exception:
        return ""


async def _is_first_init(instance_id: str, package_name: str) -> bool:
    """2026-06-22: Проверка первый ли это /init для этого instance_id.

    Используется для gate'а PI v3 advanced UNEVALUATED-combo hard-kill:
    Real user первый раз тоже может иметь UNEVALUATED (Google Play Protect
    не успел оценить свежее устройство за первые ~30 мин). Поэтому блокируем
    UNEVALUATED только если это первый раз когда мы видим этот instance_id —
    у real user в течение 14 дней будут другие successful запросы которые
    flip'нут эту проверку в False.

    Redis SETNX key=pi_first_init:{package}:{instance_id}, TTL 14 дней.
    Returns:
        True — если SETNX добавил ключ (instance не видели ранее → возможный scanner)
        False — если ключ уже есть (или Redis fail → не блокируем)
    """
    if not instance_id:
        return False  # Без instance_id не блокируем (legacy clients)
    try:
        import time as _t_mod
        r = await request_logger._get_redis()
        key = f"pi_first_init:{package_name}:{instance_id}"
        # SETNX: добавляем только если ключа ещё нет. TTL 14 дней.
        added = await r.set(key, str(int(_t_mod.time())), nx=True, ex=14 * 86400)
        return bool(added)
    except Exception:
        return False  # Redis fail → fail-open (не блокируем)


async def _check_and_mark_cloak_consumed(instance_id: str, package_name: str, ip: str, verdict: str) -> tuple[bool, dict]:
    """P1-1 (2026-06-21): одноразовая выдача grey verdict для instance_id (защита от
    Google deep-review с реальным телефоном + Bright Data residential).

    Логика: SETNX в Redis с TTL 24h ключ cloak_consumed:{pkg}:{instance_id}.
    - Первый /init с нового instance → SETNX returns True → отдаём grey (cloak активен)
    - 2-й+ /init с того же instance за 24h → SETNX returns False → отдаём safe (cloak уже использован)

    Это критично против вектора #10: reviewer от живого юзера с physical Android + residential mobile
    проходит ВСЕ 5 слоёв скоринга (ASN/Geo/UA/PI/velocity) — единственная защита это память что
    мы УЖЕ обслужили этот instance ранее. Google re-scan/follow-up review видит safe → не палимся.

    Returns (consumed, meta). consumed=True → отдать safe URL. consumed=False → отдать оффер.
    Если instance_id пустой ИЛИ Redis недоступен → fail-OPEN (consumed=False, не блокируем оффер;
    это не хуже baseline до P1-1 — мы не делаем ситуацию хуже).
    """
    if not instance_id:
        # Без instance_id не можем track одноразовость. Возвращаем consumed=False
        # чтобы не сломать существующий flow (legacy юзеры без instance_id).
        return False, {"reason": "no_instance_id"}
    try:
        import json as _json_mod
        import time as _time_mod
        r = await request_logger._get_redis()
        key = f"cloak_consumed:{package_name}:{instance_id}"
        payload = _json_mod.dumps({"ts": int(_time_mod.time()), "ip": ip, "verdict": verdict})
        # SETNX (nx=True) + TTL 86400s. Возвращает True только если ключа не было.
        added = await r.set(key, payload, nx=True, ex=86400)
        if added:
            return False, {"first_time": True}
        existing = await r.get(key)
        return True, {"first_time": False, "cached": (existing or "")[:120]}
    except Exception as e:
        # Redis выпал — fail-OPEN. Никаких exception наружу.
        return False, {"error": str(e)[:60]}


async def _asn_rotation_check(instance_id: str, asn: int):
    """Soft-PI extra: instance_id не должен прыгать между ASN — это паттерн
    residential-proxy ротации (Bright Data / Soax / IPRoyal)."""
    if not instance_id or not asn:
        return 0, []
    try:
        r = await request_logger._get_redis()
        key = f"asnrot:{instance_id}"
        await r.sadd(key, str(asn))
        await r.expire(key, 3600)
        n = await r.scard(key)
        if n > 2:
            return AUTOBAN_SCORE, [ScoringDetail(
                check="asn_rotation", points=AUTOBAN_SCORE,
                reason=f"Soft-PI: {n} разных ASN на instance {instance_id[:8]} за 1ч — residential proxy",
            )]
    except Exception:
        pass
    return 0, []


# --- PI verify (3 режима) ----------------------------------------------------


async def _verify_integrity(token: str, package_name: str, mode: str = 'lenient',
                            instance_id: str = "", app=None):
    """Три режима PI:
    - 'strict':  DEVICE+PLAY_RECOGNIZED обязательны (модер режется)
    - 'soft':    BASIC ок, пустой verdict ок, UNRECOGNIZED ок. Режем только
                 pi_init_failed, pi_stale_token, pi_virtual (явный эмулятор)
    - 'lenient': старая soft-логика (для прил без require_integrity)

    2026-06-22: instance_id + app параметры опциональные (backward-compat) — используются
    для PI v3 advanced hard-kills (CAPTURING/CONTROLLING + UNEVALUATED combo on first_init).
    """
    if not token:
        # Нет токена. Только strict + PI настроен → бан. В soft/lenient — пропускаем.
        if mode == 'strict' and play_integrity_client.available:
            return AUTOBAN_SCORE, [ScoringDetail(
                check="pi_missing", points=AUTOBAN_SCORE,
                reason="Нет Play Integrity токена при strict-режиме — устройство не прошло проверку",
            )], {}
        return 0, [], {}

    if not play_integrity_client.available:
        return 0, [], {}

    verdict = await play_integrity_client.verify_token(token, package_name)
    if not verdict:
        return AUTOBAN_SCORE, [ScoringDetail(
            check="pi_init_failed", points=AUTOBAN_SCORE,
            reason="PI токен не декодируется (fail-closed)",
        )], {}

    score = 0
    details = []
    raw = getattr(verdict, "raw", None) or {}

    # SECURITY (audit 2026-06-21 MED-1): cross-app PI replay. Verdict содержит
    # requestPackageName — должен совпадать с package_name из proxy_key. Иначе
    # модер берёт валидный токен от своего debug-APK и шлёт на наш endpoint.
    if verdict.package_name and verdict.package_name != package_name:
        return AUTOBAN_SCORE, [ScoringDetail(
            check="pi_package_mismatch", points=AUTOBAN_SCORE,
            reason=f"PI cross-app replay: token={verdict.package_name} != app={package_name}",
        )], raw

    # PI timestamp freshness: токен 0-120с (с допуском 5с на clock skew).
    # SECURITY (audit 2026-06-21 MED-3): future-time replay (модер ставит +1 год → токен живёт год)
    # и невалидный timestamp parse → fail-closed.
    try:
        token_age_ms = int(time.time() * 1000) - int(verdict.timestamp_millis)
        if not (-5_000 <= token_age_ms <= 120_000):
            return AUTOBAN_SCORE, [ScoringDetail(
                check="pi_stale_or_future_token", points=AUTOBAN_SCORE,
                reason=f"PI токен невалидный age={token_age_ms}ms (должен быть -5s..120s)",
            )], raw
    except (ValueError, TypeError):
        return AUTOBAN_SCORE, [ScoringDetail(
            check="pi_timestamp_invalid", points=AUTOBAN_SCORE,
            reason="PI timestamp_millis не парсится — fail-closed",
        )], raw

    # SECURITY (audit 2026-06-21 MED-2): nonce replay. Один валидный PI токен
    # переиспользовался ~60 раз за 120с (velocity ловила только при одном instance_id,
    # модер использовал pool). Атомарный SETNX в Redis 120s TTL.
    if verdict.nonce:
        try:
            r = await request_logger._get_redis()
            nonce_key = f"pi_nonce_seen:{verdict.nonce}"
            added = await r.set(nonce_key, "1", nx=True, ex=120)
            if not added:
                # F-burnt: replay attack → mark instance burnt на 24h.
                # Закрывает CA IPv6 alternating pattern (grey без PI между white с replay).
                await _mark_instance_burnt(instance_id, package_name, "pi_nonce_replay")
                return AUTOBAN_SCORE, [ScoringDetail(
                    check="pi_nonce_replay", points=AUTOBAN_SCORE,
                    reason=f"PI nonce {verdict.nonce[:12]}... уже использован — replay",
                )], raw
        except Exception:
            pass  # Redis down → fail-open (velocity и другие слои поймают)

    # UNLICENSED hard-kill (2026-06-21): модер обычно sideload'ит APK напрямую через ADB
    # из Google Play Console (review process) — это даёт appLicensingVerdict=UNLICENSED.
    # Реальный юзер который установил из Play Store через свой Google аккаунт → LICENSED.
    # UNLICENSED для protected app = типичный reviewer flow (вектор #13 в audit).
    # UNEVALUATED не блокируем — Play Protect может ещё не оценить (норма для новых APK).
    # Срабатывает во ВСЕХ режимах (strict, soft, lenient).
    if verdict.app_licensing == "UNLICENSED":
        await _mark_instance_burnt(instance_id, package_name, "pi_unlicensed")
        return AUTOBAN_SCORE, [ScoringDetail(
            check="pi_unlicensed", points=AUTOBAN_SCORE,
            reason="PI: App Licensing UNLICENSED — APK не установлен из Play Store через аккаунт (reviewer/sideload)",
        )], raw

    # 2026-06-22: PI v3 ADVANCED hard-kills (срабатывают во ВСЕХ режимах strict/soft/lenient).

    # Hard-kill #1: appAccessRiskVerdict.appsDetected содержит CAPTURING.
    # Reviewer пишет screen recording для evidence перед баном прилы.
    if verdict.has_capturing_app:
        await _mark_instance_burnt(instance_id, package_name, "pi_capturing")
        return AUTOBAN_SCORE, [ScoringDetail(
            check="pi_capturing", points=AUTOBAN_SCORE,
            reason=f"PI: запись экрана (apps_detected={verdict.apps_detected}) — reviewer evidence flow",
        )], raw

    # Hard-kill #2: appAccessRiskVerdict.appsDetected содержит CONTROLLING.
    # Automation framework (UiAutomator/Robo/MoonAccessibility) — Firebase Test Lab Robo crawler.
    if verdict.has_controlling_app:
        await _mark_instance_burnt(instance_id, package_name, "pi_controlling")
        return AUTOBAN_SCORE, [ScoringDetail(
            check="pi_controlling", points=AUTOBAN_SCORE,
            reason=f"PI: автоматизация (apps_detected={verdict.apps_detected}) — Robo/UiAutomator scanner",
        )], raw

    # Hard-kill #3: UNEVALUATED combo на ПЕРВОМ init этого instance_id.
    # Signature свежего sandbox: Google не успел оценить ни активность устройства
    # (deviceActivityLevel=UNEVALUATED), ни Play Protect статус (UNEVALUATED/NO_DATA).
    # Real user на активном Pixel/Galaxy обычно имеет хотя бы один из них populated.
    # Gate на first_init защищает легитимные первые установки (если они один раз попали
    # в UNEVALUATED combo но прошли — мы запомнили instance в Redis на 14 дней).
    if (app is not None
        and getattr(app, 'block_pi_unevaluated_combo', True)
        and verdict.is_activity_unevaluated
        and verdict.is_play_protect_unevaluated_or_nodata):
        first_init = await _is_first_init(instance_id, package_name)
        if first_init:
            return AUTOBAN_SCORE, [ScoringDetail(
                check="pi_unevaluated_combo", points=AUTOBAN_SCORE,
                reason=(
                    f"PI v3: UNEVALUATED combo на первом /init "
                    f"(activity={verdict.device_activity_level}, "
                    f"playProtect={verdict.play_protect_verdict or 'empty'}) — "
                    f"scanner/PHA sandbox profile"
                ),
            )], raw

    if mode == 'strict':
        # СТРОГИЙ: пускаем ТОЛЬКО MEETS_DEVICE_INTEGRITY + PLAY_RECOGNIZED
        if not verdict.meets_device:
            score += AUTOBAN_SCORE
            details.append(ScoringDetail(
                check="pi_not_device_integrity", points=AUTOBAN_SCORE,
                reason=f"PI strict: не MEETS_DEVICE_INTEGRITY — {verdict.device_recognition}",
            ))
        if not verdict.is_recognized_app:
            score += AUTOBAN_SCORE
            details.append(ScoringDetail(
                check="pi_app_not_recognized", points=AUTOBAN_SCORE,
                reason=f"PI strict: app не PLAY_RECOGNIZED — {verdict.app_recognition}",
            ))
        return score, details, raw

    if mode == 'soft':
        # SOFT: BASIC ок, UNRECOGNIZED ок (sideload — норма в NG/CI/SN — APK с 1xbet.ng, sportybet).
        # SECURITY (audit 2026-06-21 CRIT-1): пустой verdict = stripped APK / Frida-patched PI /
        # cloned Play store. Реальные Itel/Tecno на Android 11+ стабильно дают MEETS_BASIC_INTEGRITY.
        # Режем: VIRTUAL-only / пустой verdict / даже не BASIC.
        if verdict.is_virtual_only:
            score += AUTOBAN_SCORE
            details.append(ScoringDetail(
                check="pi_virtual", points=AUTOBAN_SCORE,
                reason="PI soft: только VIRTUAL без DEVICE — эмулятор даже на mobile ASN",
            ))
        elif verdict.is_empty_device:
            score += AUTOBAN_SCORE
            details.append(ScoringDetail(
                check="pi_empty_soft", points=AUTOBAN_SCORE,
                reason="PI soft: пустой deviceRecognitionVerdict — stripped APK / Frida-patched PI",
            ))
        elif not verdict.meets_basic:
            score += AUTOBAN_SCORE
            details.append(ScoringDetail(
                check="pi_basic_failed_soft", points=AUTOBAN_SCORE,
                reason=f"PI soft: BASIC не пройден — {verdict.device_recognition}",
            ))
        else:
            details.append(ScoringDetail(
                check="pi_soft_accepted", points=0,
                reason=f"PI soft (mobile ASN страны-таргета): device={verdict.device_recognition} app={verdict.app_recognition}",
            ))
        return score, details, raw

    # LENIENT (старая soft-логика для прил без require_integrity)
    if verdict.is_empty_device:
        score += AUTOBAN_SCORE
        details.append(ScoringDetail(
            check="pi_empty_device", points=AUTOBAN_SCORE,
            reason="PI: пустой deviceRecognitionVerdict",
        ))

    if not verdict.meets_basic and not verdict.is_empty_device:
        score += AUTOBAN_SCORE
        details.append(ScoringDetail(
            check="pi_basic_failed", points=AUTOBAN_SCORE,
            reason=f"PI: BASIC не пройден — {verdict.device_recognition}",
        ))

    if verdict.is_virtual_only:
        score += AUTOBAN_SCORE
        details.append(ScoringDetail(
            check="pi_virtual", points=AUTOBAN_SCORE,
            reason="PI: только VIRTUAL — эмулятор",
        ))

    if verdict.app_recognition == "UNEVALUATED":
        score += AUTOBAN_SCORE
        details.append(ScoringDetail(
            check="pi_app_unevaluated", points=AUTOBAN_SCORE,
            reason="PI: App Recognition UNEVALUATED",
        ))

    return score, details, raw


async def _velocity_check(ip: str, instance_id: str):
    """Burst/velocity по Redis. Теперь вызывается для ВСЕХ require_integrity-прил
    (раньше только для strict-mode). Пороги консервативные."""
    try:
        r = await request_logger._get_redis()
    except Exception:
        return 0, []
    score = 0
    details = []
    try:
        # 1. Один instance долбит /init — автоматизация (живая установка так не делает).
        # F-vel (2026-06-23): TTL 60s → 300s. Закрывает "wait 60s reset bypass" bot pattern
        # (NG 197.211.59.119 показал 67 req/min где после block-burst counter expired и
        # следующие 8 прошли как grey). Threshold > 12 за 5 мин — всё ещё много для real юзера.
        if instance_id:
            k = f"vel:inst:{instance_id}"
            n = await r.incr(k)
            if n == 1:
                await r.expire(k, 300)
            if n > 12:
                score += AUTOBAN_SCORE
                details.append(ScoringDetail(
                    check="velocity_instance", points=AUTOBAN_SCORE,
                    reason=f"Velocity: {n} запросов с одного instance за 5мин — бот",
                ))
        # 2. Прокси-пул: много РАЗНЫХ свежих instance из одной /24 (или /64 ipv6) за 15 мин
        if ip and instance_id:
            # P1-5 (2026-06-21): canonical subnet через ipaddress (раньше naive split
            # collapse'ил non-canonical IPv6 в 1 bucket → bypass велосити-пула).
            subnet = _subnet_key(ip)
            ks = f"vel:sub:{subnet}"
            await r.sadd(ks, instance_id)
            await r.expire(ks, 900)
            if await r.scard(ks) > 15:
                score += AUTOBAN_SCORE
                details.append(ScoringDetail(
                    check="velocity_subnet", points=AUTOBAN_SCORE,
                    reason=f"Velocity: >15 разных install из подсети {subnet} за 15мин — прокси-пул",
                ))
        # 3. Очень высокая частота с одного IP (высокий порог — чтобы не задеть CGNAT).
        # F-vel (2026-06-23): TTL 60s → 300s (синхронно с vel:inst). Threshold 60 за 5 мин
        # на одном IP. Для real CGNAT (Fastweb / MTN NG): 60 разных юзеров за 5 мин
        # с одного NAT IP — не очень частая ситуация на уровне одной мини-серверной зоны.
        if ip:
            ki = f"vel:ip:{ip}"
            ni = await r.incr(ki)
            if ni == 1:
                await r.expire(ki, 300)
            if ni > 60:
                score += AUTOBAN_SCORE
                details.append(ScoringDetail(
                    check="velocity_ip", points=AUTOBAN_SCORE,
                    reason=f"Velocity: {ni} запросов с IP {ip} за 5мин",
                ))
    except Exception:
        pass
    return score, details


def _pstep(trace, step: str, status: str, reason: str = ""):
    """Helper: append pipeline step to trace dict (no-op если trace=None)."""
    if trace is not None:
        trace.setdefault("pipeline_steps", []).append(
            {"step": step, "status": status, "reason": reason})


async def _resolve(request: Request, proxy_key: str, _trace=None):
    """_trace=None → обычный flow (production). _trace={} → trace mode:
    populates dict, skip request_logger.log (test probe не засоряет audit).
    """
    key_data = config_store.resolve_proxy_key(proxy_key)
    if not key_data:
        _pstep(_trace, "proxy_key_lookup", "failed", "Unknown proxy_key")
        if _trace is not None:
            _trace["verdict"] = None
            _trace["hard_kill"] = {"code": "unknown_proxy_key", "reason": "proxy_key не найден"}
        return None, None, None

    package_name = key_data["package_name"]
    app = config_store.get_app(package_name)
    _pstep(_trace, "proxy_key_lookup", "passed", f"package={package_name}")
    if _trace is not None:
        _trace["package_name"] = package_name

    if app and app.panic_mode:
        safe_url = app.safe_url if app else config_store.offers.safeUrl
        _pstep(_trace, "panic_mode", "fired", "Panic mode active")
        if _trace is not None:
            _trace["verdict"] = "white"
            _trace["hard_kill"] = {"code": "panic_mode", "reason": "Panic mode active for this app"}
        return package_name, "white", safe_url

    # IP клиента приходит от middleware/sidecar в X-Forwarded-For (middleware вычисляет
    # из cf-connecting-ip когда юзер реальный, и санирует от spoofing).
    # Note: CF-Connecting-IP здесь = IP middleware-сервера (т.к. middleware делает fetch),
    # не клиент. Использовать его нельзя для client IP.
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )

    user_agent = request.headers.get("user-agent", "")
    accept_language = request.headers.get("accept-language", "")
    # instance_id: header → query fallback (новый AppClient SDK кладёт в query)
    # 2026-06-22 (F4 fix): .strip() закрывает whitespace bypass для missing_instance_id gate
    # (модер слал "X-Instance-Id:  " (space) → truthy → проходил check). После strip() пустая
    # строка → falsy → missing_instance_id hard-kill срабатывает корректно.
    instance_id = (request.headers.get("x-instance-id", "") or request.query_params.get("instance_id", "")).strip()
    require_pi = app.require_integrity if app else False

    # Debug/тест-режим: whitelist IP/instance → оффер без проверок (точечно под тест дева).
    if config_store.is_debug(ip, instance_id):
        target_url = app.target_url if app and app.target_url else config_store.offers.targetUrl
        geo = await ipinfo_client.lookup(ip)
        await request_logger.log(
            ip=ip,
            result=ScoringResult(score=0, verdict="grey", rejectionCode=None, details=[
                ScoringDetail(check="debug_bypass", points=0,
                              reason="Debug whitelist (IP/instance) — оффер без проверок")]),
            user_agent=user_agent, accept_language=accept_language,
            country=(geo.country if geo else ""), country_code=(geo.country if geo else ""),
            city=(geo.city if geo else ""),
            headers={"x-app-id": package_name, "source": "init",
                     "x-instance-id": instance_id, "debug": "yes", "has-integrity": "no"},
            js_metrics=None,
        )
        logger.info(f"[{ip}] init: pkg={package_name} DEBUG bypass → grey")
        import base64 as _b64d
        _t = _b64d.urlsafe_b64encode(target_url.encode()).decode()
        return package_name, "grey", f"https://api.threeamigosteam.com/engine/go?t={_t}"

    # PI токен берём заранее — прокинем как сигнал в скоринг (для CCT-friendly not_webview)
    # header → query fallback (новый AppClient SDK кладёт в query как integrity_token)
    integrity_token = (
        request.headers.get("x-integrity-token", "")
        or request.query_params.get("integrity_token", "")
    )

    # GEO + IPQS заранее — нужны для hard-kill Google ASN и soft-PI eligibility
    geo = await ipinfo_client.lookup(ip)
    asn = geo.asn if geo else 0
    ipqs_res = None
    try:
        ipqs_res = await ipqs_client.lookup(ip)
    except Exception:
        pass

    if _trace is not None:
        _trace["ip"] = ip
        _trace["instance_id"] = instance_id
        _trace["has_integrity"] = bool(integrity_token)
        _trace["geo"] = (geo.raw if geo and hasattr(geo, "raw") else None)
        _trace["ipqs"] = (ipqs_res.raw if ipqs_res and hasattr(ipqs_res, "raw") else None)
        _trace["country"] = (geo.country if geo else "")
        _trace["asn"] = asn
        _trace["isp"] = (geo.isp if geo else "")
        _trace["city"] = (geo.city if geo else "")

    # === HARD-KILL: Google/Accenture ASN → instant white, никакой скоринг не нужен ===
    block_google = getattr(app, 'block_google_asn', True) if app else True
    require_pi_app = getattr(app, 'require_integrity', False) if app else False

    # SECURITY (audit 2026-06-21 CRIT-2): fail-closed для protected прил когда asn=0/geo=None.
    # Иначе новый GCP IPv6 prefix без org в ipinfo или timeout → asn=0 → hard-kill пропускается
    # → Google проходит. Для prilas без require_integrity оставляем старое поведение
    # (не ломаем существующий flow для незащищённых прил).
    # NG-relax (2026-06-21): exemption для стран в soft_pi_countries_any_asn —
    # NG юзеры часто имеют asn=0 (rare/missing) или non-mobile ASN. Без exemption
    # они бы блокировались ДО soft_pi check. Soft-PI eligibility сам по себе
    # требует non-empty country (fail-closed там же), так что без подтверждения
    # geo.country=NG этот exemption не сработает.
    hard_kill_reason = None
    any_asn_countries = []
    if app:
        any_asn_countries = [c.upper() for c in (getattr(app, 'soft_pi_countries_any_asn', []) or [])]
    geo_country = (geo.country if geo else '').upper()
    geo_unknown_exempt = bool(any_asn_countries) and geo_country in any_asn_countries

    # 2026-06-22 (FIX): Missing instance_id для protected apps = hard-kill.
    # Real users всегда шлют instance_id (SDK v3 force-генерит + SharedPreferences).
    # Если protected app получает /init БЕЗ x-instance-id — это manual probe
    # (curl модера) ИЛИ bypass attempt чтобы отключить pi_unevaluated_combo gate
    # (_is_first_init возвращает False если instance_id пустой → combo не сработает).
    # Zero FP — SDK гарантирует header. Применять только для require_pi_app.
    # F-burnt (2026-06-23): instance уже spam'ил compromised PI / sideload / capturing
    # — instant hard-kill на 24h без дальнейших проверок. Закрывает CA IPv6 attack
    # где между replayed PI запросами шли grey без PI, проходящие soft-mode.
    burnt_reason = ""
    if instance_id and require_pi_app:
        burnt_reason = await _is_instance_burnt(instance_id, package_name)

    if burnt_reason:
        hard_kill_reason = ("instance_burnt",
            f"Instance ранее spam'ил {burnt_reason} — burnt на 24h")
        _pstep(_trace, "instance_burnt", "fired", hard_kill_reason[1])
    elif require_pi_app and getattr(app, 'block_ipqs', True) and not instance_id:
        hard_kill_reason = ("missing_instance_id",
            "Protected app + missing x-instance-id header — manual probe или PI combo bypass")
        _pstep(_trace, "instance_burnt", "passed")
        _pstep(_trace, "missing_instance_id", "fired", hard_kill_reason[1])
    # 2026-06-22 (FIX): Tor exit unconditional hard-kill для ВСЕХ apps.
    # Tor на Android = zero FP (никто не запускает Tor exit на телефоне).
    # Срабатывает ДО require_pi_app gate — даже unprotected apps защищены.
    elif (ipqs_res and getattr(ipqs_res, 'success', False)
          and getattr(ipqs_res, 'tor', False)):
        hard_kill_reason = ("ipqs_vpn",
            f"IPQS: Tor exit (unconditional, fraud_score={ipqs_res.fraud_score})")
        _pstep(_trace, "missing_instance_id", "passed")
        _pstep(_trace, "tor_unconditional", "fired", hard_kill_reason[1])
    elif block_google and require_pi_app and (asn == 0 or geo is None) and not geo_unknown_exempt:
        hard_kill_reason = ("geo_unknown",
            f"Protected app + ASN/geo unknown (asn={asn}, geo={'None' if geo is None else 'ok'}) — fail-closed")
        _pstep(_trace, "missing_instance_id", "passed")
        _pstep(_trace, "tor_unconditional", "passed")
        _pstep(_trace, "geo_unknown", "fired", hard_kill_reason[1])
    elif block_google and asn and asn in config_store.google_asn_blocklist:
        hard_kill_reason = ("asn_google",
            f"Hard-block: ASN {asn} в Google/Accenture blocklist (FTL/review)")
        _pstep(_trace, "missing_instance_id", "passed")
        _pstep(_trace, "tor_unconditional", "passed")
        _pstep(_trace, "geo_unknown", "passed")
        _pstep(_trace, "asn_google", "fired", hard_kill_reason[1])
    # VPN-blocklist (2026-06-21): hard-block commercial VPN/datacenter ASN
    # (M247, NordVPN, Surfshark, Vultr, OVH, Hetzner, и др).
    # Срабатывает только для protected apps с block_vpn_asn=True (default).
    # Это закрывает Sisal-incident — модер пробил через M247 потому что IPinfo
    # не пометил его как hosting.
    elif (require_pi_app and getattr(app, 'block_vpn_asn', True)
          and asn and asn in config_store.vpn_asn_blocklist):
        hard_kill_reason = ("asn_vpn",
            f"Hard-block: ASN {asn} в VPN/datacenter blocklist (commercial VPN exit)")
        _pstep(_trace, "missing_instance_id", "passed")
        _pstep(_trace, "tor_unconditional", "passed")
        _pstep(_trace, "geo_unknown", "passed")
        _pstep(_trace, "asn_google", "passed")
        _pstep(_trace, "asn_vpn", "fired", hard_kill_reason[1])
    # 2026-06-22 (TUNED после live test + FIX 22.06): IPQS hard-kill для protected apps.
    # Tor — вынесен в unconditional блок выше.
    # Comprehensive test 22 IPs показал 50% false positives когда блокируем по proxy/bot:
    # - 85.18.0.133 (Fastweb IT real consumer) — proxy=true (CGNAT pollution)
    # - 176.150.1.1 (Bouygues FR real consumer) — proxy=true (CGNAT pollution)
    # - 102.91.103.241 (MTN NG real mobile) — proxy+bot=true (CGNAT abuse history)
    # - 105.112.101.6 (Airtel NG real mobile) — proxy+bot=true (CGNAT abuse history)
    # Поэтому блокируем ТОЛЬКО по сильным сигналам: vpn=true ИЛИ fraud_score>=90.
    # proxy + bot_status — soft signals в scoring_engine (не autoban).
    # Fail-open: пустой key / API down → ipqs_res=None → skip.
    # Per-app toggle block_ipqs (default True). Только для require_integrity=True.
    elif (require_pi_app and getattr(app, 'block_ipqs', True)
          and ipqs_res and getattr(ipqs_res, 'success', False)):
        if getattr(ipqs_res, 'vpn', False):
            hard_kill_reason = ("ipqs_vpn",
                f"IPQS: VPN detected (vpn=true, fraud_score={ipqs_res.fraud_score}, "
                f"ISP={ipqs_res.isp})")
            _pstep(_trace, "missing_instance_id", "passed")
            _pstep(_trace, "tor_unconditional", "passed")
            _pstep(_trace, "geo_unknown", "passed")
            _pstep(_trace, "asn_google", "passed")
            _pstep(_trace, "asn_vpn", "passed")
            _pstep(_trace, "ipqs_vpn", "fired", hard_kill_reason[1])
        elif getattr(ipqs_res, 'fraud_score', 0) >= 90:
            hard_kill_reason = ("ipqs_fraud",
                f"IPQS: very high fraud_score={ipqs_res.fraud_score} (threshold 90)")
            _pstep(_trace, "missing_instance_id", "passed")
            _pstep(_trace, "tor_unconditional", "passed")
            _pstep(_trace, "geo_unknown", "passed")
            _pstep(_trace, "asn_google", "passed")
            _pstep(_trace, "asn_vpn", "passed")
            _pstep(_trace, "ipqs_vpn", "passed")
            _pstep(_trace, "ipqs_fraud", "fired", hard_kill_reason[1])

    if hard_kill_reason:
        reject_code, reason_text = hard_kill_reason
        safe_url = app.safe_url if app else config_store.offers.safeUrl
        # Trace mode: записываем classification + skip request_logger.log
        if _trace is not None:
            from classifier import classify_actor
            _trace["verdict"] = "white"
            _trace["hard_kill"] = {"code": reject_code, "reason": reason_text}
            _trace["score_buckets"] = {"base": AUTOBAN_SCORE, "pi": 0, "vel": 0, "extra": 0, "total": AUTOBAN_SCORE}
            _trace["all_details"] = [{"check": reject_code, "points": AUTOBAN_SCORE, "reason": reason_text}]
            _trace["rejection_code"] = reject_code
            _trace["threshold"] = config_store.engine.scoreThreshold
            _trace["classification"] = classify_actor(_trace)
            return package_name, "white", safe_url

        result_stub = ScoringResult(
            score=AUTOBAN_SCORE, verdict="white", rejectionCode=reject_code,
            details=[ScoringDetail(
                check=reject_code, points=AUTOBAN_SCORE,
                reason=reason_text)],
        )
        geo_country = geo.country if geo else ""
        geo_city = geo.city if geo else ""
        # Реконструируем минимальный trace для classification
        from classifier import classify_actor
        _hk_trace = {
            "verdict": "white",
            "hard_kill": {"code": reject_code, "reason": reason_text},
            "score_buckets": {"base": AUTOBAN_SCORE, "pi": 0, "vel": 0, "extra": 0, "total": AUTOBAN_SCORE},
            "threshold": config_store.engine.scoreThreshold,
            "all_details": [{"check": reject_code, "points": AUTOBAN_SCORE, "reason": reason_text}],
            "rejection_code": reject_code,
            "country": geo_country, "asn": asn,
        }
        await request_logger.log(
            ip=ip, result=result_stub, user_agent=user_agent, accept_language=accept_language,
            country=geo_country, country_code=geo_country, city=geo_city,
            headers={
                "x-app-id": package_name, "source": "init",
                "x-proxy-key": proxy_key[:8] + "...", "user-agent": user_agent,
                "x-instance-id": instance_id,
                "has-integrity": "yes" if integrity_token else "no",
                "asn": str(asn), "hard-kill": reject_code,
            },
            js_metrics=None,
            extra_payload={
                "scoreBuckets": _hk_trace["score_buckets"],
                "hardKill": _hk_trace["hard_kill"],
                "classification": classify_actor(_hk_trace),
            },
        )
        logger.info(f"[{ip}] init: pkg={package_name} HARD-KILL asn={asn} → white {reject_code}")
        return package_name, "white", safe_url

    # Базовый скоринг (все слои, не зависящие от PI)
    # 2026-06-21: передаём country/city/isp/asn из geo чтобы score_request мог сделать
    # lang-country hard-kill check (модер с VPN на IT + lang=ru → AUTOBAN).
    _geo_country = (geo.country if geo else "")
    _geo_city = (geo.city if geo else "")
    _geo_isp = (geo.isp if geo else "")
    result = await scoring_engine.score_request(
        ip=ip,
        user_agent=user_agent,
        accept_language=accept_language,
        country=_geo_country,
        city=_geo_city,
        isp=_geo_isp,
        asn=str(asn) if asn else "",
        package_name=package_name,
        client_secret=proxy_key,
        instance_id=instance_id,
        has_integrity=bool(integrity_token),
    )

    # === Smart Soft PI: решаем режим PI verify в зависимости от страны+ASN ===
    soft_eligible, soft_reason = (False, "strict_default")
    if require_pi:
        soft_eligible, soft_reason = _is_soft_pi_eligible(app, geo, ipqs_res)
        pi_mode = 'soft' if soft_eligible else 'strict'
    else:
        pi_mode = 'lenient'

    # PI verify в выбранном режиме
    pi_score, pi_details, pi_raw = await _verify_integrity(
        integrity_token, package_name, pi_mode,
        instance_id=instance_id, app=app,  # 2026-06-22: PI v3 advanced hard-kills
    )

    # Velocity — ВСЕГДА для require_integrity-прил (раньше было только при strict)
    vel_score, vel_details = (await _velocity_check(ip, instance_id)) if require_pi else (0, [])

    # Extra-проверки если soft-PI активирован: защита от модера который надел маску NG-юзера
    extra_score, extra_details = 0, []
    if soft_eligible:
        # 1. ASN rotation на одном instance — residential proxy
        rot_s, rot_d = await _asn_rotation_check(instance_id, asn)
        extra_score += rot_s
        extra_details += rot_d
        if rot_s >= AUTOBAN_SCORE:
            await _mark_instance_burnt(instance_id, package_name, "asn_rotation")
        # 2. UA пахнет эмулятором даже на MTN-IP (тетеринг + LDPlayer)
        if _ua_smells_emulator(user_agent):
            extra_score += AUTOBAN_SCORE
            extra_details.append(ScoringDetail(
                check="soft_ua_emulator", points=AUTOBAN_SCORE,
                reason="Soft-PI: UA содержит маркер эмулятора (sdk_gphone/aosp_atd) на mobile ASN",
            ))
            await _mark_instance_burnt(instance_id, package_name, "soft_ua_emulator")
        # 3. UA = Pixel/Nexus — Pixel в Лагосе крайне редок, FTL/reviewer часто на Pixel
        if _ua_is_google_device(user_agent):
            extra_score += AUTOBAN_SCORE
            geo_country_for_log = (geo.country if geo else '?').upper()
            extra_details.append(ScoringDetail(
                check="soft_ua_google_device", points=AUTOBAN_SCORE,
                reason=f"Soft-PI: Google-device (Pixel/Nexus) в {geo_country_for_log} (редкость + типично для FTL)",
            ))
            await _mark_instance_burnt(instance_id, package_name, "soft_ua_google_device")

    total_score = result.score + pi_score + vel_score + extra_score
    all_details = result.details + pi_details + vel_details + extra_details
    rejection = result.rejectionCode
    if not rejection and pi_score >= AUTOBAN_SCORE:
        rejection = "integrity_missing" if not integrity_token else "device_compromised"
    if not rejection and vel_score >= AUTOBAN_SCORE:
        rejection = "velocity_block"
    if not rejection and extra_score >= AUTOBAN_SCORE:
        rejection = "soft_pi_extra"

    threshold = config_store.engine.scoreThreshold
    verdict = "white" if total_score >= threshold else result.verdict

    # Pipeline trace для не-hard-kill flow
    if _trace is not None:
        _pstep(_trace, "missing_instance_id", "passed")
        _pstep(_trace, "tor_unconditional", "passed")
        _pstep(_trace, "geo_unknown", "passed")
        _pstep(_trace, "asn_google", "passed")
        _pstep(_trace, "asn_vpn", "passed")
        _pstep(_trace, "ipqs_vpn", "passed")
        _pstep(_trace, "ipqs_fraud", "passed")
        _pstep(_trace, "scoring", "fired" if result.score > 0 else "passed",
               f"base={result.score} ({len(result.details)} checks)")
        _pstep(_trace, "pi_verify", "fired" if pi_score > 0 else "passed",
               f"mode={pi_mode}, score={pi_score}")
        _pstep(_trace, "velocity", "fired" if vel_score > 0 else "passed", f"score={vel_score}")
        if soft_eligible:
            _pstep(_trace, "soft_pi_extras", "fired" if extra_score > 0 else "passed",
                   f"extra_score={extra_score}")

    # P1-1 (2026-06-21): cloak_consumed — одноразовая выдача grey для instance_id.
    # Опт-ин per app (cloak_consumed_enabled=True для Snai/Stake/Sisal). Закрывает
    # red-team вектор #10 (Google reviewer с physical phone + Bright Data residential).
    cloak_enabled = getattr(app, 'cloak_consumed_enabled', False) if app else False
    cloak_meta_log = {}
    if cloak_enabled and verdict == "grey":
        cloak_consumed, cloak_meta_log = await _check_and_mark_cloak_consumed(
            instance_id, package_name, ip, verdict)
        if cloak_consumed:
            verdict = "white"
            rejection = "cloak_consumed"
            all_details.append(ScoringDetail(
                check="cloak_consumed", points=0,
                reason=f"Cloak уже выдан для instance {(instance_id or '?')[:12]} ({cloak_meta_log.get('reason', 'used')})",
            ))

    import base64 as _b64
    safe_url = app.safe_url if app else config_store.offers.safeUrl
    target_url = app.target_url if app and app.target_url else config_store.offers.targetUrl
    if verdict == "white":
        url = safe_url
    else:
        t = _b64.urlsafe_b64encode(target_url.encode()).decode()
        url = f"https://api.threeamigosteam.com/engine/go?t={t}"

    geo_country = geo.country if geo else ""
    geo_city = geo.city if geo else ""

    # Trace mode: записываем финальный state + skip request_logger.log
    if _trace is not None:
        from classifier import classify_actor
        _trace["verdict"] = verdict
        _trace["score_buckets"] = {
            "base": result.score, "pi": pi_score, "vel": vel_score,
            "extra": extra_score, "total": total_score,
        }
        _trace["threshold"] = threshold
        _trace["pi_mode"] = pi_mode
        _trace["soft_eligible"] = soft_eligible
        _trace["soft_reason"] = soft_reason
        _trace["pi_raw"] = pi_raw
        _trace["all_details"] = [d.model_dump() for d in all_details]
        _trace["rejection_code"] = rejection
        _trace["classification"] = classify_actor(_trace)
        # Логируем что trace выполнен (но без БД)
        logger.info(
            f"[{ip}] init-TRACE: pkg={package_name} verdict={verdict} "
            f"class={_trace['classification'].get('class')} score={total_score}"
        )
        return package_name, verdict, url

    # Реконструируем trace для request_logger чтобы сохранить classification + compact fields
    from classifier import classify_actor
    _log_trace = {
        "verdict": verdict,
        "rejection_code": rejection,
        "score_buckets": {
            "base": result.score, "pi": pi_score, "vel": vel_score,
            "extra": extra_score, "total": total_score,
        },
        "threshold": threshold,
        "pi_mode": pi_mode,
        "soft_eligible": soft_eligible,
        "soft_reason": soft_reason,
        "all_details": [d.model_dump() for d in all_details],
        "pi_raw": pi_raw,
        "country": geo_country,
        "asn": asn,
    }
    classification = classify_actor(_log_trace)

    await request_logger.log(
        ip=ip,
        result=ScoringResult(
            score=total_score,
            verdict=verdict,
            rejectionCode=rejection,
            details=all_details,
        ),
        user_agent=user_agent,
        accept_language=accept_language,
        country=geo_country,
        country_code=geo_country,
        city=geo_city,
        headers={
            "x-app-id": package_name,
            "source": "init",
            "x-proxy-key": proxy_key[:8] + "...",
            "user-agent": user_agent,
            "x-instance-id": instance_id,
            "has-integrity": "yes" if integrity_token else "no",
            "pi-mode": pi_mode,
            "soft-eligible": "yes" if soft_eligible else "no",
            "soft-reason": soft_reason,
            "asn": str(asn),
        },
        js_metrics={"playIntegrity": pi_raw} if pi_raw else None,
        # 2026-06-22: compact trace fields для UI обзора клика (см. classifier.py)
        extra_payload={
            "scoreBuckets": _log_trace["score_buckets"],
            "piMode": pi_mode,
            "softEligible": {"ok": soft_eligible, "reason": soft_reason},
            "hardKill": None,  # этот path = no hard-kill
            "classification": classification,
        },
    )

    logger.info(
        f"[{ip}] init: pkg={package_name} asn={asn} country={geo_country} "
        f"pi_mode={pi_mode} soft={soft_eligible}({soft_reason}) "
        f"score={total_score} (base={result.score} pi={pi_score} vel={vel_score} extra={extra_score}) "
        f"verdict={verdict}"
    )
    return package_name, verdict, url


@router.get("/init")
async def init_resolve(request: Request):
    # proxy_key: header → query fallback (новый AppClient SDK может слать в query)
    proxy_key = request.headers.get("x-proxy-key", "") or request.query_params.get("proxy_key", "")
    pkg, verdict, url = await _resolve(request, proxy_key)

    if pkg is None:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)

    return {"url": url}


@router.get("/web_content")
async def web_content(request: Request):
    proxy_key = request.headers.get("x-proxy-key", "")

    if not proxy_key:
        return HTMLResponse(STUB_HTML)

    pkg, verdict, url = await _resolve(request, proxy_key)

    if pkg is None:
        return HTMLResponse(STUB_HTML)

    return RedirectResponse(url=url, status_code=302)


# === /api/init-trace: rich trace для UI лабы тестов и админских проб ===
# Запускает _resolve в trace mode (НЕ пишет в request_logger).
# Возвращает {verdict, url, package_name, classification, trace}.
# Защищено AdminAuthMiddleware (X-Admin-Key header через ADMIN_PREFIXES).
@router.get("/api/init-trace")
async def init_trace(request: Request):
    proxy_key = request.headers.get("x-proxy-key", "") or request.query_params.get("proxy_key", "")
    trace: dict = {}
    pkg, verdict, url = await _resolve(request, proxy_key, _trace=trace)
    return {
        "verdict": verdict,
        "url": url,
        "package_name": pkg,
        "classification": trace.get("classification"),
        "trace": trace,
    }
