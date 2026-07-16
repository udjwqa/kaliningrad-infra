"""Классификация actor'а (real user / модератор / suspicious) на основе trace.

Pure function — не имеет side effects, не делает HTTP/DB вызовов.
Используется в /api/init-trace (rich response в лабе) и в request_logger
(сохраняется в raw_payload для каждого реального клика чтобы было видно
в audit log/dashboard кто пришёл).
"""

from typing import Optional


_REASON_TEMPLATES = {
    # hard-kills
    "missing_instance_id": "Запрос без instance_id — manual probe / curl",
    "ipqs_vpn": "IPQS детектит VPN/Tor exit",
    "ipqs_fraud": "IPQS fraud_score≥90 — high risk IP",
    "geo_unknown": "ASN/гео не определены (fail-closed для protected)",
    "asn_google": "ASN в google_asn_blocklist (Firebase Test Lab / Accenture)",
    "asn_vpn": "ASN в vpn_asn_blocklist (commercial VPN / datacenter)",
    "asn_blocked": "ASN в datacenter blocklist (Google/AWS/Azure/OVH/...)",
    "lang_country_mismatch": "Lang в Accept-Language не совпадает со страной IP",
    "country_not_allowed": "Страна не в allowed_countries прилы",
    "country_blocked": "Страна в countries_block",
    "device_hardban": "Hardban-устройство (Galaxy S24 Ultra / OnePlus 8 Pro)",
    "device_compromised": "PI verdict failed — устройство compromised",
    "device_spoof": "GPU не совместим с моделью / ротация GPU",
    "emulator_detected": "Codename эмулятора",
    "emulator_gpu": "GPU эмулятора (SwiftShader/llvmpipe/...)",
    "test_build_detected": "Тестовый build (test_builds_block)",
    "google_referer": "Referer от google.com (внутренний трафик Google)",
    "ip_range_blocked": "IP в bot/datacenter CIDR диапазоне",
    "vpn_detected": "VPN flagged (IPQS/IPinfo)",
    "proxy_detected": "Proxy flagged",
    "suspicious_hosting": "Hosting/datacenter ISP",
    "bot_detected": "IPQS bot_status=true",
    "bot_user_agent": "UA содержит bot-маркер (Googlebot/AhrefsBot/...)",
    "honeypot": "Запрос на honeypot path",
    "integrity_missing": "Нет PI токена при strict-режиме",
    "integrity_invalid": "PI токен невалидный",
    "behavioral_score": "Поведенческий score >= threshold",
    "velocity_block": "Velocity: слишком много запросов (instance/IP/subnet)",
    "google_device_combo": "Google устройство (Pixel/Nexus) + ещё сигнал = FTL/модер",
    "tor_exit": "IP в Tor exit list (check.torproject.org)",
    "instance_burnt": "Instance ранее spam'ил compromised PI / sideload / эмулятор UA — burnt на 24h",
    "asn_rotation": "Один instance прыгает между несколькими ASN — residential proxy ротация",
    "soft_pi_extra": "Soft-PI extra check (UA эмулятор / Pixel в Africa / ASN rotation)",
    "city_blocked": "Город модераторов (Mountain View / Hyderabad / ...)",
    "cloak_consumed": "Cloak уже выдан этому instance (одноразовая выдача)",
    "pi_capturing": "Запущен screen recorder (CAPTURING) — модер пишет evidence",
    "pi_controlling": "Включена автоматизация (CONTROLLING) — UiAutomator/Robo",
    "pi_unevaluated_combo": "PI: свежий sandbox (UNEVALUATED combo) — scanner farm",
    "pi_unlicensed": "PI UNLICENSED — APK sideload, не из Play Store",
    "pi_package_mismatch": "Cross-app PI replay (токен от чужой прилы)",
    "pi_nonce_replay": "PI nonce replay (тот же токен juzан второй раз)",
    "pi_stale_or_future_token": "PI токен устаревший или из будущего (replay)",
}


def _explain_check(check: str, reason: str) -> str:
    """Подбирает короткое русское объяснение для check кода."""
    return _REASON_TEMPLATES.get(check, reason)[:160]


def classify_actor(trace: Optional[dict]) -> dict:
    """Принимает trace dict (от _resolve в trace mode или построенный из
    raw_payload в request_logger), возвращает classification.

    Returns:
        {
            "class": "moder_bot" | "suspicious" | "real_mobile" | "real_verified" | "real_unverified",
            "label": "🔴 Модер / Bot" | "⚠️ Подозрительный" | ...,
            "confidence": "high" | "medium" | "low",
            "reasoning": ["причина 1", "причина 2"],
        }
    """
    if not trace:
        return {
            "class": "real_unverified",
            "label": "❓ Неизвестно",
            "confidence": "low",
            "reasoning": ["Trace данных нет"],
        }

    verdict = trace.get("verdict") or ""
    hard_kill = trace.get("hard_kill") or {}
    score_buckets = trace.get("score_buckets") or {}
    total = score_buckets.get("total", 0)
    threshold = trace.get("threshold", 70)
    pi_mode = trace.get("pi_mode") or "lenient"
    soft_eligible = trace.get("soft_eligible", False)
    all_details = trace.get("all_details") or []
    rejection_code = trace.get("rejection_code") or hard_kill.get("code") or ""

    # 1) HARD-KILL → moder_bot
    if hard_kill.get("code"):
        code = hard_kill["code"]
        reasoning = [_explain_check(code, hard_kill.get("reason", ""))]
        return {
            "class": "moder_bot",
            "label": "🔴 Модер / Bot",
            "confidence": "high",
            "reasoning": reasoning,
        }

    # 1.5) F5 (2026-06-22): scoring-level rejection codes которые также = модер/бот.
    # Эти rejection_codes выставляются scoring_engine не через hard_kill (в init_routes),
    # а через накопление score >= threshold. Это всё равно модер/бот сигнал — не
    # должны показываться как "suspicious" в UI.
    MODER_BOT_REJECTIONS = {
        "asn_blocked", "asn_vpn", "asn_google",
        "country_not_allowed", "country_blocked", "country_block",
        "isp_block", "suspicious_hosting",
        "vpn_detected", "proxy_detected", "tor_detected", "tor_exit",
        "instance_burnt", "asn_rotation",
        "device_blocked", "device_hardban", "device_compromised", "device_spoof",
        "emulator_detected", "emulator_gpu", "test_build_detected",
        "google_referer", "google_device_combo",
        "ip_range_blocked", "bot_user_agent", "bot_detected",
        "integrity_missing", "integrity_invalid",
        "soft_pi_extra", "honeypot", "velocity_block",
        "ipqs_high_fraud", "ipqs_fraud_high", "ipqs_vpn_tor",
    }
    if rejection_code in MODER_BOT_REJECTIONS:
        reasoning = []
        # Берём топ сигнал из all_details + rejection
        sorted_details = sorted(
            [d for d in all_details if (d.get("points") or 0) > 0],
            key=lambda d: -(d.get("points") or 0),
        )[:2]
        for d in sorted_details:
            reasoning.append(
                f"{_explain_check(d.get('check', ''), d.get('reason', ''))} (+{d.get('points')} pts)"
            )
        if not reasoning:
            reasoning = [_explain_check(rejection_code, "")]
        return {
            "class": "moder_bot",
            "label": "🔴 Модер / Bot",
            "confidence": "high",
            "reasoning": reasoning,
        }

    # 2) white verdict без hard-kill = suspicious (накопилось score)
    if verdict == "white" or total >= threshold:
        # Берём топ-2 самых жирных check'а
        sorted_details = sorted(
            [d for d in all_details if (d.get("points") or 0) > 0],
            key=lambda d: -(d.get("points") or 0),
        )[:3]
        reasoning = []
        for d in sorted_details:
            reasoning.append(
                f"{_explain_check(d.get('check', ''), d.get('reason', ''))} (+{d.get('points')} pts)"
            )
        if not reasoning and rejection_code:
            reasoning = [_explain_check(rejection_code, "")]
        return {
            "class": "suspicious",
            "label": "⚠️ Подозрительный",
            "confidence": "high" if total >= threshold * 1.5 else "medium",
            "reasoning": reasoning or [f"Накоплено {total} pts (threshold {threshold})"],
        }

    # 3) grey verdict — real user. Определяем как ему доверять.
    if pi_mode == "strict":
        pi_raw = trace.get("pi_raw") or {}
        # Парсим verdict из pi_raw
        token_payload = pi_raw.get("tokenPayloadExternal", {}) if isinstance(pi_raw, dict) else {}
        device = token_payload.get("deviceIntegrity", {})
        recognition = device.get("deviceRecognitionVerdict", [])
        meets_device = "MEETS_DEVICE_INTEGRITY" in recognition or "MEETS_STRONG_INTEGRITY" in recognition
        if meets_device:
            return {
                "class": "real_verified",
                "label": "✅ Real User (Play-verified)",
                "confidence": "high",
                "reasoning": [
                    f"Strict PI: {', '.join(recognition[:2])}",
                    f"Score {total}/{threshold} — чистый",
                ],
            }
        # strict mode + grey но PI не дал DEVICE — значит pi_score=0 и без token
        return {
            "class": "real_unverified",
            "label": "⚪ Real (unverified)",
            "confidence": "low",
            "reasoning": [
                "Strict mode, но PI verdict неполный",
                f"Score {total}/{threshold}",
            ],
        }

    if pi_mode == "soft" and soft_eligible:
        geo = trace.get("geo") or {}
        country = (geo.get("country") if isinstance(geo, dict) else None) or trace.get("country", "?")
        asn = trace.get("asn", "?")
        return {
            "class": "real_mobile",
            "label": "📱 Real User (mobile carrier)",
            "confidence": "medium",
            "reasoning": [
                f"Mobile carrier verified ({country} AS{asn})",
                "Soft-PI eligible — реальный mobile-провайдер",
                f"Score {total}/{threshold} — чистый",
            ],
        }

    # 4) lenient mode или прочие grey без сильных гарантий
    return {
        "class": "real_unverified",
        "label": "⚪ Real (unverified)",
        "confidence": "low",
        "reasoning": [
            f"PI режим: {pi_mode}",
            f"Score {total}/{threshold}",
            "Без strict-PI гарантии — может быть real user, но может быть модер с perfect setup",
        ],
    }


def classify_from_log(entry: dict) -> dict:
    """Helper для классификации из raw_payload записи из БД.
    Используется UI чтобы показывать classification на старых логах
    (где enriched trace ещё не сохранён)."""
    raw = entry.get("rawPayload") or entry.get("raw_payload") or {}

    # Если classification уже есть в payload — возвращаем
    if isinstance(raw, dict) and raw.get("classification"):
        return raw["classification"]

    # Собираем trace dict из доступных полей лога
    trace = {
        "verdict": entry.get("verdict") or "",
        "rejection_code": entry.get("rejectionCode") or entry.get("rejection_code") or "",
        "score_buckets": raw.get("scoreBuckets") if isinstance(raw, dict) else None,
        "hard_kill": raw.get("hardKill") if isinstance(raw, dict) else None,
        "pi_mode": raw.get("piMode") if isinstance(raw, dict) else None,
        "soft_eligible": (raw.get("softEligible") or {}).get("ok") if isinstance(raw, dict) else None,
        "all_details": raw.get("scoringDetails") if isinstance(raw, dict) else None,
        "pi_raw": raw.get("playIntegrity") if isinstance(raw, dict) else None,
        "country": entry.get("countryCode") or entry.get("country") or "",
    }
    # Fallback: если hard_kill нет но есть rejection_code — реконструируем
    if not trace["hard_kill"] and trace["rejection_code"] and trace["verdict"] == "white":
        trace["hard_kill"] = {"code": trace["rejection_code"], "reason": ""}

    return classify_actor(trace)
