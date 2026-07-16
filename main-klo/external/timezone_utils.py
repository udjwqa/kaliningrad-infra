from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger("timezone_utils")

TIMEZONE_OFFSETS = {
    "Africa/Abidjan": 0, "Africa/Cairo": 2, "Africa/Johannesburg": 2,
    "Africa/Lagos": 1, "Africa/Nairobi": 3,
    "America/Anchorage": -9, "America/Argentina/Buenos_Aires": -3,
    "America/Bogota": -5, "America/Chicago": -6, "America/Denver": -7,
    "America/Halifax": -4, "America/Lima": -5, "America/Los_Angeles": -8,
    "America/Mexico_City": -6, "America/New_York": -5, "America/Phoenix": -7,
    "America/Santiago": -4, "America/Sao_Paulo": -3, "America/Toronto": -5,
    "America/Vancouver": -8,
    "Asia/Almaty": 6, "Asia/Baghdad": 3, "Asia/Baku": 4,
    "Asia/Bangkok": 7, "Asia/Calcutta": 5.5, "Asia/Colombo": 5.5,
    "Asia/Dhaka": 6, "Asia/Dubai": 4, "Asia/Ho_Chi_Minh": 7,
    "Asia/Hong_Kong": 8, "Asia/Irkutsk": 8, "Asia/Istanbul": 3,
    "Asia/Jakarta": 7, "Asia/Karachi": 5, "Asia/Kolkata": 5.5,
    "Asia/Krasnoyarsk": 7, "Asia/Kuala_Lumpur": 8, "Asia/Manila": 8,
    "Asia/Novosibirsk": 7, "Asia/Riyadh": 3, "Asia/Seoul": 9,
    "Asia/Shanghai": 8, "Asia/Singapore": 8, "Asia/Taipei": 8,
    "Asia/Tashkent": 5, "Asia/Tehran": 3.5, "Asia/Tokyo": 9,
    "Asia/Vladivostok": 10, "Asia/Yekaterinburg": 5,
    "Atlantic/Reykjavik": 0,
    "Australia/Melbourne": 10, "Australia/Perth": 8, "Australia/Sydney": 10,
    "Europe/Amsterdam": 1, "Europe/Athens": 2, "Europe/Berlin": 1,
    "Europe/Brussels": 1, "Europe/Bucharest": 2, "Europe/Budapest": 1,
    "Europe/Dublin": 0, "Europe/Helsinki": 2, "Europe/Kiev": 2,
    "Europe/Lisbon": 0, "Europe/London": 0, "Europe/Madrid": 1,
    "Europe/Minsk": 3, "Europe/Moscow": 3, "Europe/Oslo": 1,
    "Europe/Paris": 1, "Europe/Prague": 1, "Europe/Rome": 1,
    "Europe/Samara": 4, "Europe/Stockholm": 1, "Europe/Vienna": 1,
    "Europe/Vilnius": 2, "Europe/Warsaw": 1, "Europe/Zurich": 1,
    "Pacific/Auckland": 12, "Pacific/Honolulu": -10,
    "Etc/UTC": 0, "Etc/GMT": 0, "UTC": 0,
    "US/Eastern": -5, "US/Central": -6, "US/Mountain": -7, "US/Pacific": -8,
}


def get_utc_offset(tz_name: str) -> float:
    if not tz_name:
        return 0.0

    if tz_name in TIMEZONE_OFFSETS:
        return TIMEZONE_OFFSETS[tz_name]

    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(tz_name)
        now = datetime.now(tz)
        offset_seconds = now.utcoffset().total_seconds()
        return offset_seconds / 3600
    except Exception:
        pass

    for key, val in TIMEZONE_OFFSETS.items():
        if tz_name.lower() in key.lower() or key.lower() in tz_name.lower():
            return val

    return 0.0


def compare_timezones(js_tz: str, ip_tz: str) -> float:
    if not js_tz or not ip_tz:
        return 0.0

    js_offset = get_utc_offset(js_tz)
    ip_offset = get_utc_offset(ip_tz)
    diff = abs(js_offset - ip_offset)

    logger.debug(
        f"TZ compare: js={js_tz}(UTC{js_offset:+.1f}) vs ip={ip_tz}(UTC{ip_offset:+.1f}) → diff={diff:.1f}h"
    )
    return diff
