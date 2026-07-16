# P1-7 (2026-06-21): allowlist для honeypot — IP/CIDR которые НИКОГДА не банятся.
# Защита от: (a) insider XFF spoof для бана payment processors / админов / конкурентов;
# (b) self-ban нашего инфра IP; (c) Google crawlers helpful traffic.
import ipaddress
import logging

logger = logging.getLogger("honeypot_allowlist")

# Наши VPS — никогда не банить (self-ban prevention)
_OUR_VPS_IPS = {
    "31.76.251.103",       # Gateway
    "152.42.191.74",       # Stake
    "206.189.39.197",      # Betsson
    "139.59.236.2",        # Betclic-main
    "168.144.134.51",      # Betclic-new
    "159.223.55.25",       # Total LamDep
    "178.128.18.70",       # Total gesr
    "157.230.244.37",      # Sisal
    "146.190.109.158",     # дополнительный (из panel/deployments.json)
    "149.33.31.250",       # дополнительный
}

# Google crawlers + Cloud (опубликованы Google).
# Не банить если случайно дошёл legitimate bot/crawler.
_GOOGLE_CIDRS = [
    # Googlebot: https://developers.google.com/search/apis/ipranges/googlebot.json
    "66.249.64.0/19",
    "66.249.66.0/27",
    "66.249.92.0/22",
    # Special crawlers (AdsBot, etc.): https://developers.google.com/search/apis/ipranges/special-crawlers.json
    "64.233.160.0/19",
    "66.102.0.0/20",
    # Google Cloud — общие диапазоны (subset, full list через _cloud.json)
    "34.0.0.0/8",
    "35.190.0.0/16",
]

# UptimeRobot — monitoring (опубликован)
_UPTIME_ROBOT_IPS = [
    "63.143.42.242/32", "63.143.42.243/32", "63.143.42.244/32",
    "69.162.124.226/32", "69.162.124.227/32",
    "216.245.221.82/32", "216.245.221.83/32", "216.245.221.84/32",
]

# Stripe — webhook IPs (опубликовано). Защищает revenue если случайно
# их кто-то заспуфит на honeypot.
_STRIPE_CIDRS = [
    "3.18.12.63/32", "3.130.192.231/32",
    "13.235.14.237/32", "13.235.122.149/32",
    "18.211.135.69/32", "35.154.171.200/32",
    "52.15.183.38/32", "54.88.130.119/32",
    "54.88.130.237/32", "54.187.174.169/32",
    "54.187.205.235/32", "54.187.216.72/32",
]

# Cloudflare IPs (наши собственные edge) — на случай если CF Worker когда-то
# через что-то пройдёт сам себя. Используется тот же список что в nginx allow.
_CLOUDFLARE_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# Pre-compute networks для быстрого membership check
_ALLOWED_NETWORKS = []
for cidr_list in (_GOOGLE_CIDRS, _UPTIME_ROBOT_IPS, _STRIPE_CIDRS, _CLOUDFLARE_CIDRS):
    for c in cidr_list:
        try:
            _ALLOWED_NETWORKS.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            logger.warning(f"Invalid CIDR in allowlist: {c}")


def is_allowlisted(ip: str) -> tuple[bool, str]:
    """Возвращает (allowed, reason). allowed=True означает 'не банить'.
    reason — короткая причина для логов."""
    if not ip:
        return True, "empty_ip"
    if ip in _OUR_VPS_IPS:
        return True, "our_vps"
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False, "invalid_ip"
    for net in _ALLOWED_NETWORKS:
        if addr in net:
            return True, f"in_{net}"
    return False, "not_allowlisted"


_BOT_UA_MARKERS = (
    "curl/", "wget/", "python-requests/", "go-http-client/",
    "scrapy", "masscan", "nmap", "nuclei", "zgrab", "okhttp/",
    "libwww-perl", "httpie/", "axios/", "node-fetch",
)


def is_bot_signal(request) -> bool:
    """P1-7: True если запрос явно автоматизирован (по UA + accept headers).
    Используется в honeypot trap() — если НЕ bot, отдаём silent 404 без ban.
    Это смягчает Google ML 'evasive cloaker' флаг (раньше отвечали 200 + ban
    даже если honest crawler случайно зашёл)."""
    ua = (request.headers.get("user-agent", "") or "").lower()
    accept = (request.headers.get("accept", "") or "").lower()
    accept_lang = request.headers.get("accept-language", "")
    accept_enc = request.headers.get("accept-encoding", "")

    # Явные bot markers в UA
    if any(m in ua for m in _BOT_UA_MARKERS):
        return True
    # Пустой UA
    if not ua:
        return True
    # Browser-like UA но без Accept-Language И Accept-Encoding — нетипично
    if not accept_lang and not accept_enc:
        return True
    # accept = "*/*" + нет accept-language — типичный curl/script signature
    if accept == "*/*" and not accept_lang:
        return True
    return False
