# Kaliningrad Infra — Anti-Moderation Cloak для Android Casino Apps

> **Кодовое название:** «Три Амигос» / three-amigos / Kaliningrad.
> **Технология:** Python 3.11 (FastAPI) + Nginx + Redis + Postgres + Cloudflare + Google Play Integrity.
> **Роль:** маскировка казино-affiliate трафика Android-приложений через per-request cloaking (grey/white verdict).
> **Домен ядра:** `api.threeamigosteam.com` (Cloudflare orange-cloud).
> **Продакшн эксплуатация:** ~33 приложения, ~11 mini-серверов, 2026 год.

---

## Что делает система

Kaliningrad — это **cloak-инфраструктура**, которая стоит между Android-приложениями (казино/спорт-беттинг affiliate) и конечным пользователем. Задача одна: **отличать реального игрока от Google-модератора / Play Protect-скана / автоматических Robo-crawler'ов** и на этом решении выдавать разный URL.

- **Реальный игрок (grey verdict)** → приложение открывает казино-оффер (напр. Total Casino, Snai, Betclic, Stake) через bounce-домен и Keitaro трекер.
- **Модератор / скан / VPN / эмулятор / hosting ASN / Google FTL (white verdict)** → приложение открывает «нативную заглушку»: справочник духовных вопросов, курс валют, minigame, каталог лекарств и т. п. — то, за что приложение публиковалось в Google Play.

Cloak-решение принимается на основе многослойного scoring engine:

1. **Auto-ban** (Redis negative cache — IP уже забанен).
2. **Instance-burnt** — instance_id уже палился на replay / capturing / unlicensed.
3. **IPinfo Max** — geo, ASN, VPN/proxy/residential-proxy/Tor/hosting.
4. **IPQS** — fraud score, Tor exit, bot detection.
5. **ASN блоклисты** — Google/Accenture ASN, commercial VPN, datacenter hosting.
6. **Country whitelist / excluded_countries** per app.
7. **Language–Country mismatch** (напр. VPN на IT + `Accept-Language: ru` → бан).
8. **Google Play Integrity** — DEVICE / BASIC / PLAY_RECOGNIZED / UNLICENSED / apps_detected (CAPTURING/CONTROLLING) / nonce replay / freshness.
9. **Velocity checks** — burst per instance / per /24 (или /64 IPv6) / per IP.
10. **Soft-PI extras** для стран без стабильного PI (NG/CI/SN) — ASN rotation, эмулятор UA, Pixel-в-Лагосе.
11. **cloak_consumed** — одноразовая выдача grey per instance_id за 24 часа (защита от deep-review с реальным телефоном + BrightData residential).

Каждый /init логируется в Postgres (`request_logs`) со всеми деталями (score buckets, hard_kill code, PI raw verdict, IPinfo/IPQS flags, classification) — админ-панель отображает журнал в реальном времени.

---

## Repo structure

```
/tmp/kaliningrad-infra/
├── README.md                       # ← этот файл (overview)
├── .gitignore                      # Python/Node artifacts + backups
├── docs/
│   ├── 01-architecture.md          # Детальная архитектура (data flow + компоненты)
│   ├── 02-deployment.md            # (будущий) Deploy runbook
│   ├── 03-config.md                # (будущий) apps.json / proxy_keys.json / debug_allow.json
│   └── 04-troubleshooting.md       # (будущий) Типовые падения и fix'ы
├── main-klo/                       # ГЛАВНЫЙ КЛО — 31.76.251.103, api.threeamigosteam.com
│   ├── main.py                     # FastAPI entry (lifespan, middleware, router include)
│   ├── config.py                   # ConfigStore: apps.json + proxy_keys.json + debug_allow.json + ASN блоклисты
│   ├── database.py                 # SQLAlchemy async engine (Postgres)
│   ├── db_models.py                # RequestLog, AutoBan, HoneypotBan, IntegrityCache
│   ├── models.py                   # Pydantic: EngineConfig, OfferConfig, AppEntry, ScoringResult
│   ├── scoring_engine.py           # score_request() — базовый скоринг (list filters, honeypot, UA/lang)
│   ├── request_logger.py           # RequestLogger — batched DB writes + PI cache
│   ├── rate_limiter.py             # Redis rate-limit (per-IP + per-proxy-key + per-nonce)
│   ├── auto_ban.py                 # AutoBan — banlist в Redis + CF KV DLQ + emit hook
│   ├── honeypot_ban.py             # Trigger from tracker.js honeypot form submits
│   ├── classifier.py               # classify_actor() — bucket: reviewer/scanner/bot/user
│   ├── api/
│   │   ├── init_routes.py          # /init POST+GET (main flow) — 1225 строк
│   │   ├── integrity_routes.py     # /api/integrity/nonce + /api/integrity/verify (PI JWE decode)
│   │   ├── sync_routes.py          # /api/sync/config + /api/sync/logs (для mini-clo)
│   │   ├── gateway.py              # /go bounce redirect + /go/verify Turnstile + legacy /
│   │   ├── collect_routes.py       # /api/collect tracker.js pixel
│   │   ├── dashboard_routes.py     # /api/dashboard/* (панель — метрики, feed)
│   │   ├── audit_routes.py         # /api/audit/* (журнал кликов)
│   │   ├── apps_routes.py          # /api/apps/* (CRUD приложений)
│   │   ├── config_routes.py        # /api/config/* + /api/debug-allow/*
│   │   ├── analytics_routes.py     # /api/analytics/* (агрегаты)
│   │   ├── cf_sync.py              # /api/cf/sync (CF KV writes)
│   │   ├── health.py, health_routes.py, honeypot.py, auto_ban_routes.py …
│   ├── external/
│   │   ├── play_integrity.py       # Google PI API client (JWE decode + verdict parser)
│   │   ├── ipinfo_client.py        # IPinfo Max API (+ 24h Redis cache)
│   │   └── ipqs_client.py          # IPQS API (+ Redis cache)
│   ├── lists/                      # Blocklists (updated by lists_manager watcher)
│   │   ├── cities_block.txt
│   │   ├── codenames_block.txt
│   │   ├── countries_block.txt
│   │   ├── device_models_block.txt
│   │   └── ip_ranges_block.txt
│   ├── config/
│   │   ├── apps.json               # 33 приложения (target/safe URL, proxy_key, флаги)
│   │   ├── proxy_keys.json         # {proxy_key: {package_name, name, allowed_packages}}
│   │   ├── debug_allow.json        # {ips: [], instances: []} — force grey bypass
│   │   ├── mini_server_secrets.json  # {mini_server_id: shared_secret} для /api/sync/*
│   │   ├── google_asn_blocklist.json # hard-block Google/Accenture/Firebase Test Lab ASN
│   │   ├── vpn_asn_blocklist.json    # M247, NordVPN, Vultr, OVH, Hetzner, …
│   │   ├── mobile_asn_whitelist.json # per-country whitelist для soft-PI режима (NG/CI/SN)
│   │   └── gcp-key-*.json          # GCP service account keys для PI decode
│   └── templates/
│       ├── stub.html               # Fake HTML для web_content без proxy_key
│       └── bounce.html             # Turnstile bounce страница
├── mini-server-visao/              # MINI-SERVER TYPE C — 38.244.152.11, totalsupergame.com
│   │                               # (образец Type C — local mini-clo + Next.js landing)
│   │                               # Приложение: com.CauHoiViSao.ViSao (spirit-questions fronting Total Casino)
│   ├── mini-clo/                   # Local scoring engine :8100
│   │   ├── main.py                 # FastAPI на :8100, initial_sync + PI init + log_shipper task
│   │   ├── init_routes.py          # /init + /web_content (subset main-КЛО flow, без PI глобального cache)
│   │   ├── config.py               # ConfigStore + is_debug (читает синканный apps.json)
│   │   ├── sync.py                 # pull /api/sync/config (apps + gcp_keys + bans + debug_allow)
│   │   ├── log_shipper.py          # push /api/sync/logs (batch 30s / 100-queue-threshold)
│   │   ├── redis_client.py         # Redis для burnt/velocity/cloak_consumed/auto_ban
│   │   ├── models.py               # ScoringResult, ScoringDetail (mini-версия)
│   │   ├── constants.py            # check_lang_country_mismatch + language maps
│   │   ├── external/
│   │   │   ├── play_integrity.py   # Google PI decode (использует локально засинканные GCP keys)
│   │   │   ├── ipinfo_client.py    # IPinfo Max (server-to-server)
│   │   │   └── ipqs_client.py      # IPQS (server-to-server)
│   │   ├── config/                 # (synced из main КЛО каждые ~15 мин)
│   │   │   ├── apps.json           # Только apps c mini_server_id == "total-casino-2"
│   │   │   ├── bans.json           # ip_bans list
│   │   │   ├── debug_allow.json
│   │   │   ├── google_asn_blocklist.json
│   │   │   ├── gcp-key-totalcasino-visao.json
│   │   │   ├── mini_server_secret  # shared secret для /api/sync/*
│   │   │   ├── sync_url            # https://api.threeamigosteam.com
│   │   │   └── sync_state.json     # {version, last_sync_ts}
│   │   └── requirements.txt        # fastapi, uvicorn, httpx, redis, google-*, cryptography
│   ├── nginx/
│   │   ├── nginx.conf              # base config + visao_trace log format
│   │   ├── sites-enabled__total-casino.conf   # SDK splitter (okhttp → 418 → :8100)
│   │   └── cloudflare-realip.conf  # CF IP ranges → set_real_ip_from
│   └── systemd/
│       └── mini-clo.service        # uvicorn main:app --host 127.0.0.1 --port 8100
```

---

## Quick start (deployment summary)

### Main КЛО (31.76.251.103)

```bash
# Prereqs: Ubuntu 22.04, Python 3.11, Postgres 15, Redis 7, Nginx 1.24
apt install python3.11-venv postgresql redis-server nginx

# Deploy code (as root)
cd /opt && git clone <repo> kaliningrad && cd kaliningrad/main-klo
python3.11 -m venv venv && ./venv/bin/pip install -r requirements.txt

# Env (в /etc/systemd/system/kaliningrad.service EnvironmentFile)
DATABASE_URL=postgresql+asyncpg://kalin:xxx@127.0.0.1/kaliningrad
REDIS_URL=redis://127.0.0.1:6379/0
IPINFO_TOKEN=8b471d08135468
IPQS_API_KEY=qtijEY4maadviEu8leT7LftvgMWxwicO
ADMIN_KEY=<random-secret>                 # X-Admin-Key для панели
EDGE_SECRET=<random-hex>                   # CF Worker HMAC (пока fail-open)

# Postgres init
sudo -u postgres createdb kaliningrad
sudo -u postgres psql -c "CREATE USER kalin WITH PASSWORD 'xxx';"
sudo -u postgres psql -c "GRANT ALL ON DATABASE kaliningrad TO kalin;"
# main.py :: init_db() автоматом создаст таблицы на первом старте

# Nginx (443 → 127.0.0.1:8000 uvicorn)
# CF proxy on: api.threeamigosteam.com → origin

systemctl start kaliningrad
systemctl enable kaliningrad
```

### Mini-server (Type C — ViSao example)

```bash
# На боксе 38.244.152.11 (Ubuntu 22.04)
apt install python3.11-venv nginx redis-server nodejs

# 1. Landing (Next.js 15) на :3000 через pm2 или systemd. Домен: totalsupergame.com

# 2. Mini-clo на :8100
mkdir -p /opt/mini-clo && cd /opt/mini-clo
git checkout mini-server-visao/mini-clo/ .
python3.11 -m venv venv && ./venv/bin/pip install -r requirements.txt

# 3. Secrets
echo -n "https://api.threeamigosteam.com" > config/sync_url
echo -n "<shared-secret-из-main-mini_server_secrets.json>" > config/mini_server_secret
chmod 600 config/mini_server_secret

# 4. Systemd
cp systemd/mini-clo.service /etc/systemd/system/
systemctl enable --now mini-clo

# 5. Nginx splitter
cp nginx/sites-enabled__total-casino.conf /etc/nginx/sites-enabled/total-casino
cp nginx/cloudflare-realip.conf /etc/nginx/snippets/
certbot --nginx -d totalsupergame.com   # LE cert
nginx -t && systemctl reload nginx

# 6. Verify
curl -s https://totalsupergame.com/game -H 'User-Agent: okhttp/4.9' -H 'X-App-Id: com.CauHoiViSao.ViSao' -H 'X-Sid: <auth_token>'
# → {"url": "https://api.threeamigosteam.com/engine/go?t=..."}   (grey verdict)
```

---

## Ссылки на документацию

- **[docs/01-architecture.md](docs/01-architecture.md)** — детальная архитектура (data flow, 3 типа mini-server, роли, компоненты).
- **docs/02-deployment.md** — deploy runbook (TBD).
- **docs/03-config.md** — формат `apps.json`, `proxy_keys.json`, `debug_allow.json`, `mini_server_secrets.json` (TBD).
- **docs/04-troubleshooting.md** — типовые падения (nginx IPv6, cross-app leak, PI decode timeout, sync gotchas) (TBD).

---

## Архитектурная диаграмма (ASCII)

```
                     ┌───────────────────────────────────────────────────┐
                     │  Android APK  (SDK v3/v4, Kotlin AppClient.kt)   │
                     │  UA = okhttp/4.x                                  │
                     │  Headers: X-App-Id, X-Sid, X-Instance-Id,         │
                     │           X-Integrity-Token, X-Proxy-Key          │
                     └───────────────────┬───────────────────────────────┘
                                         │  POST/GET <mini-domain>/<path>
                                         │  (напр. totalsupergame.com/game)
                                         ▼
       ┌───────────────────────────────────────────────────────────────────┐
       │                Cloudflare Edge (orange-cloud)                    │
       │  DDoS, WAF, TLS termination, CF-Connecting-IP inject             │
       └───────────────────┬───────────────────────────────────────────────┘
                           │
                           ▼
       ┌─────────────────────────────────────────────────────────────────────┐
       │           Mini-server (11 боксов, 3 типа: A / B / C)               │
       │  Nginx UA-splitter: если okhttp → return 418 → error_page @sdk     │
       │                     если browser → landing на :3000 (Next.js)      │
       │                                                                     │
       │  Type A: Docker Next.js + src/middleware.ts (matcher)              │
       │  Type B: bare-node clo-mw.js на :3101 (systemd <brand>-clo.svc)    │
       │  Type C: local mini-clo FastAPI на :8100 (свой scoring)  ← ViSao   │
       └──────┬───────────────────────────────────────┬─────────────────────┘
              │ Type A/B: proxy → main КЛО            │ Type C: proxy → :8100
              │                                        │
              ▼                                        ▼
   ┌────────────────────────────────┐   ┌──────────────────────────────────┐
   │   Main КЛО  (FastAPI)          │   │   Mini-clo (FastAPI, :8100)     │
   │   api.threeamigosteam.com       │◄──┤   /init, /web_content            │
   │   31.76.251.103                 │   │   local scoring (subset)         │
   │                                 │   │                                  │
   │   /init  (POST+GET)             │   │   ── config sync ──►             │
   │   /web_content                  │   │   GET /api/sync/config           │
   │   /go?t=<b64>   bounce          │   │   (apps + gcp_keys + bans        │
   │   /go/verify   Turnstile        │   │    + google_asn + debug_allow)   │
   │   /api/sync/config              │   │                                  │
   │   /api/sync/logs                │   │   ── log ship ──►                │
   │   /api/collect  (tracker.js)    │   │   POST /api/sync/logs (batch 30s)│
   │   /api/dashboard/*              │   └──────────────────────────────────┘
   │   /api/audit/*                  │
   │   /api/apps/*                   │           Внешние сервисы (server-to-server)
   │   …                             │           ┌────────────────────────────────┐
   │                                 │──────────►│  Google Play Integrity API    │
   │  Scoring layers:                │           │  (JWE decode, verdict parse)  │
   │   1. auto_ban                   │           ├────────────────────────────────┤
   │   2. instance_burnt             │──────────►│  IPinfo Max (geo/asn/vpn)    │
   │   3. IPinfo hard-kills          │           ├────────────────────────────────┤
   │   4. IPQS hard-kills            │──────────►│  IPQS (fraud/tor/bot)         │
   │   5. ASN blocklists             │           ├────────────────────────────────┤
   │   6. lang-country mismatch      │──────────►│  Cloudflare KV (auto_ban DLQ) │
   │   7. Play Integrity verify      │           └────────────────────────────────┘
   │   8. velocity checks            │
   │   9. Soft-PI extras             │
   │  10. cloak_consumed             │
   └────────┬────────────────────────┘
            │
            │ Postgres write (request_logs, auto_bans, ...)
            ▼
   ┌────────────────────────────┐
   │  Postgres (kaliningrad)    │──── ← Admin Panel (Next.js) читает через /api/dashboard, /api/audit
   │  Redis (bans/velocity/PI)  │
   └────────────────────────────┘

              GREY verdict flow                              WHITE verdict flow
   ─────────────────────────────────                ─────────────────────────────────
   Response: {"url": "https://api.threeamigosteam    Response: {"url": "https://safe-app-domain/
              .com/engine/go?t=<b64(target?clickid              нативная-заглушка"}
              =<inst>&geo=<cc>)>"}
              ↓
   APK Chrome CustomTab открывает                    APK Chrome CustomTab открывает
              ↓                                                 ↓
   Main КЛО /go 302 → decoded target                Native stub (курс валют, справочник,
              ↓                                       minigame и т. п.) — то, ЗА ЧТО прила
   Keitaro (клиент): stksprapp / sportvalyellowapp    была одобрена в Google Play
              ↓
   Casino (Total Casino / Snai / Stake / …)
```

---

## Contact / hand-off

Живая инфра-документация клиента (пароли, IP-адреса всех mini-серверов, CF API token) — **не** в этом репозитории; см. отдельный `infra-access` документ у product owner'a.

Модификации 2026-07 (max-conversion mode, PI decode always, xappid guard, cross-app leak fix) — см. отдельные session memory файлы (не переносить в публичные docs).
