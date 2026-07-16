# Main КЛО (scoring-engine) — детальная документация

Главный оркестрационный сервер cloak-системы Kaliningrad. Python FastAPI приложение, слушает на порту `8000` (в продакшене публикуется через nginx на `api.threeamigosteam.com`, backend IP `31.76.251.103`).

**Роль в архитектуре**
1. Первичный контур скоринга запросов от Android SDK v3/v4 (endpoint `/init`).
2. Декодирование Play Integrity токенов (Google Play API).
3. `/engine/go` bounce redirect (base64-decoded target url → 302 в Keitaro клиента).
4. Хранилище конфига (apps, proxy_keys, debug_allow, blocklists).
5. Sync API для mini-серверов (`/api/sync/config` pull, `/api/sync/logs` push).
6. Backend панели администратора (`/api/apps`, `/api/dashboard`, `/api/audit`, `/api/config`).
7. Приёмник tracker-пикселя (`/api/collect`) с JS-эвристиками.

---

## 1. Установка

### 1.1. Требования

- Ubuntu 22.04 LTS, root-доступ.
- Python 3.12 (`apt install python3.12 python3.12-venv python3.12-dev`).
- Postgres 14+ (для хранения `request_logs`, `auto_banned_entries`, `reports`).
- Redis 7+ (для PI cache, instance_burnt, cloak_consumed, velocity counters, autoban).
- Nginx (upstream proxy с TLS от Let's Encrypt / Cloudflare).
- Cloudflare Worker (edge HMAC + proxy на api.threeamigosteam.com).

### 1.2. Клонирование и venv

```bash
mkdir -p /opt/main-klo && cd /opt/main-klo
git clone <repo-url> .
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` содержит (основные):
- `fastapi`, `uvicorn[standard]` — веб-фреймворк + ASGI runner.
- `sqlalchemy[asyncio]`, `asyncpg` — Postgres ORM.
- `redis[hiredis]` — async Redis клиент.
- `httpx` — async HTTP клиент (для IPinfo/IPQS/PI API).
- `google-auth`, `google-api-python-client` — Play Integrity Google API.
- `pydantic`, `python-dotenv`.

### 1.3. Переменные окружения (`.env`)

```dotenv
# Postgres
DATABASE_URL=postgresql+asyncpg://klo:PASSWORD@127.0.0.1/klo_db

# Redis
REDIS_URL=redis://127.0.0.1:6379/0

# Внешние API
IPINFO_TOKEN=8b471d08135468
IPQS_API_KEY=qtijEY4maadviEu8leT7LftvgMWxwicO

# GCP (fallback для PI — но каждой прилы своя gcp-key-<id>.json в config/)
GCP_KEY_PATH=/opt/main-klo/config/gcp-key.json

# Секреты
ADMIN_KEY=<random-hex-32>          # Защита /api/apps, /api/config, /api/audit, ...
EDGE_SECRET=                       # HMAC secret между CF Worker и origin (empty = fail-open)
TURNSTILE_SECRET=                  # CF Turnstile для /go/verify (empty = не используется)

# Rate limiter
NONCE_TTL=300                      # Play Integrity nonce TTL, sec

# CF Bans API
CF_ZONE_ID=...
CF_API_TOKEN=...
```

### 1.4. Postgres миграции

Таблицы создаются автоматически на startup через `init_db()` (SQLAlchemy `Base.metadata.create_all`). Схема — см. `db_models.py`.

```bash
sudo -u postgres createuser klo -P
sudo -u postgres createdb klo_db -O klo
```

### 1.5. systemd unit (`/etc/systemd/system/main-klo.service`)

```ini
[Unit]
Description=Main КЛО scoring-engine
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=klo
WorkingDirectory=/opt/main-klo
EnvironmentFile=/opt/main-klo/.env
ExecStart=/opt/main-klo/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now main-klo.service
journalctl -fu main-klo -n 200
```

### 1.6. Nginx front (`/etc/nginx/sites-enabled/api-threeamigosteam.conf`)

```nginx
server {
    listen 443 ssl http2;
    server_name api.threeamigosteam.com;
    ssl_certificate     /etc/letsencrypt/live/api.threeamigosteam.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.threeamigosteam.com/privkey.pem;

    client_max_body_size 128k;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # CF Worker уже прокинул cf-connecting-ip, X-Edge-Signature, X-Edge-Timestamp
    }
}
```

---

## 2. Структура директории

```
main-klo/
├── main.py                     # FastAPI entrypoint (routers + middleware)
├── config.py                   # ConfigStore (apps.json, proxy_keys.json, debug_allow.json)
├── database.py                 # SQLAlchemy engine, init_db()
├── db_models.py                # ORM: RequestLog, AutoBannedEntry, Report, BannedIP
├── models.py                   # Pydantic: EngineConfig, AppEntry, ScoringResult, ...
├── scoring_engine.py           # score_request() + score_js_metrics() (blocklist matching, PI-cache use, гео)
├── request_logger.py           # log() → Postgres + Redis PI-кеш + _sanitize_headers()
├── auto_ban.py                 # 3-tier ban store (Redis + Postgres + CF)
├── rate_limiter.py             # per-IP / per-proxy_key / per-nonce счётчики
├── honeypot_ban.py             # CF-KV поднимаемые баны (365d)
├── lists_manager.py            # Загрузка lists/*.txt (device_models_block, cities_block, ...)
├── ip_ranges.py                # Загрузка lists/ip_ranges_block.txt (CIDR)
├── classifier.py               # classify_actor() → moder_bot / suspicious / clean
├── external/
│   ├── ipinfo_client.py        # IPinfo Max API (country, asn, vpn, proxy, hosting, res_proxy, ...)
│   ├── ipqs_client.py          # IPQualityScore API (fraud_score, vpn, tor, bot_status, ...)
│   ├── play_integrity.py       # Google PI API decode
│   └── timezone_utils.py       # compare_timezones() для JS metrics
├── api/
│   ├── init_routes.py          # POST/GET /init — SDK resolve (main hot path)
│   ├── gateway.py              # GET /go — bounce redirect, GET / — legacy v2 SDK gateway
│   ├── integrity_routes.py     # POST /api/integrity/verify, GET /api/integrity/nonce
│   ├── collect_routes.py       # POST /api/collect — tracker.js JS metrics
│   ├── sync_routes.py          # GET /api/sync/config, POST /api/sync/logs — mini-clo pull/push
│   ├── apps_routes.py          # /api/apps CRUD + /panic + /health-check + /dal-check
│   ├── dashboard_routes.py     # /api/dashboard/{metrics,feed,traffic,rejections,app-stats}
│   ├── audit_routes.py         # /api/audit/logs — page-based фильтруемый feed
│   ├── config_routes.py        # /api/{config,offers,debug-allow}
│   ├── lists_routes.py         # /api/lists — CRUD blocklists
│   ├── health.py               # /api/health — простой uptime
│   ├── health_routes.py        # /api/health-ext/{ipqs,ipinfo,play_integrity,redis,postgres,cf_kv}
│   ├── auto_ban_routes.py      # /api/bans — админский UI для 3-tier ban store
│   ├── honeypot.py             # /api/honeypot — CF-KV баны
│   ├── cf_sync.py              # /api/cf — CF-KV rotation (PANIC_MODE, CLIENT_SECRET)
│   ├── reports_routes.py       # /api/reports — Docs Hub (свободные MD-отчёты)
│   ├── analytics_routes.py     # /api/analytics — pivot-запросы
│   └── gh_doc_routes.py        # /api/gh-doc — генерация MD из session state
├── config/
│   ├── apps.json               # список прил (см. §5.1)
│   ├── proxy_keys.json         # маппинг pk_... → {package_name, allowed_packages[]}
│   ├── debug_allow.json        # whitelist IP/instance (force grey, bypass всех фильтров)
│   ├── mini_server_secrets.json  # X-Sync-Secret per mini_server_id
│   ├── mobile_asn_whitelist.json # ASN мобильных операторов per country (NG/CI/SN/...)
│   ├── google_asn_blocklist.json # hard-block ASN (Google, Accenture, FTL)
│   ├── vpn_asn_blocklist.json    # hard-block ASN (M247, NordVPN, OVH, ...)
│   ├── gcp-key-<id>.json       # GCP service-account per прила (для PI decode)
│   └── gpu_model_map.json      # семейства девайсов → допустимые GPU renderers
├── lists/
│   ├── countries_block.txt
│   ├── cities_block.txt
│   ├── codenames_block.txt
│   ├── device_models_block.txt
│   ├── gpu_block.txt
│   ├── isp_block.txt
│   ├── user_agents_block.txt
│   ├── ip_ranges_block.txt     # CIDR
│   ├── tor_exits.txt           # обновляется cron'ом каждые 6ч
│   └── ...
├── templates/
│   ├── stub.html               # заглушка для /web_content без proxy_key
│   └── bounce.html             # (unused после fix9 2026-07-04, /go теперь 302)
└── tests/
```

---

## 3. `main.py` — точка входа

```python
app = FastAPI(title="API Service", version="2.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)  # OpenAPI скрыт
```

### 3.1. `lifespan` startup

1. `config_store.load()` — читает `config.json`, `offers.json`, `apps.json`, `proxy_keys.json`, `debug_allow.json`, `mobile_asn_whitelist.json`, `google_asn_blocklist.json`, `vpn_asn_blocklist.json`.
2. `init_db()` — SQLAlchemy `create_all()` (idempotent).
3. `lists_manager.load_all()` + `start_watcher(interval=5)` — файл-watcher на `lists/*.txt`, автоперечитка без рестарта.
4. `ip_range_checker.load()` — CIDR блоки в память.
5. `rate_limiter.connect()`, `honeypot_ban.connect()`, `auto_ban.connect()` — Redis singletons.
6. `play_integrity_client.init()` — сканирует `config/gcp-key*.json`, создаёт service-account credentials per проект.
7. Фоновая задача `_dlq_drain_loop()` — каждые 30s пробует переотправить проваленные CF-KV writes из dead-letter-queue.

### 3.2. Middleware (порядок применения — сверху вниз в списке = снизу вверх при выполнении)

**`AdminAuthMiddleware`** — админ-API `X-Admin-Key`. Список префиксов:
```
/api/apps, /api/config, /api/offers, /api/debug-allow, /api/lists,
/api/dashboard, /api/audit, /api/cf, /api/bans, /api/honeypot,
/api/integrity/status, /api/integrity/reload, /api/health-ext,
/api/init-trace, /api/reports, /api/gh-doc, /api/analytics
```
Без/невалидный ключ → **404** (не 403 — не палим, что путь есть).

**`EdgeAuthMiddleware`** — HMAC-SHA256 от CF Worker. Защищённые пути: `/init`, `/web_content`, `/api/collect`, `/api/integrity/verify`. Формула:
```
msg = f"{ts}|{xff}|{country}|{asn}"
sig = HMAC_SHA256(EDGE_SECRET, msg)
```
Клиент кладёт `X-Edge-Signature`, `X-Edge-Timestamp`, `X-CF-Country`, `X-CF-ASN`. Ошибка → 200 c safe URL (для `/init`) или 302 на safe (для остального). Timestamp skew > 300s → тот же результат. **Если `EDGE_SECRET` пустой — middleware пропускает всё** (phased rollout).

**`RateLimitMiddleware`** — 3-tier rate limit.
- `/api/integrity/nonce` — жёсткий 10 req/min/IP → 429.
- `/init` — 100 req/min/proxy_key → 200 c safe URL (не палим что rate-limited).
- Всё остальное — общий per-IP лимит → 302 на safe URL.
- Skip пути: `/api/health`, `/api/bans`, `/api/config`, `/api/lists`, `/api/offers`, `/api/cf/*`, `/api/dashboard`, `/api/audit`, `/api/form`, `/api/integrity/{status,reload}`, `/api/security/token`, `/api/apps`.
- `honeypot_ban.is_banned(cf_ip)` — если CF IP в CF-KV banned list → 302 на safe.

**`CORSMiddleware`** — `allow_origins=["https://threeamigosteam.com"]`.

### 3.3. Регистрация роутеров

```python
app.include_router(health_router)          # /api/health
app.include_router(health_ext_router)      # /api/health-ext/*
app.include_router(config_router)          # /api/config, /api/offers, /api/debug-allow
app.include_router(lists_router)           # /api/lists/*
app.include_router(dashboard_router)       # /api/dashboard/*
app.include_router(audit_router)           # /api/audit/logs
app.include_router(collect_router)         # /api/collect
app.include_router(cf_sync_router)         # /api/cf/*
app.include_router(sync_router)            # /api/sync/*
app.include_router(integrity_router)       # /api/integrity/{nonce,verify,status,reload}
app.include_router(apps_router)            # /api/apps CRUD
app.include_router(reports_router)         # /api/reports
app.include_router(gh_doc_router)          # /api/gh-doc
app.include_router(analytics_router)       # /api/analytics
app.include_router(honeypot_router)        # /api/honeypot
app.include_router(auto_ban_router)        # /api/bans
app.include_router(init_router)            # /init  (main hot path)
app.include_router(gateway_router)         # /, /go, /go/verify, /score-debug, /analytics/config
```

Дополнительно `/tracker.js` и `/analytics.js` — отдают минифицированный `js-scripts/tracker.min.js` с `Cache-Control: public, max-age=3600`.

---

## 4. `api/init_routes.py` — `/init` handler

Главный hot path. `~1225 строк`, из них 700+ — функция `_resolve()` c 15-шаговым pipeline.

### 4.1. Endpoint

```python
@router.get("/init")
@router.post("/init")   # POST добавлен 2026-07-09 для SDK v4 (nginx проксирует POST)
async def init_resolve(request: Request):
    proxy_key = request.headers.get("x-proxy-key", "") \
             or request.query_params.get("proxy_key", "")
    pkg, verdict, url = await _resolve(request, proxy_key)
    if pkg is None:
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    return {"url": url}
```

Возвращает **всегда 200 + JSON `{"url": "..."}`**, если prox_key валидный. Для white — safe URL, для grey — bounce URL `https://api.threeamigosteam.com/engine/go?t=<base64>`.

### 4.2. Pipeline `_resolve()` — по шагам

#### Шаг 1. Резолв proxy_key + guard cross-app leak

```python
key_data = config_store.resolve_proxy_key(proxy_key)
if not key_data:
    return None, None, None            # → 403 Unauthorized

x_app_id = request.headers.get("x-app-id", "").strip() \
        or request.query_params.get("app_id", "").strip()
allowed = key_data.get("allowed_packages") or [key_data["package_name"]]
if x_app_id:
    if x_app_id not in allowed:
        # 2026-07-15 SECURITY: cross-app leak block
        return None, None, None        # → 403
    package_name = x_app_id
else:
    package_name = key_data["package_name"]
app = config_store.get_app(package_name)
```

**Почему guard**: один `proxy_key` может обслуживать несколько прил (`allowed_packages` в `proxy_keys.json`). Раньше `X-App-Id` из SDK принимался без проверки — leaked `proxy_key` = master-key ко всем 32 прилам. Теперь X-App-Id должен быть в whitelist.

#### Шаг 2. Panic mode

```python
if app and app.panic_mode:
    return package_name, "white", app.safe_url
```

Клиент через панель (`PUT /api/apps/{id}/panic`) может мгновенно вырубить прилу.

#### Шаг 3. IP resolution + skip_internal_ip

```python
real_user_ip = request.headers.get("x-real-user-ip", "").strip()   # custom header от mini-server nginx
forwarded    = request.headers.get("x-forwarded-for", "")
real_ip      = request.headers.get("x-real-ip", "")
ip = real_user_ip or (forwarded.split(",")[0].strip() if forwarded else (
    real_ip or (request.client.host if request.client else "0.0.0.0")
))

# 2026-07-15: private-IP → skip scoring (health checks, docker bridge)
if ip.startswith(("127.", "10.", "172.16.", ..., "192.168.", "::1", "fc00:", ...)):
    return package_name, "white", app.safe_url
```

#### Шаг 4. Debug bypass (whitelist)

```python
instance_id = (request.headers.get("x-instance-id") or
               request.query_params.get("instance_id", "")).strip()
if config_store.is_debug(ip, instance_id):
    # Force grey, лог с check="debug_bypass", enrichment target_url c clickid+geo
    return package_name, "grey", "https://api.threeamigosteam.com/engine/go?t=<base64>"
```

Файл `config/debug_allow.json`:
```json
{"ips": ["37.9.54.205"], "instances": []}
```

#### Шаг 5. Auto-ban check (top-layer negative cache)

```python
if AUTOBAN_ENFORCE:
    is_banned, ban_code = await auto_ban.is_banned(ip, package_name)
    if is_banned:
        # Instant white без остальных проверок (экономит IPQS/IPinfo/PI/DB).
        # Лог с check="autoban_hit", rejection_code="autoban_hit"
        return package_name, "white", app.safe_url
```

3-tier модель: instance_burnt (Redis 24h per-instance) → auto_ban (Redis+Postgres 24h-7d per-IP) → honeypot_ban (Postgres 365d + CF KV global).

#### Шаг 6. GEO + IPQS lookup (нужны для последующих hard-kills)

```python
geo     = await ipinfo_client.lookup(ip)   # country, asn, vpn, proxy, hosting, res_proxy, tor, ...
ipqs_res = await ipqs_client.lookup(ip)     # fraud_score, vpn, proxy, tor, bot_status, ...
asn = geo.asn if geo else 0
```

#### Шаг 7. Hard-kill chain (первый match = white + AUTOBAN_SCORE)

Проверки идут строго в этом порядке (переменная `hard_kill_reason`):

1. **`instance_burnt`** — если require_pi и instance помечен burnt в Redis (сейчас **отключено** в max-conversion mode).
2. **`missing_instance_id`** — protected app без `X-Instance-Id` → manual probe.
3. **`ipqs_vpn`** (Tor unconditional) — IPQS `tor=true` для ЛЮБОЙ прилы (zero FP на Android).
4. **`geo_unknown`** — protected app + `asn=0/geo=None` (fail-closed), кроме стран в `soft_pi_countries_any_asn`.
5. **`asn_google`** — protected app + ASN ∈ `google_asn_blocklist` (Google/Accenture/FTL).
6. **`asn_vpn`** — protected app + `block_vpn_asn=True` + ASN ∈ `vpn_asn_blocklist` (M247, NordVPN, OVH, ...).
7. **`ipqs_vpn`** — protected app + `block_ipqs=True` + IPQS `vpn=true`.
8. **`ipqs_fraud`** — protected app + `block_ipqs=True` + IPQS `fraud_score ≥ 90`.

При срабатывании — лог в Postgres, вызов `auto_ban.emit()` для G1-кодов (глобальный ban) или G2 (если `AUTOBAN_G2_READY=true`). Ответ — `{"url": app.safe_url}`.

#### Шаг 8. Базовый scoring (не PI-зависимые слои)

```python
result = await scoring_engine.score_request(
    ip=ip, user_agent=user_agent, accept_language=accept_language,
    country=geo.country, city=geo.city, isp=geo.isp, asn=str(asn),
    package_name=package_name, client_secret=proxy_key,
    instance_id=instance_id, has_integrity=bool(integrity_token),
)
# result: ScoringResult(score, verdict, rejectionCode, details=[...])
```

Внутри — блок-листы (device_models, cities, codenames, gpu, isp, user_agents, tor_exits, ip_ranges, countries), IPinfo hard-kills (vpn/proxy/tor/hosting), IPinfo `res_proxy` soft (+15), IPQS tiered scoring (fraud 75-89 = +10, 90+ = +50, bot = +25, proxy = +15), lang-country mismatch soft (+20), device velocity, GPU-model mismatch, GPU rotation, WebView/OkHttp UA gate. Подробно — см. `05-filters-scoring.md`.

#### Шаг 9. PI verify mode selection

```python
if require_pi:
    soft_eligible, soft_reason = _is_soft_pi_eligible(app, geo, ipqs_res)
    pi_mode = 'soft' if soft_eligible else 'strict'
else:
    pi_mode = 'lenient'

pi_score, pi_details, pi_raw = await _verify_integrity(
    integrity_token, package_name, pi_mode,
    instance_id=instance_id, app=app,
)
```

**Три режима**:
- **`strict`** — требует `MEETS_DEVICE_INTEGRITY` + `PLAY_RECOGNIZED`. Для всех prilas с `require_integrity=True` кроме тех что попадают в Smart Soft PI (страна ∈ `soft_pi_countries` + ASN ∈ `mobile_asn_whitelist[country]` + IPinfo clean + IPQS clean).
- **`soft`** — `MEETS_BASIC_INTEGRITY` ок, `UNRECOGNIZED_VERSION` ок. Режем только `pi_virtual` / `pi_empty_soft` / `pi_basic_failed_soft`.
- **`lenient`** — старая soft-логика для прил без `require_integrity`.

**Всегда hard-kill (во всех режимах)**:
- `pi_package_mismatch` (cross-app replay).
- `pi_stale_or_future_token` (age < -5s или > 120s).
- `pi_nonce_replay` (SETNX в Redis 15s TTL, пропустимо через `app.skip_nonce_replay=True`).
- `pi_unlicensed` (reviewer flow).
- `pi_capturing` — `appAccessRiskVerdict.appsDetected` содержит CAPTURING.
- `pi_controlling` — `appsDetected` содержит CONTROLLING (Robo/UiAutomator).
- `pi_unevaluated_combo` — `deviceActivityLevel=UNEVALUATED` + `playProtectVerdict=UNEVALUATED/NO_DATA` на **первом** `/init` этого instance_id (сейчас no-op в max-conversion mode).

#### Шаг 10. Velocity check (только для require_integrity)

```python
vel_score, vel_details = await _velocity_check(ip, instance_id)
```

3 счётчика:
- `vel:inst:{instance_id}` INCR, TTL 300s, threshold **100** (было 12, отпущено в max-conversion mode).
- `vel:sub:{subnet}` SADD instance_id, TTL 900s, SCARD threshold **100** (было 15).
- `vel:ip:{ip}` INCR, TTL 300s, threshold **300** (было 60).

`_subnet_key(ip)` — `/24` для IPv4, `/64` для IPv6 (через `ipaddress` модуль, canonical).

#### Шаг 11. Soft-PI extras (для страны в `soft_pi_countries`)

- `asn_rotation` — instance_id менял ASN 2+ раз за час (residential-proxy rotation). Сейчас no-op.
- `soft_ua_emulator` — UA содержит `sdk_gphone|emulator|genymotion|aosp_atd|goldfish|ranchu` даже на mobile ASN.
- `soft_ua_google_device` — UA содержит `pixel|nexus|google sdk` в NG/CI/SN (Pixel в Лагосе редок, типично FTL/reviewer).

#### Шаг 12. Финальный вердикт + rejection_code

```python
total_score = result.score + pi_score + vel_score + extra_score
all_details = result.details + pi_details + vel_details + extra_details
threshold   = config_store.engine.scoreThreshold          # default 70
verdict     = "white" if total_score >= threshold else result.verdict

# Rejection code fallback
if not rejection and pi_score >= AUTOBAN_SCORE:
    if not integrity_token: rejection = "integrity_missing"
    # else: device_compromised — DISABLED 2026-07-15
if not rejection and vel_score >= AUTOBAN_SCORE: rejection = "velocity_block"
if not rejection and extra_score >= AUTOBAN_SCORE: rejection = "soft_pi_extra"
```

#### Шаг 13. Cloak-consumed (opt-in per-app)

```python
if app.cloak_consumed_enabled and verdict == "grey":
    consumed, meta = await _check_and_mark_cloak_consumed(instance_id, package_name, ip, verdict)
    if consumed:
        verdict = "white"
        rejection = "cloak_consumed"
```

SETNX `cloak_consumed:{pkg}:{iid}` с TTL 24h. Первый /init → grey, 2-й+ → safe. Защита от Google deep-review с реальным телефоном + Bright Data residential.

#### Шаг 14. URL selection

```python
if verdict == "white":
    url = safe_url
else:
    # 2026-07-10 P7: enrich target с clickid+geo (Keitaro attribution)
    sep = "&" if "?" in target_url else "?"
    target_url = f"{target_url}{sep}clickid={instance_id}&geo={geo_country}"
    t = base64.urlsafe_b64encode(target_url.encode()).decode()
    url = f"https://api.threeamigosteam.com/engine/go?t={t}"
```

#### Шаг 15. Log + auto_ban emit

```python
classification = classify_actor(_log_trace)                      # moder_bot / suspicious / clean
await request_logger.log(...)                                    # Postgres INSERT + Redis PI-cache
if verdict == "white" and rejection in AUTOBAN_CODES:
    await auto_ban.emit(ip, pkg_key, code=rejection, ...)
elif verdict == "grey":
    await auto_ban.mark_grey(ip, package_name)                   # negative cache 1h
```

### 4.3. Trace mode

`GET /api/init-trace?proxy_key=...` — тот же `_resolve()` c `_trace={}`, populates dict со всеми pipeline steps, но **не** пишет в `request_logger`. Используется UI-лабой тестов. Защищено `AdminAuthMiddleware`.

Ответ:
```json
{
  "verdict": "white",
  "url": "https://safe...",
  "package_name": "com.example",
  "classification": {"class": "moder_bot", "confidence": "high", "signals": [...]},
  "trace": {
    "pipeline_steps": [
      {"step": "proxy_key_lookup", "status": "passed", "reason": "package=com.example"},
      {"step": "instance_burnt", "status": "passed", "reason": ""},
      {"step": "asn_google", "status": "fired", "reason": "ASN 15169 в blocklist"}
    ],
    "ip": "...", "instance_id": "...", "geo": {...}, "ipqs": {...},
    "score_buckets": {"base": 100, "pi": 0, "vel": 0, "extra": 0, "total": 100},
    "hard_kill": {"code": "asn_google", "reason": "..."},
    "rejection_code": "asn_google",
    "all_details": [...]
  }
}
```

---

## 5. `api/gateway.py` — `/go` bounce redirect

### 5.1. `GET /go?t=<base64>` — instant 302

```python
@router.get("/go")
async def bounce_redirect(request: Request):
    t = request.query_params.get("t", "")
    if not t:
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)
    try:
        target = base64.urlsafe_b64decode(t).decode()
    except Exception:
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)
    if not target.startswith(("https://", "http://")):
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)
    return RedirectResponse(url=target, status_code=302)
```

**Fix 2026-07-04 (fix9)**: раньше отдавали Turnstile bounce страницу — Chrome CT показывал `threeamigos + капчу` для SDK v2. Теперь instant 302 на branded domain (Keitaro клиента).

### 5.2. `POST /go/verify` — legacy Turnstile гейт

Bounce-страница шлёт CF Turnstile token, мы verify через `https://challenges.cloudflare.com/turnstile/v0/siteverify`. Возвращает `{"redirect": offer_url}` или `{"redirect": safe_url}`. Fail-CLOSED на exception (P1-6 2026-06-21).

### 5.3. `GET /` — legacy v2 SDK gateway

Устаревший path для SDK v2 (до 2026-05). Читает большой набор `X-*` заголовков, вызывает `scoring_engine.score_request()`, применяет `white_flow_type` (redirect_safe / show_403 / show_404 / fake_html). Для v2-locked прил (`app.block_v2_gateway=True`) — всегда white.

---

## 6. `api/sync_routes.py` — mini-clo pull/push

### 6.1. Auth

`X-Sync-Secret` header. Список секретов — `config/mini_server_secrets.json`:
```json
{
  "sisal-football": "s3cret_sisal_...",
  "visao-total": "s3cret_visao_...",
  "stake-camnang": "s3cret_stake_..."
}
```

### 6.2. `GET /api/sync/config`

Mini-clo вытягивает конфиг. Response:
```json
{
  "version": 1721139600,
  "mini_server_id": "visao-total",
  "apps": [<app entries где mini_server_id == 'visao-total'>],
  "bans": {
    "ip_bans": [
      {"ip": "1.2.3.4", "code": "asn_google", "package_name": null, "expires_at": "..."}
    ]
  },
  "gcp_keys": {
    "total-casino-497709": "<base64(gcp-key-<id>.json)>"
  },
  "google_asn_blocklist": [15169, 16591, ...],
  "debug_allow": {"ips": [...], "instances": [...]}
}
```

Mini-clo сохраняет всё в `config/apps.json`, `config/gcp-key-<proj>.json` (chmod 600), `config/bans.json`, `config/google_asn_blocklist.json`, `config/debug_allow.json` и вызывает `config_store.reload()`.

### 6.3. `POST /api/sync/logs`

Body:
```json
{
  "logs": [
    {
      "ip": "1.2.3.4",
      "score": 100, "verdict": "white", "rejection_code": "ipinfo_vpn",
      "details": [{"check": "ipinfo_vpn", "points": 100, "reason": "..."}],
      "user_agent": "okhttp/4.12.0",
      "accept_language": "it-IT",
      "country": "IT", "country_code": "IT", "city": "Rome",
      "headers": {"x-app-id": "com.example", "source": "mini-clo", ...},
      "extra_payload": {
        "package_name": "com.example",
        "pi": {"app": "PLAY_RECOGNIZED", "device": ["MEETS_BASIC_INTEGRITY"], "license": "LICENSED"},
        "ipinfo": {...}, "ipqs": {...}
      }
    }
  ]
}
```

Reuses `request_logger.log()` — пишет в тот же Postgres `request_logs`, mini-clo клика видна в панели наравне с main КЛО.

### 6.4. `GET /api/sync/health`

Простой health для mini-clo → main КЛО (проверка связи).

---

## 7. Конфиг-файлы

### 7.1. `config/apps.json` (schema per app)

```json
{
  "id": "26e2b97b-415c-4f5f-ac40-4888c1377bcc",
  "name": "Betclic Sports",
  "package_name": "com.mazourbn.jaberbagh",
  "cert_sha256": "JLAOL7f6RW7dh0XWVahgLCjeOXExtAYf15PeSS+kcJM=",
  "gcp_project_id": "betclic-497407",
  "safe_url": "https://api-bclicsportsapp.com/betclic_matches",
  "target_url": "https://bclicsportsapp.com/hvSRX6",
  "white_flow_type": "redirect_safe",  // show_403 | show_404 | redirect_safe | fake_html
  "panic_mode": false,
  "excluded_countries": ["FR", "PL"],   // страны где отдаём safe (не таргетируем)
  "excluded_cities": [],                 // города где не режем даже если в cities_block
  "allowed_countries": [],               // если задан — оффер ТОЛЬКО из этих стран
  "disable_lang_check": false,
  "require_integrity": true,             // включает strict/soft PI + velocity + hard-kills
  "block_v2_gateway": false,             // v2 SDK path (/, /score-debug) → always white
  "soft_pi_countries": [],               // NG/CI/SN — Smart Soft PI eligibility
  "soft_pi_countries_any_asn": [],       // NG-relax: пропускать не только mobile ASN
  "block_google_asn": true,
  "block_vpn_asn": true,
  "block_pi_unevaluated_combo": true,    // hard-kill UNEVALUATED×2 на первом /init
  "block_ipqs": true,                    // hard-kill IPQS vpn/tor/fraud≥90 для protected
  "cloak_consumed_enabled": false,       // одноразовость grey per instance_id
  "skip_nonce_replay": true,             // per-app kill switch (SDK v3 Classic PI reuses nonce)
  "proxy_key": "pk_daf8bde087935e228e4289bfa9155af1",
  "auth_token": "b5f1981afbce",
  "endpoint": "",                         // brand-domain для DAL check (без слеша)
  "sdk_path": "/init",                    // path из assetlinks.json (по умолчанию /init)
  "mini_server_id": "sisal-football",     // роутинг на mini-clo (если пусто — main КЛО)
  "created_at": "2026-05-27T00:29:44.779043+00:00"
}
```

### 7.2. `config/proxy_keys.json`

```json
{
  "pk_daf8bde087935e228e4289bfa9155af1": {
    "package_name": "com.mazourbn.jaberbagh",
    "name": "Betclic Sports",
    "allowed_packages": ["com.mazourbn.jaberbagh"]
  },
  "pk_shared_snai_...": {
    "package_name": "com.snai.muslimazkarpro",
    "name": "Snai Muslim Azkar",
    "allowed_packages": [
      "com.snai.muslimazkarpro",
      "com.snai.omniconvert"
    ]
  }
}
```

**`allowed_packages`** — критично для cross-app leak protection. Один proxy_key → несколько прил, но SDK через `X-App-Id` должен указывать только одну из allowed.

### 7.3. `config/debug_allow.json`

```json
{
  "ips": ["37.9.54.205"],
  "instances": ["dev-instance-uuid-123"]
}
```

`is_debug(ip, instance_id)` → True → force grey, bypass всех фильтров. Точечная дырка под тест разработчиков. Синкается на mini-clo боксы через `/api/sync/config` (с 2026-07-14).

### 7.4. `config/mini_server_secrets.json`

```json
{
  "sisal-football": "<shared-secret-64-chars>",
  "visao-total":    "<shared-secret-64-chars>",
  "stake-camnang":  "<shared-secret-64-chars>"
}
```

Сравнивается с `X-Sync-Secret` header в `/api/sync/*`.

### 7.5. `config/gcp-key-<id>.json`

GCP service-account JSON. Для каждой прилы своя (per `gcp_project_id`). Пример:
```json
{
  "type": "service_account",
  "project_id": "total-casino-497709",
  "client_email": "playintegrity-verify@total-casino-497709.iam.gserviceaccount.com",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  ...
}
```

Права: `chmod 600`. Файл `config/gcp-key.json` без префикса — legacy fallback (нежелательно использовать).

### 7.6. `config/google_asn_blocklist.json`

```json
{
  "hard_block": [15169, 16591, 396982, 45566, ...]
}
```

Google (15169), Accenture FTL (16591), Google Cloud (396982), Google Fibre, Google servers. Срабатывает для `block_google_asn=True` (по умолчанию для всех protected прил).

### 7.7. `config/vpn_asn_blocklist.json`

```json
{
  "hard_block": [9009, 63023, 60068, 62240, 51852, ...]
}
```

M247, NordVPN, Surfshark, ExpressVPN, ProtonVPN, Vultr, OVH, Hetzner, DigitalOcean, Contabo. Срабатывает для `block_vpn_asn=True`.

### 7.8. `config/mobile_asn_whitelist.json`

```json
{
  "_comment": "Mobile carrier ASN per country для Smart Soft PI",
  "NG": [29465, 36873, 37148, 36884],   // MTN, Airtel, Globacom, 9mobile
  "CI": [24757, 37453, 33787],
  "SN": [37649, 25543, 29975]
}
```

Используется в `_is_soft_pi_eligible()`. Юзер должен быть с mobile ASN своей страны из `soft_pi_countries`.

---

## 8. Redis usage

| Ключ | TTL | Назначение |
| --- | --- | --- |
| `pi_cache:{ip}:{package_name}` | 180s | PI verdict cache (fallback после prilы, чтобы score_js_metrics видел device_compromised) |
| `pi_nonce_seen:{nonce}` | 15s | SETNX anti-replay PI токена (per-app skip через `skip_nonce_replay=True`) |
| `pi_first_init:{pkg}:{iid}` | 14 days | SETNX для gate'а UNEVALUATED combo hard-kill (сейчас no-op) |
| `instance_burnt:{pkg}:{iid}` | 24h | Instance помечен burnt (сейчас no-op в max-conversion mode) |
| `cloak_consumed:{pkg}:{iid}` | 24h | SETNX одноразовость grey verdict (opt-in per-app) |
| `asnrot:{iid}` | 1h | SADD ASN per instance (>2 разных ASN → residential proxy) |
| `vel:inst:{iid}` | 300s | INCR — велосити per instance (threshold 100) |
| `vel:sub:{subnet}` | 900s | SADD instance_id per /24 или /64 (threshold 100) |
| `vel:ip:{ip}` | 300s | INCR — велосити per IP (threshold 300) |
| `fp:{pkg}:{ip}:{model}` | 1h | SADD gpu_renderer (>1 → GPU rotation, антидетект) |
| `dfv:{pkg}:{model}:{gpu}:{build}` | 1h | INCR — per-device velocity (>30 → device_velocity) |
| `nonce:{sha256}` | 300s | Play Integrity nonce store (генерация в `/api/integrity/nonce`) |
| `autoban:{pkg}:{ip}` / `autoban:_:{ip}` | 24h-7d | 3-tier ban store (package-scoped или global) |
| `iid_state:{pkg}:{iid}` | Hash | tracker-callback cloak-bypass detection (сравнение country /init vs /collect) |
| `init_ip_recent:{pkg}:{ip}` | 10m | Correlation для tracker cloak-bypass |
| `init_subnet_recent:{pkg}:{subnet}` | 10m | Fallback correlation |

---

## 9. Postgres: `request_logs` (schema)

```sql
CREATE TABLE request_logs (
    id              UUID PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL DEFAULT now(),
    ip              VARCHAR(45),
    country         VARCHAR(100),
    country_code    VARCHAR(5),
    city            VARCHAR(200),
    device_model    VARCHAR(200),
    os              VARCHAR(100),
    user_agent      TEXT,
    score           INTEGER DEFAULT 0,
    verdict         VARCHAR(10),     -- 'grey' | 'white'
    rejection_code  VARCHAR(50),
    package_name    VARCHAR(200),
    raw_payload     JSONB DEFAULT '{}'
);
CREATE INDEX idx_timestamp_verdict ON request_logs(timestamp, verdict);
CREATE INDEX idx_ip_timestamp      ON request_logs(ip, timestamp);
CREATE INDEX idx_package_timestamp ON request_logs(package_name, timestamp);
```

### `raw_payload` (JSONB) — что кладём

```json
{
  "headers": {                          // sanitized (P1-4 2026-06-21)
    "user-agent": "okhttp/4.12.0",
    "accept-language": "it-IT",
    "x-app-id": "com.example",
    "x-instance-id": "b3f5-...",
    "x-proxy-key": "sha256:a3f5b2c1",   // sensitive → sha256[:8] hash
    "cf-ipcountry": "IT", "cf-ray": "..."
  },
  "scoringDetails": [
    {"check": "asn_google", "points": 100, "reason": "ASN 15169 в blocklist"}
  ],
  "jsMetrics": {},
  "playIntegrity": {                     // если /init декодировал PI
    "tokenPayloadExternal": {
      "requestDetails": {"requestPackageName": "com.example", "timestampMillis": "..."},
      "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "certificateSha256Digest": [...]},
      "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"]},
      "accountDetails": {"appLicensingVerdict": "LICENSED"},
      "environmentDetails": {"playProtectVerdict": "NO_ISSUES", "appAccessRiskVerdict": {...}}
    }
  },
  "scoreBuckets": {"base": 25, "pi": 0, "vel": 0, "extra": 0, "total": 25},
  "piMode": "strict",
  "softEligible": {"ok": false, "reason": "country_IT_not_in_soft"},
  "hardKill": null,                       // или {"code": "...", "reason": "..."}
  "classification": {"class": "clean", "confidence": "high", "signals": [...]},
  "ipinfo": {
    "country": "IT", "city": "Rome", "asn": 12874,
    "asn_type": "isp", "vpn": false, "proxy": false, "res_proxy": false,
    "tor": false, "relay": false, "hosting": false, "mobile": true,
    "anonymous_name": ""
  },
  "pi": {"app": "PLAY_RECOGNIZED", "device": [...], "license": "LICENSED"}  // ← alias от mini-clo
}
```

**Sanitize headers** (P1-4 2026-06-21):
- `HEADER_ALLOWLIST` — CF/geo + стандартные + наши SDK-headers (user-agent, x-app-id, x-instance-id, ...).
- `HEADER_SENSITIVE` — sha256[:8] hash (`sha256:xxxxxxxx`). Список: `x-proxy-key`, `x-client-secret`, `x-app-token`, `x-admin-key`, `x-integrity-token`, `authorization`, `cookie`, `x-csrf-token`, `x-api-key`.
- Всё остальное — дропается (privacy-by-default).

Backup leak = master-key compromise без sanitize (~5 минут exfil через `GET /api/audit/logs`).

---

## 10. Логи + мониторинг

- systemd journal: `journalctl -fu main-klo -n 500`.
- Формат: `2026-07-16 12:34:56 [init] INFO: [1.2.3.4] init: pkg=com.example asn=12874 country=IT pi_mode=strict soft=False(country_IT_not_in_soft) score=25 (base=25 pi=0 vel=0 extra=0) verdict=grey`.
- Панель `/dashboard/monitoring` — real-time метрики через `/api/dashboard/metrics`, hourly traffic через `/api/dashboard/traffic`, top rejections через `/api/dashboard/rejections`.
- Health checks: `/api/health-ext/{ipqs,ipinfo,play_integrity,redis,postgres,cf_kv}` — вручную через панель (защищено X-Admin-Key).

---

## 11. Основные fix'ы (chronological)

| Дата | Изменение |
| --- | --- |
| 2026-06-21 | P1 batch: subnet_key canonical (IPv4/24, IPv6/64), PI TTL 24h→180s, IPQS sanitize CF-ASN, sensitive headers sha256[:8], fail-closed geo_unknown для protected apps, Google ASN hard-block, VPN ASN hard-block, cloak_consumed SETNX 24h |
| 2026-06-22 | PI v3 advanced hard-kills: `pi_capturing`, `pi_controlling`, `pi_unevaluated_combo` (first_init gate). IPQS tiered (75/90). Tor unconditional. F1 EdgeAuth HMAC middleware, F2/F3 rate-limit per-key. |
| 2026-06-23 | F-vel TTL 60s→300s, F-burnt instance_burnt on pi_nonce_replay. Auto_ban 3-tier. Cloak-bypass P2 (tracker callback correlation). |
| 2026-07-04 | fix9 `/go` instant 302 (без Turnstile bounce). res_proxy soft для CGNAT countries. Mini-clo sync API. |
| 2026-07-09 | Max-conversion mode: `instance_burnt` no-op, `_is_first_init` no-op, `_asn_rotation_check` no-op, velocity thresholds 12→100, 15→100, 60→300. POST /init для SDK v4. |
| 2026-07-10 | X-App-Id override (per-instance app resolution). IPv6 nginx resolver fix. Clickid+geo enrichment target_url. skip_nonce_replay per-app flag. |
| 2026-07-14 | playIntegrity alias (pi→playIntegrity в raw_payload). PI decode always. Betclic hadyarba nginx POST splitter. Sync.py auto-reload на mini-clo. debug_allow.json sync на mini-clo. |
| 2026-07-15 | Cross-app leak fix: `allowed_packages` в proxy_keys.json + guard в `_resolve`. `device_compromised` disable (PI-cache soft-log). `skip_internal_ip` для private/docker IPs. |
