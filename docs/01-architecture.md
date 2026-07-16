# 01 — Архитектура Kaliningrad

> **Читатель:** новый разработчик, впервые видящий проект. Здесь — полный data flow /init запроса, все компоненты, деплой-топология.
> **Родительский документ:** [../README.md](../README.md).

## Содержание

1. [Общая карта: APK → Cloudflare → mini-server → main КЛО → Keitaro → казино](#1-общая-карта)
2. [Три типа mini-server (A / B / C) — где какой](#2-три-типа-mini-server-a--b--c)
3. [Роль main КЛО](#3-роль-main-кло)
4. [Роль mini-server](#4-роль-mini-server)
5. [Data flow: `/init` от запроса до verdict](#5-data-flow-init-от-запроса-до-verdict)
6. [Список компонентов](#6-список-компонентов)
7. [Диаграмма БД + Redis-ключи](#7-диаграмма-бд--redis-ключи)

---

## 1. Общая карта

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                Android APK                                       │
│  • SDK v3 (GET ?app_id=…&sid=…&instance_id=…&integrity_token=…)                │
│  • SDK v4 (POST c body + X-App-Id / X-Sid / X-Instance-Id / X-Integrity-Token) │
│  • UA = okhttp/4.9 (маркер что запрос из приложения, не браузер)               │
│  • Проверяет: `X-App-Id` в headers, `X-Sid` = auth_token, PI token из Google   │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       │ HTTPS
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Cloudflare Edge (все mini-server домены + api.threeamigosteam.com)             │
│  • DDoS/L7 protection, WAF                                                       │
│  • TLS termination                                                               │
│  • CF-Connecting-IP inject (реальный client IP)                                 │
│  • CF-IPCountry / CF-ASN inject (fallback если origin не разрезолвит)          │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│           Mini-server (11 боксов, покупаются под каждую прилу отдельно)         │
│                                                                                  │
│  Домены: totalsupergame.com, supercastotalgame.com, asportvalsisapp.com,        │
│           attlgameapp.com, btsnfitapp.com, api-stkapp.com, sportsaredsapp.com,  │
│           bclicsportsapp.com, agamecasualapp.com, footballapisnai, …            │
│                                                                                  │
│  Nginx (SDK-splitter):                                                          │
│    location = /<sdk-path>  →  if $http_user_agent ~* "okhttp" { return 418; } │
│                                error_page 418 = @sdk_proxy                     │
│                                (иначе — landing на Next.js :3000)              │
│                                                                                  │
│  Landing (Next.js 15) на :3000:                                                 │
│    • Real content: духовный справочник / курс валют / minigame / каталог        │
│      лекарств — то, за что приложение опубликовалось в Google Play              │
│    • Обрабатывает Deep App Links (assetlinks.json)                              │
│    • Обслуживает браузерный трафик (модератор откроет URL в браузере — увидит   │
│      настоящий сайт)                                                             │
│                                                                                  │
│  Type A/B: sdk_proxy → main КЛО /engine/init через proxy_pass                   │
│  Type C:   sdk_proxy → local :8100 mini-clo (собственный scoring)               │
└───────────────┬───────────────────────────────────────┬─────────────────────────┘
                │                                        │
                │ Type A/B                              │ Type C (ViSao, ThaiCucQuyen,
                │ (Sisal, Stake, Betclic, Betsson,       │  Snai, Sisal Football, Betsson,
                │  gesr, LamDep, Stake-old)              │  Olimpbet)
                ▼                                        ▼
    ┌───────────────────────────┐         ┌────────────────────────────────┐
    │  Main КЛО — FastAPI        │         │  Mini-clo — FastAPI :8100      │
    │  api.threeamigosteam.com   │◄────────┤  Local scoring engine          │
    │  31.76.251.103             │  logs   │                                 │
    │                            │         │  Sync (pull):                   │
    │  Handles ALL scoring       │         │    GET /api/sync/config        │
    │                            │         │    → apps.json (filtered)      │
    │                            │         │    + GCP keys (base64)         │
    │                            │         │    + bans.json                 │
    │                            │         │    + google_asn_blocklist      │
    │                            │         │    + debug_allow.json          │
    │                            │         │  (первый запуск = blocking,    │
    │                            │         │   потом периодически по timer) │
    │                            │         │                                 │
    │                            │  logs   │  Log shipping (push):          │
    │                            │◄────────┤    POST /api/sync/logs         │
    │                            │  batch  │    (30-сек batch, до 100 в     │
    │                            │         │     очереди, fail → pending    │
    │                            │         │     .jsonl → retry)            │
    └────────┬───────────────────┘         └────────────────────────────────┘
             │
             │ Postgres (RequestLog) + Redis (bans/velocity/PI-cache/burnt/consumed)
             ▼
    ┌──────────────────────────────────┐
    │  Admin Panel  (Next.js Vercel)   │
    │  panel.threeamigosteam.com        │
    │  ────────────────────────────    │
    │  GET /api/dashboard  → метрики   │
    │  GET /api/audit      → журнал    │
    │  POST /api/apps      → CRUD      │
    │  X-Admin-Key header (secret)     │
    └──────────────────────────────────┘

        Grey verdict → Response { "url": "https://api.threeamigosteam.com/engine/go?t=<b64>" }
                        APK открывает через Chrome CustomTab
                        → main КЛО /go 302 → decoded target (?clickid=<inst>&geo=<cc>)
                        → Keitaro трекер клиента (stksprapp, sportvalyellowapp, …)
                        → казино (Total Casino / Snai / Stake / Betclic / …)

        White verdict → Response { "url": "https://safe-domain.com/native-stub-path" }
                        APK открывает нативную заглушку (тот самый духовный
                        справочник / курс валют / minigame), Google модератор
                        видит легитимный контент.
```

---

## 2. Три типа mini-server (A / B / C)

Kaliningrad эволюционировал через **три поколения архитектуры**. Одновременно в продакшне все три:

### Type A — Docker Next.js + `src/middleware.ts`

- **Стек:** Docker-контейнер, Next.js 15, `src/middleware.ts` (Edge middleware) с matcher на v3-путь (`/sports`, `/game`, `/football_data`).
- **Роль middleware:** извлекает `app_id + sid` из query/headers, дёргает main КЛО `/engine/init` с `X-Proxy-Key`, отдаёт 302 на полученный `url`.
- **Nginx:** `proxy_pass http://127.0.0.1:3000` для всех путей.
- **Кто:** Sisal (asportvalsisapp.com), TC-gesr (agamecasualapp.com), Stake (api-stkapp.com), Betclic (bclicsportsapp.com).
- **Плюсы:** landing + splitter в одном процессе, минимум moving parts.
- **Минусы:** cold restarts Next.js могут дать 502 на 1-2 sec; SDK v4 POST плохо переваривался middleware (см. `todo-middleware-v4-fix.md`).

### Type B — Sidecar `clo-mw.js` на :3101

- **Стек:** отдельный Node.js процесс (`<brand>-clo.service` systemd), не связан с landing.
- **Роль:** реализует то же что Type A middleware, но как отдельный HTTP-сервер на 127.0.0.1:3101.
- **Nginx:** SDK-путь → `proxy_pass http://127.0.0.1:3101`, остальное → `:3000` (Next.js).
- **Кто:** Betsson (btsnfitapp.com), TC-LamDep (attlgameapp.com — viso-clo).
- **Плюсы:** независимые релизы splitter и landing; проще дебажить.
- **Минусы:** ещё один systemd unit на боксе; env-переменные надо синкать (CLO_BACKEND, CLO_PROXY_KEY, CLO_APP_TOKEN, CLO_SAFE_URL).

### Type C — Local mini-clo FastAPI на :8100 (собственный scoring)

- **Стек:** Python 3.11, FastAPI, uvicorn на 127.0.0.1:8100 (`mini-clo.service`).
- **Роль:** **самодостаточный scoring engine**. Читает синканный apps.json, делает Google PI decode локально (нужен GCP key), IPinfo/IPQS server-to-server, verdict → response. Main КЛО дёргается **только** для config sync (pull) и log shipping (push) — оба вне hot path.
- **Nginx:** SDK-путь → `proxy_pass http://127.0.0.1:8100` (после UA-split на 418).
- **Кто:** ViSao (totalsupergame.com), ThaiCucQuyen (supercastotalgame.com), Snai (149.33.29.82 / footballapisnai), Sisal Football (38.180.224.3), Betsson (38.180.74.83), Olimpbet (149.33.0.240).
- **Плюсы:**
  - **Latency:** нет round-trip main КЛО → mini-clo → PI → back. Всё локально.
  - **Отказоустойчивость:** если main КЛО падает — mini-clo продолжает скорить (cached config).
  - **Client IP:** не теряется в цепочке proxy (nginx → main-КЛО через CF → …). У Type C client IP приходит прямо в `$remote_addr`.
- **Минусы:**
  - **Config sync gotchas:** apps.json пустой если `mini_server_id` не выставлен → 403 (см. `mini-clo-sync-gotchas.md`).
  - Нужно держать GCP key на боксе (secret rotation risk).
  - Не все проверки бэкпортированы (нет PI JWE cache, нет CF KV DLQ).

### Реестр (упрощённо, 2026-07-15)

| Домен                          | IP              | Type | Приложение                             |
| ------------------------------ | --------------- | ---- | -------------------------------------- |
| asportvalsisapp.com            | 157.230.244.37  | A    | Sisal                                  |
| api-stkapp.com                 | (do)            | A    | Stake                                  |
| bclicsportsapp.com             | (do)            | A    | Betclic                                |
| agamecasualapp.com             | (do)            | A    | TC-gesr                                |
| btsnfitapp.com                 | (do)            | B    | Betsson (legacy Type A → B)            |
| attlgameapp.com                | (do)            | B    | TC-LamDep (`viso-clo` :3101)           |
| totalsupergame.com             | 38.244.152.11   | C    | Total Casino #2 (ViSao)                |
| supercastotalgame.com          | 38.244.152.111  | C    | Total Casino #1 (ThaiCucQuyen)         |
| footballapisnai                | 149.33.29.82    | C    | Snai (multi-app: muslimazkarpro + omniconvert) |
| (sisal-football)               | 38.180.224.3    | C    | Sisal Football                         |
| (betsson-new)                  | 38.180.74.83    | C    | Betsson (new gen)                      |
| (olimpbet)                     | 149.33.0.240    | C    | Olimpbet                               |

---

## 3. Роль main КЛО

Единственная центральная нода. Всё, что нужно всей системе:

### 3.1 Scoring engine (все Type A/B боксы полностью, Type C — только для не-mini flows)

Endpoint `POST/GET /init` (роутер `main-klo/api/init_routes.py`). Флоу:

1. **Rate limit** (middleware `RateLimitMiddleware` в `main.py`) — per-proxy-key лимит 100/min для `/init` (иначе 200 OK + safe URL, не палим что rate-limited).
2. **Edge HMAC** (middleware `EdgeAuthMiddleware`) — если `EDGE_SECRET` задан, проверяет `X-Edge-Signature = HMAC(EDGE_SECRET, timestamp|xff|country|asn)`. Иначе direct-origin bypass возможен. Сейчас fail-open (secret не задан на проде).
3. **Admin auth** (middleware `AdminAuthMiddleware`) — админ-пути (/api/apps, /api/config, …) требуют `X-Admin-Key` иначе 404.
4. **`_resolve()`** — основной scoring pipeline (см. §5).
5. Возврат `{"url": "..."}` — либо bounce (`api.threeamigosteam.com/engine/go?t=<b64>`) для grey, либо safe URL для white.

### 3.2 Google Play Integrity decode

Endpoint `POST /api/integrity/verify` (роутер `main-klo/api/integrity_routes.py`).

- Принимает JWE токен + nonce (сгенерённый через `/api/integrity/nonce`).
- Дёргает Google PI API (project-specific service account keys).
- Парсит `deviceRecognitionVerdict`, `appRecognitionVerdict`, `appLicensingVerdict`, `appAccessRiskVerdict.appsDetected`, `deviceActivityLevel`, `playProtectVerdict`, `nonce`, `timestampMillis`.
- Кэширует parsed verdict в Redis (24h) — не декодировать один и тот же токен дважды.
- Nonce одноразовый (Redis SETNX 300s TTL) — attach IP при выдаче, проверка при verify (защита от cross-IP replay).

### 3.3 Bounce redirect

Endpoint `GET /go?t=<b64(target_url)>` (роутер `main-klo/api/gateway.py`).

- Base64-decode target URL.
- 302 redirect на него.
- Раньше был Turnstile CAPTCHA-gate (`/go/verify`) — с 2026-07-04 (`fix9`) сразу 302 без промежуточной страницы (SDK v2 apps ловили брендинг).

### 3.4 Config sync source

Endpoints `GET /api/sync/config` + `POST /api/sync/logs` (роутер `main-klo/api/sync_routes.py`).

- Auth: header `X-Sync-Secret` (per mini_server_id в `config/mini_server_secrets.json`).
- `sync_config()`:
  - Фильтрует `apps.json` по `mini_server_id == <auth'd id>` → только «свои» apps.
  - Собирает GCP keys для нужных `gcp_project_id` (base64-encoded).
  - Собирает активные bans (auto_ban.get_all_paginated).
  - Отдаёт также `google_asn_blocklist` и `debug_allow`.
  - `version` = timestamp — mini-clo пропустит если local >= remote.
- `sync_logs()`:
  - Принимает batch `{"logs": [<entry>, ...]}` от mini-clo.
  - Инсертит через тот же `request_logger.log()` в `request_logs` таблицу.

### 3.5 tracker.js pixel

- Файл: `/tracker.js` (serves `js-scripts/tracker.min.js`).
- Инжектится в landing pages / bounce страницы.
- Отправляет POST `/api/collect` с браузерными метриками (canvas fingerprint, WebGL, timezone, etc) + honeypot form submissions.
- Honeypot detection → `honeypot_ban.add(ip)` → 302 safe URL на всех последующих запросах с этого IP.

### 3.6 Admin API + panel

- Панель — Next.js hosted на Vercel (`panel.threeamigosteam.com`).
- Дёргает main КЛО `/api/dashboard/*`, `/api/audit/*`, `/api/apps/*`, `/api/config/*`, `/api/analytics/*`, `/api/reports/*`, `/api/lists/*`, `/api/honeypot/*`, `/api/auto-ban/*`.
- Auth: `X-Admin-Key` header. Fallback 404 если ключ неверный (path masking).

### 3.7 Auto-ban orchestration

- `auto_ban.py` — Redis banlist (per-IP-per-package + global) с TTL.
- Хук `auto_ban.emit()` вызывается когда `verdict = white + rejection_code in AUTOBAN_CODES_G1/G2`.
- Реплицируется в CF KV (для эджа) через `api/cf_sync.py`; при failure — DLQ, drain каждые 30 сек.
- Mini-clo забирает bans через `/api/sync/config` (эт warm в Redis на старте).

---

## 4. Роль mini-server

### 4.1 Nginx как SDK-splitter (все типы)

**Ключевая идея:** один и тот же URL (напр. `totalsupergame.com/game`) отдаёт разный контент в зависимости от `User-Agent`:

- **`okhttp/*`** (значит запрос из APK через SDK) → возвращаем 418 → `error_page 418 = @sdk_proxy` → отправляем в scoring.
- **Всё остальное** (реальный браузер, curl без UA, Googlebot) → отдаём landing на `127.0.0.1:3000` (Next.js).

Пример из [`mini-server-visao/nginx/sites-enabled__total-casino.conf`](../mini-server-visao/nginx/sites-enabled__total-casino.conf):

```nginx
location = /game {
    if ($http_user_agent ~* "okhttp") { return 418; }
    error_page 418 = @vsao_sdk_proxy;
    if ($arg_sid$arg_app_id$arg_instance_id) { return 418; }   # v3 GET fallback
    proxy_pass http://127.0.0.1:3000;                          # browser → landing
}

location @vsao_sdk_proxy {
    internal;
    rewrite ^ /init break;                                     # переписываем в /init
    proxy_pass http://127.0.0.1:8100;                          # → mini-clo (Type C)
    proxy_set_header X-Proxy-Key "<VISAO_PROXY_KEY>";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

**Гочи (важно!):**

- `$remote_addr` за Cloudflare = IP CF-эджа, **не** пользователь. Нужен `$http_cf_connecting_ip` или `set_real_ip_from` из `cloudflare-realip.conf`. Игнорирование этого = «cloak всегда белый» (см. `mini-server-architecture.md`).
- **X-Proxy-Key** хардкод в nginx (SDK его не шлёт из соображений безопасности — иначе один reverse-engineer APK палит ключ для всех прил, тут ключ per-mini-server, живёт только на его конфиге).
- **X-App-Id** приходит от SDK, main КЛО с 2026-07-15 использует его через `_resolve()` (если valid в `allowed_packages` list для этого proxy_key) — фикс кросс-app leak, когда 2 прилы делили один proxy_key (см. `xappid-fix-shared-proxy-key-2026-07-10.md` и `cross-app-leak-fix-2026-07-15.md`).
- **Force IPv4 resolver:** `resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;` — иначе `proxy_pass https://api.threeamigosteam.com` резолвит в IPv6, а CF выдаёт `error 1000` если origin AAAA не сматчен (см. `p7-nginx-ipv6-clickid-fix-2026-07-10.md`).

### 4.2 Landing на :3000 (Next.js)

- Реальный контент за что прила публикуется (духовный справочник, каталог лекарств, курс валют, minigame, футбольная статистика, каталог хадисов и т. д.).
- Обрабатывает Android App Links через `/.well-known/assetlinks.json` (JSON без редиректа, важно для DAL-верификации Google).
- Обычный Next.js SSR, ничего экзотического. Часто раскатан через pm2 или systemd + `pm2 start npm --name landing -- start`.
- **Опасность:** Next.js :3000 не должен быть открыт наружу (ufw allow 3000 нельзя!). Иначе кто-то дёрнет прямо и обнаружит стек. См. `landing-box-3000-exposure-incident.md`.

### 4.3 Local mini-clo :8100 (только Type C)

Что делает FastAPI на 127.0.0.1:8100 (см. [`mini-server-visao/mini-clo/main.py`](../mini-server-visao/mini-clo/main.py)):

- **Lifespan startup:**
  1. `initial_sync()` — blocking pull config от main КЛО (5 retry × 3 сек). Если apps.json пустой и sync fail → сервис падает с `RuntimeError`.
  2. `config_store.reload()` — читает apps.json в память.
  3. `play_integrity_client.init()` — загружает GCP service account keys из `config/gcp-key-*.json`, инициализирует Google API discovery services (один сервис per gcp_project_id).
  4. `warm_autoban()` — читает `config/bans.json`, warm-load'ит в Redis (SET key + TTL до expires_at).
  5. `log_shipper.run()` background task — batching queue + POST `/api/sync/logs` каждые 30 сек.
- **Requests:** `/init` (POST + GET) и `/web_content` — subset main КЛО flow (см. §5).
- **Redis (locally):** ключи `autoban:<pkg>:<ip>`, `burnt:<pkg>:<instance>`, `cloak:<pkg>:<instance>`, `vel:*`.

Ключевое отличие от main КЛО: **нет** богатого backing (нет CF KV DLQ, нет глобального PI JWE cache, нет full-fat classification). Всё что нужно — есть. Ничего лишнего.

### 4.4 Sync (pull config) + shipper (push logs)

- **Sync file:** [`mini-server-visao/mini-clo/sync.py`](../mini-server-visao/mini-clo/sync.py).
  - Читает `config/mini_server_secret` (shared с main КЛО).
  - Читает `config/sync_url` (обычно `https://api.threeamigosteam.com`).
  - GET `/api/sync/config` → сохраняет apps.json, GCP keys (base64→decode→chmod 600), bans.json, google_asn_blocklist.json, debug_allow.json.
  - Записывает `sync_state.json` с `{version, last_sync_ts}` — пропускает если local >= remote.
  - **2026-07-15 fix:** `initial_sync()` вызывает `config_store.reload()` СРАЗУ после sync — иначе apps.json меняется на диске, а в памяти старая версия до рестарта (см. `miniclo-msid-full-fix-2026-07-15.md`).

- **Log shipper file:** [`mini-server-visao/mini-clo/log_shipper.py`](../mini-server-visao/mini-clo/log_shipper.py).
  - `asyncio.Queue` (max 5000).
  - Flush каждые 30 сек ИЛИ когда queue > 100.
  - При HTTP fail → append batch в `logs/pending.jsonl` → retry на следующем flush.
  - Shutdown: `flush_pending()` дренит очередь.

---

## 5. Data flow: `/init` от запроса до verdict

Читаем главный флоу в [`main-klo/api/init_routes.py`](../main-klo/api/init_routes.py) → функция `_resolve()`. Ниже сжатая версия.

```
Request: POST /init (or GET)
  Headers:
    X-Proxy-Key:    pk_XXXXXXXXXXXXXXXXXXX   (nginx inject или query fallback)
    X-App-Id:       com.CauHoiViSao.ViSao   (SDK — используется если ∈ allowed_packages)
    X-Instance-Id:  <uuid из SharedPreferences прилы>
    X-Integrity-Token: <Google PI JWE ~1-2KB>
    User-Agent:     okhttp/4.9.0
    X-Real-User-IP: <mini-server nginx custom header — CF не трогает>
    X-Forwarded-For: <cf-connecting-ip, mini-nginx>
    Accept-Language: pl-PL,en;q=0.9
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1. resolve_proxy_key(pk)                                       │
│    proxy_keys.json → {package_name, name, allowed_packages}        │
│    None → return 403 (nothing logged)                              │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 2. resolve X-App-Id                                            │
│    Если X-App-Id ∈ allowed_packages → package_name = X-App-Id      │
│    Иначе если X-App-Id есть но НЕ в allowed → cross-app leak,      │
│           логируем xappid_cross_leak_blocked → return 403           │
│    Иначе package_name из proxy_keys.json entry                     │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 3. panic_mode?                                                 │
│    app.panic_mode = true → white, safe_url                         │
│    (используется для emergency kill switch, «выключить всё сейчас»)│
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 4. IP resolution                                               │
│    ip = X-Real-User-IP (custom, CF не трогает)                     │
│      or X-Forwarded-For[0]                                          │
│      or X-Real-IP                                                   │
│      or request.client.host                                         │
│                                                                     │
│    skip_internal_ip: если 127.*/10.*/172.16-31.*/192.168.* →       │
│      return white (health check / docker bridge, не в scoring)     │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 5. debug_allow whitelist                                       │
│    is_debug(ip, instance_id) → force GREY (bypass all), log, done  │
│    Для тестирования dev'ом без запуска PI-мокапов                  │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 6. auto_ban.is_banned(ip, package)                             │
│    Instant white, negative cache 1h. Экономит IPQS/IPinfo/PI quota │
│    logs с rejection = autoban_hit                                   │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 7. IPinfo Max lookup (24h Redis cache)                         │
│    → geo.country, city, asn, isp, vpn, proxy, res_proxy, tor,      │
│      relay, hosting, is_mobile, anonymous_name                     │
│    Fail-open (timeout → geo = None)                                │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 8. IPQS lookup (Redis cache)                                   │
│    → fraud_score, vpn, proxy, tor, bot_status, isp                 │
│    Fail-open. Ключ IPQS_API_KEY в env                              │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 9. HARD-KILL chain (первое совпадение выигрывает)              │
│   [Только для require_integrity apps, кроме tor — он unconditional] │
│                                                                     │
│   9.1 instance_burnt (2026-07-09: disabled, всегда false)          │
│   9.2 missing_instance_id (require_pi + no header → бан)           │
│   9.3 tor_unconditional (IPQS.tor = true → бан, все apps)          │
│   9.4 geo_unknown (require_pi + asn=0 + not soft-PI-any-ASN)        │
│   9.5 asn_google (asn ∈ google_asn_blocklist)                       │
│   9.6 asn_vpn (asn ∈ vpn_asn_blocklist)                             │
│   9.7 ipqs_vpn (IPQS.vpn=true)                                      │
│   9.8 ipqs_fraud (fraud_score ≥ 90)                                 │
│                                                                     │
│   Hard-kill hit → verdict=white, log, auto_ban.emit(), return      │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 10. Базовый скоринг — scoring_engine.score_request()           │
│    - Country/city/ASN blocklists (lists/*.txt)                     │
│    - lang-country hard-kill (VPN на IT + lang=ru = АВТОБАН)        │
│    - Device model + codename blocks                                │
│    - UA-blocks                                                      │
│    - honeypot_ban check                                             │
│    - Returns: ScoringResult(score, verdict, rejectionCode, details)│
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 11. PI verify (только если require_integrity=true)             │
│    Определяем mode:                                                 │
│      • soft-PI eligible (страна ∈ soft_pi_countries, ASN whitelist,│
│        нет VPN/proxy) → 'soft'                                     │
│      • иначе → 'strict'                                             │
│      • require_integrity=false → 'lenient'                          │
│                                                                     │
│    _verify_integrity(token, package, mode):                        │
│      • decode через play_integrity_client.verify_token()           │
│      • package_name mismatch (cross-app PI replay) → бан           │
│      • timestamp freshness (-5s..120s) → бан если stale/future     │
│      • nonce replay (Redis SETNX 15s) → бан если seen (skippable  │
│         per app: skip_nonce_replay=true для SDK v3 Classic PI)     │
│      • UNLICENSED → бан (модер sideload через ADB)                 │
│      • CAPTURING (screen recording) → бан                          │
│      • CONTROLLING (Robo/UiAutomator) → бан                        │
│      • UNEVALUATED combo on first_init → бан (scanner sandbox)     │
│      • strict: not MEETS_DEVICE_INTEGRITY OR not PLAY_RECOGNIZED   │
│      • soft: virtual/empty/not-basic → бан                         │
│      • lenient: только virtual/empty                                │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 12. Velocity check (для require_integrity apps)                │
│    • per-instance: > 100 req / 5min = бот                          │
│    • per-subnet: > 100 разных install / 15min = прокси-пул         │
│    • per-IP: > 300 req / 5min = burst                              │
│    (2026-07-09 max-conversion: пороги расширены 5-7×)              │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 13. Soft-PI extras (только если soft-PI eligible)              │
│    • asn_rotation (instance прыгает между ASN = residential proxy) │
│    • soft_ua_emulator (sdk_gphone/aosp_atd на mobile ASN)          │
│    • soft_ua_google_device (Pixel/Nexus в Лагосе = редкость + FTL) │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 14. Aggregate score + verdict                                  │
│    total = result.score + pi_score + vel_score + extra_score       │
│    verdict = white if total >= threshold else result.verdict       │
│    rejection = первое подходящее (integrity_missing / velocity_    │
│                block / soft_pi_extra / …)                          │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 15. cloak_consumed (только если verdict=grey + опция вкл.)     │
│    check_and_mark_cloak_consumed(instance, package, ip):           │
│      • Redis SETNX cloak_consumed:<pkg>:<inst>, TTL 24h            │
│      • Первый /init с нового instance → SETNX true → grey          │
│      • 2-й+ /init за 24h → SETNX false → verdict = white, safe URL │
│    Защита от Google deep-review с реальным телефоном + BrightData  │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 16. URL selection                                              │
│    grey → target_url + ?clickid=<inst>&geo=<cc>                    │
│           → base64 encode                                           │
│           → return "https://api.threeamigosteam.com/engine/go?t=…" │
│    white → return safe_url                                          │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 17. Log to Postgres                                            │
│    request_logger.log() → request_logs (async batch)               │
│    Поля: ip, ua, country, city, verdict, rejectionCode, details    │
│      + extra_payload: {scoreBuckets, piMode, softEligible,          │
│                        hardKill, classification, ipinfo}            │
│    js_metrics = {"playIntegrity": pi_raw} — панель показывает      │
│                                                                     │
│    Дальше auto_ban emit hook — если white + rejection in AUTOBAN_  │
│    CODES_G1/G2 → добавить в banlist Redis + CF KV DLQ              │
│    Если grey → mark_grey (negative cache 1h)                       │
└─────────────────────────────────────────────────────────────────────┘
       │
       ▼
   Response: {"url": "https://…"}
```

**APK получает URL** → открывает через Chrome CustomTab (окно браузера в приложении). Дальше:

- **Grey path:** URL = `https://api.threeamigosteam.com/engine/go?t=<base64(target_url?clickid=<inst>&geo=<cc>)>` → main КЛО делает 302 на decoded target → target = `https://minigamegoldblue.com/4S9MBj?clickid=…&geo=…` → это Keitaro стрим клиента → Keitaro делает 302 на реальный оффер (казино) → регистрация игрока → комиссия капает.

- **White path:** URL = safe_url (напр. `https://sportivewave.com/game_app`) → браузер грузит нативную заглушку. Модератор Google Play видит: «прила про minigame, всё легитимно».

---

## 6. Список компонентов

### 6.1 Runtime services

| Компонент             | Тип                | Где                                    | Роль                                                |
| --------------------- | ------------------ | -------------------------------------- | --------------------------------------------------- |
| Main КЛО              | FastAPI + uvicorn  | 31.76.251.103, api.threeamigosteam.com | Scoring engine + PI decode + config source + panel API |
| Postgres 15           | RDBMS              | localhost на main-КЛО                  | request_logs, auto_bans, honeypot_bans, integrity_cache |
| Redis 7               | KV/cache           | localhost на main-КЛО и на каждом mini | Rate limit, bans, PI cache, velocity, cloak_consumed |
| Mini-clo (Type C)     | FastAPI + uvicorn  | :8100 на каждом Type C mini            | Local scoring (subset main-КЛО flow)                 |
| Landing (Next.js 15)  | Node.js SSR        | :3000 на каждом mini                   | Fake site content (справочник, курс валют, minigame) |
| Nginx                 | HTTP proxy         | :443 на каждом mini + на main-КЛО      | SDK-splitter (UA-based), TLS termination            |
| Clo-mw (Type B)       | Node.js sidecar    | :3101 на Type B mini                   | Splitter middleware (proxy к main-КЛО)              |
| Admin Panel           | Next.js на Vercel  | panel.threeamigosteam.com              | Web UI поверх main-КЛО admin API                    |

### 6.2 Внешние сервисы

| Сервис                       | Endpoint                                              | Используется для                                             |
| ---------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ |
| Cloudflare                   | Все домены проекта                                    | DDoS, WAF, TLS, cf-connecting-ip, cf-country/asn, KV storage |
| Google Play Integrity API    | `playintegrity.googleapis.com/v1/*:decodeIntegrityToken` | PI JWE decode (per gcp_project_id service account key)       |
| IPinfo Max                   | `https://api.ipinfo.io/lite/{ip}?token=...`           | Geo, ASN, VPN/proxy/tor/hosting/residential-proxy flags       |
| IPQualityScore (IPQS)        | `https://ipqualityscore.com/api/json/ip/{key}/{ip}`   | fraud_score, tor exit, bot detection, VPN                    |
| Cloudflare Workers KV        | CF API                                                | Edge-cached bans (auto_ban replication, DLQ retry)           |
| Cloudflare Turnstile         | `challenges.cloudflare.com/turnstile/v0/siteverify`   | Legacy bounce CAPTCHA (сейчас unused, fail-CLOSED)           |
| Google Cloud Platform        | Service accounts                                       | PI keys (per app: `gcp-key-<project>.json`)                  |
| Keitaro (клиентское)         | `stksprapp.com`, `sportvalyellowapp.com`, …           | Трекер, split-testing, партнёрские офферы                    |

### 6.3 Хранилища и данные

| Хранилище              | Что там                                                                          |
| ---------------------- | -------------------------------------------------------------------------------- |
| `config/apps.json`     | 33 приложения: name, package_name, target_url, safe_url, флаги (require_integrity, cloak_consumed_enabled, allowed_countries, mini_server_id, cert_sha256, gcp_project_id, proxy_key, auth_token…) |
| `config/proxy_keys.json` | `{pk_xxx: {package_name, name, allowed_packages: [pkg1, pkg2, …]}}` — реверс-lookup + guard |
| `config/debug_allow.json` | `{ips: [...], instances: [...]}` — force grey для dev-тестов                  |
| `config/mini_server_secrets.json` | `{mini_server_id: shared_secret}` для `/api/sync/*`                    |
| `config/google_asn_blocklist.json` | ASN Google, Accenture, Firebase Test Lab → hard-kill                  |
| `config/vpn_asn_blocklist.json` | M247, NordVPN, Vultr, OVH, Hetzner, … → hard-kill (protected apps)      |
| `config/mobile_asn_whitelist.json` | Per-country: NG=[29465,36873,…], CI=[29571,…], SN=[8346,…] для soft-PI |
| `lists/countries_block.txt` | ISO2 коды стран которые ВСЕГДА в блок                                       |
| `lists/cities_block.txt` | Названия городов                                                                |
| `lists/codenames_block.txt` | Device codenames (напр. `sdk_gphone64_x86_64`)                              |
| `lists/device_models_block.txt` | Полные модели (напр. `Google Pixel 4a`)                                |
| `lists/ip_ranges_block.txt` | CIDR блоклист                                                                |
| `config/gcp-key-*.json` | Service account key per gcp_project_id (для PI decode)                          |
| Postgres `request_logs` | Каждый /init: ip, ua, country, city, verdict, rejection_code, details JSONB, extra_payload JSONB (score buckets, PI raw, ipinfo/ipqs blocks, classification) |
| Postgres `auto_bans` | Активные баны: ip, package_name, code, expires_at                                   |
| Postgres `honeypot_bans` | IP submit-нувшие honeypot form                                               |
| Redis `nonce:<sha256>` | PI nonce (TTL 300s) — cross-IP replay защита                                     |
| Redis `pi_nonce_seen:<nonce>` | Замеченные PI nonces (TTL 15s) — replay защита                             |
| Redis `pi_verdict:<token-hash>` | Кэш decoded PI verdict (TTL 24h)                                         |
| Redis `autoban:<pkg>:<ip>` | Banlist (TTL до expires_at)                                                  |
| Redis `mark_grey:<pkg>:<ip>` | Negative cache для grey IPs (TTL 1h) — защита от errant ban              |
| Redis `cloak_consumed:<pkg>:<inst>` | Одноразовость grey per instance (TTL 24h)                           |
| Redis `vel:inst:<inst>`, `vel:sub:<subnet>`, `vel:ip:<ip>` | Velocity counters (TTL 5-15 min)              |
| Redis `burnt:<pkg>:<inst>` | Устаревший (2026-07-09 disabled в max-conversion mode)                       |

---

## 7. Диаграмма БД + Redis-ключи

### Postgres (SQLAlchemy async, схема в `main-klo/db_models.py`)

```
request_logs                     auto_bans                        honeypot_bans
────────────                     ─────────                        ─────────────
id (bigserial)                    id                              id
timestamp (timestamptz)           ip (inet, index)                ip (inet, index)
ip (inet, index)                  package_name (nullable)         first_seen
country_code (varchar(2))         code (varchar)                  count
country                           reason (text)
city                              expires_at (timestamptz, index) integrity_cache
verdict (varchar) index           created_at                      ───────────────
rejection_code (varchar)          request_id                      token_hash (varchar, pk)
score (int)                       classification                  verdict (jsonb)
details (jsonb)                                                   fetched_at
extra_payload (jsonb)                                             ttl_expires_at
user_agent (text)
accept_language
device_model, os_version, isp
package_name (varchar, index)
headers (jsonb)
js_metrics (jsonb)               indices на (timestamp, verdict, package_name, ip)
```

### Redis keys reference

```
nonce:<sha256>                    → issued PI nonce → IP (TTL 300s)
pi_nonce_seen:<nonce>             → "1" (TTL 15s, replay guard)
pi_verdict:<token-hash>           → JSON parsed verdict (TTL 24h)
pi_first_init:<pkg>:<inst>        → timestamp (TTL 14d, UNEVALUATED gate — 2026-07-09 disabled)
autoban:<pkg>:<ip>                → ban_code (TTL до expires_at)
autoban:global:<code>:<ip>        → ban_code (для GLOBAL_AUTOBAN_CODES)
mark_grey:<pkg>:<ip>              → "1" (TTL 1h, negative cache)
cloak_consumed:<pkg>:<inst>       → JSON {ts, ip, verdict} (TTL 24h)
instance_burnt:<pkg>:<inst>       → reason (TTL 24h — 2026-07-09 disabled)
asnrot:<inst>                     → set ASN (TTL 1h — 2026-07-09 disabled)
vel:inst:<inst>                   → counter (TTL 5min)
vel:sub:<subnet>                  → set instance_ids (TTL 15min)
vel:ip:<ip>                       → counter (TTL 5min)
rl:<ip>                           → rate-limit counter (60s window)
rl:init:<pkg-hash>                → per-proxy-key init limit (60s)
rl:nonce:<ip>                     → per-IP nonce limit (60s)
```

---

**Дальше читать:**

- **[../README.md](../README.md)** — top-level overview.
- `docs/02-deployment.md` — как ставить и апгрейдить (TBD).
- `docs/03-config.md` — детали формата apps.json / proxy_keys.json (TBD).
- `docs/04-troubleshooting.md` — типовые падения (TBD).

Ключевые исходники (по частоте изменений):

- [`main-klo/api/init_routes.py`](../main-klo/api/init_routes.py) — 90% багов и фиксов приходят сюда.
- [`main-klo/config.py`](../main-klo/config.py) — все конфиг-загрузки.
- [`main-klo/scoring_engine.py`](../main-klo/scoring_engine.py) — базовые фильтры.
- [`mini-server-visao/mini-clo/init_routes.py`](../mini-server-visao/mini-clo/init_routes.py) — mini-clo scoring.
- [`mini-server-visao/mini-clo/sync.py`](../mini-server-visao/mini-clo/sync.py) — config sync (gotchas!).
- [`mini-server-visao/nginx/sites-enabled__total-casino.conf`](../mini-server-visao/nginx/sites-enabled__total-casino.conf) — эталонный nginx для Type C.
