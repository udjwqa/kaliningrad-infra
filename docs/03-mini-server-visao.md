# 03. Mini-server ViSao (Total Casino #2) — детальный разбор

> Актуально на 2026-07-16. Все патчи июля 2026 (07-04 ... 07-15) применены.

## 1. Обзор

**Бокс:** `38.244.152.11` (root / `6bP82ddHds`)
**Домен:** `totalsupergame.com` (за Cloudflare, real IP восстановлен через `set_real_ip_from`)
**Тип:** **C** (mini-clo :8100 + Next.js landing :3000 + nginx-сплиттер)
**Пакет:** `com.CauHoiViSao.ViSao` — Android spirit-questions приложение, фронтит Total Casino
**proxy_key:** `pk_d9185ab14201d57bd47302844e231347`
**GCP project для PI:** `totalcasino-visao`
**mini_server_id:** `total-casino-2` (используется main КЛО в `/api/sync/config` фильтре)
**SDK path:** `/game`

### Что такое Type C

Три поколения архитектуры мини-серверов сосуществуют в проде. Тип C — самый новый, «полноценная копия КЛО на боксе»:

| Компонент               | Порт        | Роль                                                                 |
|-------------------------|-------------|----------------------------------------------------------------------|
| **nginx**               | 80, 443     | TLS termination, UA-сплиттер, proxy к :3000 и :8100                  |
| **mini-clo** (uvicorn)  | 127.0.0.1:8100 | Локальный FastAPI-скорер (PI decode + IPinfo + IPQS + Redis)      |
| **Next.js landing**     | 127.0.0.1:3000 | Белый фасад — spirit-questions страница (Total Casino cover-story) |
| **Redis**               | 127.0.0.1:6379 | velocity, cloak_consumed, autoban warm-cache                       |

**Всё, что относится к SDK (`okhttp` UA или query с sid/app_id/instance_id), уходит на mini-clo :8100 → Google PI API → скоринг локально → JSON `{"url": ...}`.** Всё, что относится к браузеру (Chrome CT после `/go`, реальные посетители лендинга, `/.well-known/assetlinks.json` для App Links), уходит на Next.js :3000.

Никакого /init хода к `api.threeamigosteam.com` в hot-path нет (кроме fallback `@init_fallback_p4` — legacy для non-Type-C прил через тот же nginx). Main КЛО у Type C участвует только в:
1. **Sync конфига** (`GET /api/sync/config` каждые ~5 мин, см. [04-sync-flow.md](04-sync-flow.md)).
2. **Приёме батчей логов** (`POST /api/sync/logs` каждые 30 с).
3. **`/engine/go` bounce redirect** (grey → 302 → Keitaro клиента).

## 2. Software stack

- **OS:** Debian 12 (Bookworm)
- **nginx:** 1.22+, systemd unit `nginx.service`
- **Python:** 3.12 (в `/opt/mini-clo/venv/`)
- **uvicorn:** ASGI сервер, слушает `127.0.0.1:8100`
- **Redis:** `redis://127.0.0.1:6379/0`, systemd `redis-server.service`
- **Docker:** для Next.js landing (`docker compose up -d`), контейнер биндится на `127.0.0.1:3000:3000` (см. security fix из [landing-box-3000-exposure-incident](../memory/landing-box-3000-exposure-incident.md) — на Type C всё изначально на localhost)
- **Let's Encrypt:** `/etc/letsencrypt/live/totalsupergame.com/` — управляется через Certbot (auto-renew через systemd timer)
- **ufw:** `allow 22,80,443/tcp; default deny incoming` (обязательно — иначе :3000 голым в интернет)

## 3. Nginx — полный разбор `sites-enabled/total-casino`

Полный конфиг лежит в этом репо: `/tmp/kaliningrad-infra/mini-server-visao/nginx/sites-enabled__total-casino.conf`. Ниже — построчный разбор.

### 3.1 Глобальный resolver (первая строка файла)

```nginx
# P7: force IPv4 resolver — required for proxy_pass to api.threeamigosteam.com domain
resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
```

**Зачем.** Cloudflare возвращает AAAA (IPv6) первым для `api.threeamigosteam.com`. Многие боксы не имеют IPv6-route → `connect() failed (101: Network is unreachable)` на upstream. Патч 07-10 (см. [p7-nginx-ipv6-clickid-fix-2026-07-10](../memory/p7-nginx-ipv6-clickid-fix-2026-07-10.md)) заставляет nginx ходить только по IPv4.

**Grabli:** `resolver` не разрешён на любом уровне. Правильно — на верхнем уровне файла (http-контекст include). Если засунуть внутрь `upstream {}` — `nginx -t` ругнётся `not allowed here`.

### 3.2 `location = /web_content` — tracker.js proxy

```nginx
location = /web_content {
    proxy_pass https://api.threeamigosteam.com/engine/web_content$is_args$args;
    proxy_set_header X-Proxy-Key "pk_d9185ab14201d57bd47302844e231347";
    ...
}
```

**Роль:** SDK при старте (или лендинг браузером) тянет `tracker.js`. Всё уходит на main КЛО, потому что tracker должен быть централизован (единая версия, единая логика pixel-collection). Nginx **инжектит X-Proxy-Key** — SDK этого делать не должен, ключ секретный.

### 3.3 `location = /api/collect` — tracker pixel

Аналогично `/web_content`, только для pixel-запросов от tracker.js в браузере. Query-string обязана дойти до main КЛО (`$is_args$args`) — там метрики.

### 3.4 `location = /go` и `/go/verify` — bounce redirect

```nginx
location = /go {
    proxy_pass https://api.threeamigosteam.com/engine/go$is_args$args;
    ...
    add_header Cache-Control "no-store" always;
}
```

**Роль.** Когда mini-clo даёт grey verdict, URL в JSON-ответе SDK = `https://api.threeamigosteam.com/engine/go?t=<b64>`. Chrome Custom Tabs открывает его, main КЛО декодит `t` → 302 → Keitaro. Мы могли бы отдать APK URL сразу на api.threeamigosteam.com, но тогда браузер видит apex-домен КЛО в истории — палево. Проксируя через `totalsupergame.com/go`, мы держим единый домен «прилы» в трафике.

**Cache-Control: no-store** — важно, чтобы CF/браузер не кешировали 302 с одним clickid для разных юзеров.

### 3.5 `location = /game` — SDK-сплиттер (главная точка входа)

```nginx
location = /game {
    access_log /var/log/nginx/visao_trace.log visao_trace;
    if ($http_user_agent ~* "okhttp") { return 418; }
    error_page 418 = @vsao_sdk_proxy;
    if ($arg_sid$arg_app_id$arg_instance_id) { return 418; }
    proxy_pass http://127.0.0.1:3000;   # браузер — на лендинг
    ...
}
```

**Логика UA-split:**
1. Если UA содержит `okhttp` (это Kotlin/Android SDK HTTP client) → `return 418` → `error_page 418 = @vsao_sdk_proxy` (см. ниже).
2. Если в query есть хоть один из `sid|app_id|instance_id` (SDK-контракт) → тоже 418. Это спасает случай, когда прошивка меняет okhttp UA.
3. Иначе — обычный браузер → на Next.js лендинг :3000. Пользователь видит spirit-questions.

**access_log с custom format `visao_trace`** (см. `nginx.conf`) даёт полный дамп заголовков — включая `X-Integrity-Token`, `X-App-Id`, `X-Sid`, `CF-Connecting-IP`. Незаменим при отладке.

### 3.6 `@vsao_sdk_proxy` — internal named location для SDK-запросов

```nginx
error_page 418 = @vsao_sdk_proxy;
location @vsao_sdk_proxy {
    access_log /var/log/nginx/visao_trace.log visao_trace;
    internal;
    rewrite ^ /init break;
    proxy_pass http://127.0.0.1:8100;
    ...
    proxy_set_header X-Proxy-Key "pk_d9185ab14201d57bd47302844e231347";
    proxy_connect_timeout 8s;
    proxy_read_timeout 12s;
}
```

**Ключевые моменты:**
- `internal` — location недоступен снаружи (только через `error_page`).
- `rewrite ^ /init break` — переписывает URI на `/init` (mini-clo слушает только `/init`).
- `proxy_pass http://127.0.0.1:8100` — на локальный mini-clo (без TLS, всё в localhost).
- `X-Proxy-Key` **инжектится nginx-ом** — SDK ничего не знает про этот ключ. Ротация ключа = править nginx-конфиг во всех 4 хардкодах (`/web_content`, `/api/collect`, `/go`, `@vsao_sdk_proxy`) + `apps.json` на main КЛО + `proxy_keys.json` на main КЛО. См. [mini-server-architecture](../memory/mini-server-architecture.md) ранбук ротации.
- Timeout 8s connect / 12s read — с запасом, чтобы Google PI decode (обычно ~1-2 с, макс. 8 с после [pi-decode-timeout-fix](../memory/pi-decode-timeout-fix.md)) успел завершиться.

### 3.7 `location = /init` и `@init_fallback_p4` — универсальный fallback

```nginx
location = /init {
    if ($http_user_agent ~* "okhttp") { return 418; }
    proxy_pass http://127.0.0.1:3000;   # браузер /init — на лендинг (маловероятно)
    ...
}
error_page 418 = @init_fallback_p4;
location @init_fallback_p4 {
    internal;
    rewrite ^ /engine/init break;
    proxy_pass https://api.threeamigosteam.com;
    proxy_set_header X-Proxy-Key "pk_d9185ab14201d57bd47302844e231347";
    ...
}
```

**Зачем.** Оставлено с эпохи универсального fallback'а (max-conversion mode 07-09). Если какая-то версия APK шлёт напрямую `POST /init` вместо `/game`, nginx маршрутизирует её на main КЛО (`/engine/init`), не на mini-clo. Type C бокс не обслуживает это локально, потому что `/init` дублирует named location — историческая причина (сначала был универсальный fallback, потом добавили Type C `/game`).

**⚠️ Grabli с двойным `error_page 418`.** В том же server-блоке `/game` и `/init` оба используют `error_page 418`. Последний определённый **перекрывает** предыдущий на уровне server-блока. Правильно — оба `error_page 418 = @...` дублируются, но на практике nginx матчит по последнему. Для детерминизма имеет смысл переписать так, чтобы `error_page` жил внутри самого `location {}` (см. [visao-integrity-fix-2026-07-14](../memory/visao-integrity-fix-2026-07-14.md)).

### 3.8 Прочие location'ы

- `location /` → `proxy_pass http://127.0.0.1:3000` с WebSocket-поддержкой (`Upgrade`/`Connection: upgrade`) для HMR/live-reload.
- `location /_next/static/` — статика Next с immutable cache 1 год.
- `location = /.well-known/assetlinks.json` — обязательно `default_type application/json` без редиректа (Android App Links проверяют строгий Content-Type).

### 3.9 TLS

- Cert от Let's Encrypt (`/etc/letsencrypt/live/totalsupergame.com/`), managed by Certbot.
- Redirect с 80 на 443 (второй `server {}` блок).
- `include /etc/nginx/snippets/cloudflare-realip.conf` — обязательно **ДО** любых allow/deny, чтобы `$remote_addr` уже был реальным IP клиента к моменту фильтрации.

### 3.10 `cloudflare-realip.conf` — снаппет

```nginx
set_real_ip_from 173.245.48.0/20;
...  # весь список CF v4/v6 диапазонов
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
```

- CF-Connecting-IP — заголовок, который CF гарантирует. `X-Forwarded-For` тоже приходит, но менее строг.
- `real_ip_recursive on` — если XFF содержит цепочку `[CF-ip, real-ip]`, nginx выбирает не-CF из хвоста.

**⚠️ Не добавлять наивно `allow CF-ranges; deny all;` на этом же снаппете** — `set_real_ip_from` переписывает `$remote_addr` **до** allow/deny, и живые юзеры за CF получат deny. Origin-protection надо делать иначе (WAF на CF, либо allow/deny **до** `real_ip_header`).

## 4. Systemd unit — `mini-clo.service`

```ini
[Unit]
Description=mini-КЛО FastAPI service
After=network.target
Wants=mini-clo-sync.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mini-clo
Environment=PYTHONUNBUFFERED=1
Environment=BOUNCE_URL_BASE=https://totalsupergame.com
Environment=IPINFO_TOKEN=8b471d08135468
Environment=IPQS_API_KEY=qtijEY4maadviEu8leT7LftvgMWxwicO
Environment=REDIS_URL=redis://127.0.0.1:6379/0
ExecStart=/opt/mini-clo/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8100
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Что важно:**
- `BOUNCE_URL_BASE` — не используется в текущей версии mini-clo (`init_routes.py` хардкодит `https://api.threeamigosteam.com/engine` через `os.getenv("BOUNCE_URL_BASE", ...)`), но оставлено как gcp-hint для будущего.
- `IPINFO_TOKEN`, `IPQS_API_KEY` — общие для всех Type C боксов, ротируются централизованно.
- `REDIS_URL` — локальный Redis, обязательный для velocity/cloak_consumed. Если Redis отключён, все Redis-checks fail-OPEN (см. `redis_client.py:get_redis()`).
- `Wants=mini-clo-sync.service` — тянет sync-таймер (см. [04-sync-flow.md](04-sync-flow.md)).

## 5. Файловая структура `/opt/mini-clo/`

```
/opt/mini-clo/
├── main.py                 # FastAPI, lifespan (initial_sync, PI init, log_shipper task)
├── init_routes.py          # POST /init + GET /init — весь scoring pipeline (~380 строк)
├── config.py               # ConfigStore, is_debug(), _load_debug()
├── sync.py                 # sync_config() + initial_sync() — pull от main КЛО
├── log_shipper.py          # LogShipper — async queue + batch POST /api/sync/logs
├── redis_client.py         # is_autobanned, is_instance_burnt (disabled), cloak_consumed, velocity
├── constants.py            # LANG_HARDKILL_MAP + check_lang_country_mismatch
├── models.py               # Dataclasses (ScoringDetail, ScoringResult)
├── requirements.txt
├── venv/                   # Python 3.12 virtualenv
├── external/
│   ├── play_integrity.py   # Google PI API client (обёртка google-api-python-client)
│   ├── ipinfo_client.py    # IPinfo v2 Max — asn/geo/vpn/proxy/res_proxy/hosting
│   └── ipqs_client.py      # IPQualityScore fraud API
├── config/
│   ├── apps.json                       # synced от main КЛО (только apps с mini_server_id=total-casino-2)
│   ├── bans.json                       # synced ip_bans (7d TTL в Redis после warm)
│   ├── debug_allow.json                # synced whitelist (IP + instance_id → force grey)
│   ├── google_asn_blocklist.json       # synced list of Google ASN (asn_google hard-kill)
│   ├── gcp-key-totalcasino-visao.json  # synced из main КЛО (base64-decoded)
│   ├── mini_server_secret              # X-Sync-Secret для /api/sync/config auth
│   ├── sync_url                        # "https://api.threeamigosteam.com/engine"
│   └── sync_state.json                 # {"version": <timestamp>, "last_sync_ts": ...}
└── logs/
    └── pending.jsonl                   # неотправленные батчи логов (retry на следующем flush)
```

### 5.1 `mini_server_secret`

Один shared-secret на бокс. Соответствует ключу в `mini_server_secrets.json` на main КЛО (для ViSao это `total-casino-2` → `1pMs6PMpmUVp0gJJGNPLMGS1MktEUC15mQIwKf2MEO0`). Передаётся в заголовке `X-Sync-Secret` при sync и log-ship.

### 5.2 `sync_url`

Одна строка: `https://api.threeamigosteam.com/engine`. Используется `sync.py` и `log_shipper.py` для формирования endpoint'ов (`{sync_url}/api/sync/config`, `{sync_url}/api/sync/logs`).

### 5.3 `apps.json`

Локальная копия `config/apps.json` от main КЛО, но **отфильтрованная** по `mini_server_id="total-casino-2"`. На ViSao всегда должна быть ровно одна запись — `com.CauHoiViSao.ViSao`. Если пусто (`[]`) — значит на main КЛО у прилы стал `mini_server_id=null` (инцидент [visao-integrity-fix-2026-07-14](../memory/visao-integrity-fix-2026-07-14.md)) → все SDK-запросы получают 403.

## 6. Flow трафика на этом боксе

### 6.1 SDK-запрос (Android, окhttp, целевой сценарий)

```
APK (SDK v4 AppClient.kt)
  │ POST https://totalsupergame.com/game
  │ Headers:
  │   User-Agent: okhttp/4.x
  │   X-App-Id: com.CauHoiViSao.ViSao
  │   X-Sid: <UUID>
  │   X-Instance-Id: <UUID>
  │   X-Integrity-Token: <Play Integrity JWT>
  │   X-Locale: en-US
  ▼
Cloudflare (edge)
  │ добавляет CF-Connecting-IP
  ▼
nginx :443 (totalsupergame.com)
  │ location = /game
  │   if ($http_user_agent ~* "okhttp") { return 418; }
  │ error_page 418 = @vsao_sdk_proxy
  ▼
@vsao_sdk_proxy (internal)
  │ rewrite ^ /init break
  │ proxy_pass http://127.0.0.1:8100
  │ + X-Proxy-Key: pk_d9185ab14201d57bd47302844e231347 (инжект)
  │ + X-Real-IP, X-Forwarded-For
  ▼
mini-clo :8100 (init_routes.py init_resolve)
  │ 1. auth (proxy_key → apps.json → ViSao)
  │ 2. HDRTRACE лог (integrity_token длина, headers dump — ViSao only)
  │ 3. Debug whitelist bypass (config_store.is_debug(ip, instance_id))
  │ 4. auto_ban (Redis autoban:pkg:ip / autoban:_:ip)
  │ 5. instance_burnt (Redis, disabled с 07-14)
  │ 6. IPinfo lookup (geo, asn, vpn, proxy, res_proxy, hosting, mobile)
  │ 7. asn_google hard-kill (google_asn_blocklist.json)
  │ 8. IPinfo hard-kills (vpn / proxy / res_proxy non-CGNAT / tor / hosting)
  │ 9. country_not_allowed / excluded_countries
  │ 10. lang_country_mismatch (require_integrity apps)
  │ 11. IPQS lookup + hard-kills (tor unconditional, vpn/fraud for require_integrity)
  │ 12. Velocity guard (per-instance 12/5min, per-ip 60/5min, per-subnet 15/15min)
  │ 13. Play Integrity verify (Google PI API, unconditional if token present since 07-14)
  │ 14. Verdict decision (grey / white)
  │ 15. cloak_consumed check (SETNX, если verdict=grey и cloak_consumed_enabled)
  │ 16. Mark instance_burnt (если verdict=white и rejection ∈ BURN_CODES)
  ▼
Response JSON:
  grey → {"url":"https://api.threeamigosteam.com/engine/go?t=<b64(target?clickid=X&geo=Y)>"}
  white → {"url":"<safe_url>"}
  │
  ▼
APK получает URL:
  grey → открывает в Chrome Custom Tabs
    │
    ▼
  Chrome → GET https://api.threeamigosteam.com/engine/go?t=...
    │
    ▼
  main КЛО (gateway.py) → декодит t → 302 → Keitaro (stksprapp / sportvalyellowapp)
    │
    ▼
  Keitaro → 302 → казино
```

**Логирование:** `log_shipper.enqueue(log_entry)` кладёт запись в asyncio.Queue. Каждые 30 с (`FLUSH_INTERVAL_SEC`) все накопленные записи батчем уходят на `POST /api/sync/logs` main КЛО. Там `request_logger.log()` пишет в Postgres `request_logs` table.

### 6.2 Браузер (случайный посетитель или Chrome CT после `/go`)

```
Browser → GET https://totalsupergame.com/game
  │ User-Agent: Mozilla/... (не okhttp)
  ▼
nginx location = /game
  │ okhttp check — не совпало
  │ arg_sid$arg_app_id$arg_instance_id — пусто
  │ proxy_pass http://127.0.0.1:3000
  ▼
Next.js landing → spirit-questions страница
```

### 6.3 tracker.js pixel

```
Browser → GET https://totalsupergame.com/api/collect?...
  ▼
nginx location = /api/collect
  │ proxy_pass https://api.threeamigosteam.com/engine/api/collect?...
  │ + X-Proxy-Key инжект
  ▼
main КЛО (collect_routes.py) → пишет в БД
```

## 7. Landing (Next.js) — что это

Next.js standalone-приложение `total-casino` — фасад для white-flow. Крутится либо через systemd `total-casino.service` (стандартный `node server.js`) в Type C-вариантах, либо через `docker compose`. На ViSao — **standalone без исходников** (только `.next/` build), правки политики (email, юр. лицо) делаются напрямую в `.next/server/app/privacy-total.{rsc,html}` через sed → restart сервиса. Подробнее — [visao-integrity-fix-2026-07-14](../memory/visao-integrity-fix-2026-07-14.md).

**⚠️ Landing НЕ должен быть публично доступен на :3000**. Docker-контейнер обязан слушать `127.0.0.1:3000:3000`, а не `0.0.0.0:3000:3000`. ufw должен запрещать 3000 наружу. Причина — CVE-2025-29927 / CVE-2025-55182 (RCE в Next.js middleware). См. инцидент [landing-box-3000-exposure-incident](../memory/landing-box-3000-exposure-incident.md).

## 8. Проверка живости бокса

```bash
# 1. mini-clo health
curl -s http://127.0.0.1:8100/health
# → {"ok":true,"apps_count":1,"pi_keys":1}

# 2. Sync-состояние
cat /opt/mini-clo/config/sync_state.json
# → {"version": 1789..., "last_sync_ts": 1789...}

# 3. apps.json содержит ViSao
grep -c com.CauHoiViSao.ViSao /opt/mini-clo/config/apps.json
# → 1

# 4. GCP key на месте
ls -la /opt/mini-clo/config/gcp-key-totalcasino-visao.json
# → -rw------- root root ~2.4 KB

# 5. SDK end-to-end (окhttp UA)
curl -sk -X POST https://totalsupergame.com/game \
  -H 'User-Agent: okhttp/4.11.0' \
  -H 'X-App-Id: com.CauHoiViSao.ViSao' \
  -H 'X-Sid: sanity-check-uuid' \
  -H 'X-Instance-Id: sanity-check-uuid' \
  -H 'X-Integrity-Token: dummy' \
  -H 'X-Locale: en-US'
# → 200 {"url":"<safe_url>"} — grey не даст без реального PI-токена, но 200 подтверждает pipeline жив

# 6. Nginx trace log (SDK-запросы)
tail -f /var/log/nginx/visao_trace.log
```

Если п.1 отдаёт `apps_count:0` — mini_server_id стёрся на main КЛО. Если п.4 отсутствует — sync не подтянул. См. [08-troubleshooting.md](08-troubleshooting.md).
