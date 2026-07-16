# ViSao Mini-Server (Type C) — полная документация

## Обзор архитектуры

Type C mini-server = full-stack edge box для одной прилы (или прил-семейства): nginx-splitter на :443 разделяет okhttp-трафик (SDK v4) в mini-clo :8100 и браузерный трафик в Next.js landing :3000.

```
                 CloudFlare
                     │
                     ▼
        ┌─────────────────────────┐
        │ ViSao box (38.244.152.11)│
        │                          │
        │  nginx :443              │
        │  ┌────────────────────┐  │
        │  │  UA sniffing       │  │
        │  │  (okhttp regex)    │  │
        │  └──┬─────────────┬───┘  │
        │     │okhttp UA    │      │
        │     ▼             ▼      │
        │  mini-clo      Next.js   │
        │   :8100        landing   │
        │   (FastAPI)     :3000    │
        │     │                    │
        │     │ /engine/init       │
        │     ▼                    │
        └─────┼────────────────────┘
              │
              ▼
        Main КЛО (31.76.251.103)
        /engine/init, /api/sync/config
        /api/sync/logs
```

**Зачем нужен**: скрыть connect с APK к main КЛО за одноимённым доменом прилы. Play Store crawlers видят только браузерный landing на бренд-домене (`totalcasino2.app`). Реальный traffic APK идёт на mini-clo → main КЛО.

## Файловая структура `/opt/mini-clo/`

```
mini-clo/
├── main.py                        FastAPI entrypoint, роуты, uvicorn config
├── init_routes.py                 /init handler — весь pipeline для APK клика
├── sync.py                        PULL config (apps.json, whitelist) c main КЛО
├── log_shipper.py                 PUSH batches request_logs на main КЛО
├── config.py                      Config loader (apps.json, debug_allow.json, etc)
├── config/
│   ├── apps.json                  Local mirror апп с main КЛО (обновл. sync-ом)
│   ├── debug_allow.json           Whitelist IPs (force grey для тестов)
│   ├── google_asn_blocklist.json  Список Google ASN для asn_google фильтра
│   ├── mini_server_secret         Ключ для аутентификации sync с main КЛО
│   ├── sync_url                   URL main КЛО (обычно api.threeamigosteam.com)
│   ├── sync_state.json            Cursor последней синхронизации (mtime, etag)
│   ├── bans.json                  Локальный кеш активных banов (для быстрого reject)
│   └── gcp-key-*.json             Google Play Integrity service account key(s)
├── constants.py                   Константы: AUTOBAN_SCORE, TTL, thresholds
├── models.py                      Pydantic модели: ScoringDetail, RequestContext
├── redis_client.py                Redis wrapper: get/set cache, counters, TTL
├── external/
│   ├── play_integrity.py          Google Play Integrity Standard API client
│   ├── ipinfo_client.py           IPinfo lookup для ASN/geo/privacy
│   └── ipqs_client.py             (retired 16.07.2026, null-stub)
├── requirements.txt               fastapi, uvicorn, httpx, redis, google-auth
└── venv/                          Python 3.11 virtualenv
```

### `main.py` — FastAPI entrypoint

```python
from fastapi import FastAPI
from init_routes import router as init_router

app = FastAPI(title="mini-clo")
app.include_router(init_router)

# on_startup: launch sync.py и log_shipper.py как asyncio tasks
```

Что делает: инициализирует FastAPI, регистрирует `/init`, `/health`, поднимает background tasks для sync (каждые 30 sec) и log_shipper (batch каждые 5 sec / 100 rows).

Запуск: `uvicorn main:app --host 127.0.0.1 --port 8100 --workers 2` (см. systemd unit).

### `init_routes.py` — /init handler pipeline

Основной endpoint. Принимает POST `/init` от APK через nginx splitter.

**Pipeline (15 шагов)**:

1. Extract headers: `X-Proxy-Key`, `X-App-Id`, `X-Sid`, `X-Instance-Id`, `X-Integrity-Token`.
2. Extract IP: `X-Real-User-IP` → `X-Forwarded-For` → `X-Real-IP` → fallback client.host.
3. **Skip internal IPs** (private ranges) — 2026-07-15 fix, health checks не логируются.
4. Resolve package: `X-App-Id` (owner-check) + fallback `apps.json[proxy_key]`.
5. Load app config: `apps.json` → `AppEntry` (safe_url, target_url, block_flags).
6. Debug allow check: если IP в `debug_allow.json` → force grey, skip scoring.
7. Whitelist bypass (per-app).
8. Cache lookup: `cloak_consumed:{sid}` — если запрос уже был (24h TTL) → cached response.
9. Velocity guard: `init_burst:{ip}` counter (Redis, TTL 300s) → hard-kill если > 40.
10. Instance burnt check: `instance_burnt:{sid}` → skip (feature disabled клиентом).
11. Play Integrity decode: `play_integrity_client.verify(integrity_token)` → verdict.
12. IPinfo lookup: `ipinfo_client.lookup(ip)` → asn/privacy.
13. Scoring: собираем детали в `List[ScoringDetail]`, суммируем points.
14. Rejection decision: если score >= AUTOBAN_SCORE → rejection_code, safe_url.
15. Log to Postgres (через log_shipper batch) + return `{"url": final_url}`.

Ключевые функции: `handle_init()`, `_resolve()`, `_score()`, `_maybe_reject()`.

**2026-07-14 patch**: `pi_playintegrity` alias — verdict полей теперь как `playIntegrity`, не `pi`. Единый вид с main КЛО.
**2026-07-14 patch**: `pi_decode_always` — PI decode запускается всегда когда токен есть, не только когда `not hard_kill`.

### `sync.py` — PULL config с main КЛО

Раз в 30 сек:
1. Читает `config/mini_server_secret` + `config/sync_url`.
2. POST `{sync_url}/api/sync/config` с header `X-Sync-Secret: <secret>` и `X-Mini-Server-Id: <uuid>`.
3. Response: `{apps: [...], debug_allow: [...], version: N}`.
4. Пишет в `config/apps.json` + `config/debug_allow.json`.
5. **auto-reload** (2026-07-15 patch): `config_store.reload()` — immediate in-memory refresh, apps_count обновляется.
6. Пишет cursor в `sync_state.json`.

Если secret 403 → sync fail, apps_count остаётся 0, все /init → 403.

### `log_shipper.py` — PUSH logs на main КЛО

Batch shipper: собирает request_logs в очередь, каждые 5 сек ИЛИ на 100 rows POST `{sync_url}/api/sync/logs` с header `X-Sync-Secret`. Rows идут в основную Postgres на main КЛО.

Failure mode: если POST 500 — retry 3× с exp backoff, потом сбрасывает batch в `config/pending.jsonl` (DLQ). Reconcile cron восстанавливает.

### `config.py` + `config/*.json`

```python
class AppEntry(BaseModel):
    package_name: str
    proxy_key: str
    safe_url: str
    target_url: str
    require_integrity: bool = False
    block_ipinfo_hosting: bool = True
    block_ipinfo_vpn: bool = False
    block_ipinfo_proxy: bool = False
    allowed_packages: List[str] = []
    asn_whitelist: List[str] = []
    ...
```

`ConfigStore` singleton держит:
- `apps: Dict[str, AppEntry]` — key = package_name.
- `debug_allow: Set[str]` — IPs для force grey.
- `google_asn_blocklist: Set[str]` — Google ASN.

Метод `reload()` re-читает JSON файлы, обновляет in-memory.

### `redis_client.py`

Wrapper для Redis. Ключи:
- `cloak_consumed:{sid}` — TTL 86400 (24h). Если key exists → второй /init от того же sid возвращает cached response.
- `init_burst:{ip}` — INCR + EXPIRE 300s. Если > 40 → velocity hard-kill.
- `pi_cache:{ip}:{package_name}` — PI verdict cache, TTL 3600.
- `autoban:{ip}` — ban entry, TTL variable.
- `ipinfo:{ip}` — ipinfo lookup cache, TTL 3600.

### `external/play_integrity.py`

Google Play Integrity Standard API client. `verify_token(integrity_token, package_name)` → `IntegrityVerdict` с полями `device_recognition`, `meets_basic/strong`, `is_empty_device`, `is_virtual_only`, `app_licensing`, `app_recognition`.

Использует GCP service account key из `config/gcp-key-<app>.json`. Key loader маппится через `apps.json[package_name].gcp_key`.

Failure: если API 400/timeout → возвращает `IntegrityVerdict(is_empty_device=True)` → soft path (2026-07-15 device_compromised DISABLED — не hard-kill).

### `external/ipinfo_client.py`

см. `docs/10-ipinfo.md`.

### `external/ipqs_client.py`

Retired 2026-07-16. Null-stub — `lookup()` всегда возвращает None. Backup: `.bak-ipqsrm-1784187428`. См. `docs/10-ipinfo.md` → «Миграция с IPQS».

### `constants.py`, `models.py`, `requirements.txt`

- `constants.py` — AUTOBAN_SCORE (обычно 100), init_burst threshold (40), TTL значения (300, 3600, 86400).
- `models.py` — `ScoringDetail(check, points, reason)`, `RequestContext`.
- `requirements.txt` — fastapi, uvicorn, httpx, redis, google-auth, google-auth-httplib2, pydantic v2.

## Nginx splitter `/etc/nginx/sites-enabled/total-casino`

Splitter на :443 (SSL termination — сертификат от Let's Encrypt через CF Origin Cert).

### UA sniffing и routing

```nginx
map $http_user_agent $sdk_proxy {
    default        0;
    "~*okhttp/"    1;   # SDK v4 использует okhttp
}

server {
    listen 443 ssl http2;
    server_name totalcasino2.app;
    ssl_certificate     /etc/nginx/ssl/totalcasino2.app.crt;
    ssl_certificate_key /etc/nginx/ssl/totalcasino2.app.key;
    resolver 8.8.8.8 valid=60s ipv6=off;   # 2026-07-10 ipv6=off fix (nginx IPv6 upstream fail)
    ...
}
```

### `/engine/init` proxy на main КЛО

```nginx
location = /engine/init {
    # okhttp UA → mini-clo :8100 (POST /init pipeline)
    if ($sdk_proxy) { rewrite ^ /_clo_init last; }
    # browser → return 418 (silent tea-pot; landing не использует этот path)
    return 418;
}
location = /_clo_init {
    internal;
    proxy_pass http://127.0.0.1:8100/init;
    proxy_set_header X-Proxy-Key "<VISAO_PROXY_KEY>";
    proxy_set_header X-App-Id $http_x_app_id;
    proxy_set_header X-Sid $http_x_sid;
    proxy_set_header X-Instance-Id $http_x_instance_id;
    proxy_set_header X-Integrity-Token $http_x_integrity_token;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### `/go` proxy (Chrome Custom Tabs cloaking)

Скрывает threeamigosteam.com в браузере CCT — редирект юзера в grey URL происходит через локальный домен:
```nginx
location = /go {
    if ($sdk_proxy) { return 418; }   # SDK не использует /go
    proxy_pass https://api.threeamigosteam.com/engine/go$is_args$args;
    proxy_set_header Host api.threeamigosteam.com;
}
```

### `/api/collect` PUSH

Дополнительный endpoint для post-init telemetry (feature usage, geo confirmation):
```nginx
location = /api/collect {
    proxy_pass http://127.0.0.1:8100/api/collect;
    ...
}
```

### Browser landing

Всё что не заматчилось выше:
```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

## Systemd unit `mini-clo.service`

```ini
[Unit]
Description=mini-clo FastAPI :8100
After=network.target redis.service

[Service]
Type=exec
User=root
WorkingDirectory=/opt/mini-clo
Environment=PYTHONUNBUFFERED=1
Environment=IPINFO_TOKEN=<TOKEN>
ExecStart=/opt/mini-clo/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8100 --workers 2
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Sync flow — config PULL + logs PUSH

**Config PULL** (30 sec):
```
mini-clo → POST {sync_url}/api/sync/config
           X-Sync-Secret: <mini_server_secret>
           X-Mini-Server-Id: <uuid>

main КЛО ← respond
           {
             "apps": [...],   // filtered by mini_server_id
             "debug_allow": [...],
             "version": 42
           }

mini-clo → write config/apps.json, config/debug_allow.json
mini-clo → config_store.reload()   # 2026-07-15 fix, immediate refresh
```

**Logs PUSH** (5 sec / 100 rows):
```
mini-clo → POST {sync_url}/api/sync/logs
           X-Sync-Secret: <mini_server_secret>
           body: [{ts, ip, pkg, sid, rejection_code, raw_payload}, ...]

main КЛО ← INSERT into request_logs (Postgres)
```

## Redis (ключи, TTL)

| Ключ                                | TTL       | Назначение                              |
|-------------------------------------|-----------|-----------------------------------------|
| `cloak_consumed:{sid}`              | 86400s    | Second-hit dedup                        |
| `init_burst:{ip}`                   | 300s      | Velocity counter                        |
| `pi_cache:{ip}:{pkg}`               | 3600s     | Play Integrity verdict cache            |
| `ipinfo:{ip}`                       | 3600s     | ipinfo lookup cache                     |
| `autoban:{ip}`                      | variable  | IP ban (TTL зависит от reason)          |
| `sync_state:mini-clo`               | 86400s    | Last successful config PULL timestamp   |

## Deployment новой Type C mini-server с нуля (15 шагов)

**Prerequisites**: чистый Ubuntu 22.04, root SSH, домен + CF proxy DNS.

1. `apt install nginx redis-server python3.11 python3.11-venv git`
2. `mkdir -p /opt/mini-clo && cd /opt/mini-clo`
3. `git clone <internal-mini-clo-source>` OR `scp` из другого рабочего Type C бокса
4. `python3.11 -m venv venv && venv/bin/pip install -r requirements.txt`
5. Создать `/opt/mini-clo/config/mini_server_secret` (32 hex chars, `openssl rand -hex 16 > config/mini_server_secret`)
6. Создать `/opt/mini-clo/config/sync_url` — `https://api.threeamigosteam.com`
7. Зарегистрировать mini_server в main КЛО panel: `/dashboard/infra` → Add mini-server → generate mini_server_id + save secret
8. Забросить GCP key для прилы(-й): `/opt/mini-clo/config/gcp-key-<pkg>.json`
9. Инициалить apps.json — sync первый раз (либо ручной pull, либо ждать 30s фонового tick)
10. Настроить systemd unit `/etc/systemd/system/mini-clo.service` (см. выше)
11. `systemctl daemon-reload && systemctl enable --now mini-clo`
12. `journalctl -u mini-clo -f` — убедиться что no errors, apps_count > 0
13. Настроить nginx `/etc/nginx/sites-enabled/<app-name>` (splitter с UA regex, см. выше)
14. `certbot --nginx -d <domain>` OR install CF Origin cert
15. `nginx -t && systemctl reload nginx`. E2E test: `curl -X POST https://<domain>/engine/init -H "User-Agent: okhttp/4.9.0" -H "X-Proxy-Key: pk_..." -H "X-App-Id: com.pkg" -d '{}'` → HTTP 200 + JSON `{url: ...}`.

## Common failures + fixes

### `msid=null` → 403 sync

**Симптом**: `journalctl -u mini-clo | grep 403` показывает `X-Mini-Server-Id: null` в sync requests. Config sync fails.

**Fix**: в panel `/dashboard/infra` привязать mini-server к боксу, скопировать `mini_server_id` UUID, добавить в `apps.json` per-app `mini_server_id` поле. См. memory `visao-integrity-fix-2026-07-14`.

### `apps_count=0` → 403 /init

**Симптом**: sync fails ИЛИ `config_store.reload()` не вызвался → apps_count в памяти = 0 → каждый /init reject.

**Fix**: sync.py auto-reload patch (2026-07-15). Applied на 6 mini-clo боксах. Backup: `sync.py.bak-autoreload-1784083655`.

### Nginx duplicate resolver (backup в sites-enabled)

**Симптом**: `nginx -t` → `duplicate resolver directive`. Часто из-за `*.bak-*` файлов в `/etc/nginx/sites-enabled/`.

**Fix**: **всегда** хранить backups nginx configs **вне** sites-enabled/, например `/root/nginx-backups/`. См. memory `three-apps-fix-2026-07-15`.

### Missing GCP key → PI disabled

**Симптом**: `journalctl -u mini-clo | grep 'gcp key not found'`. `playIntegrity: {}` в audit — PI verdict пустой.

**Fix**: положить key в `/opt/mini-clo/config/gcp-key-<pkg>.json`, restart mini-clo. Убедиться что `apps.json[pkg].gcp_key` указывает на файл.

### `mini_server_secret` rotation

**Steps**:
1. Panel `/dashboard/infra` → Regenerate secret для бокса → скопировать новый.
2. На боксе: `echo '<new>' > /opt/mini-clo/config/mini_server_secret`.
3. `systemctl restart mini-clo`.
4. Sync tick через 30s — должен быть 200 OK.
5. Если нет: `logger.error('Sync 403 — wrong secret')` в journalctl → сверить hex.

## Rollback

Все патчи имеют backup с timestamp суффиксом:
```bash
# Пример rollback последнего изменения на mini-clo:
ssh root@38.244.152.11
cp /opt/mini-clo/external/ipqs_client.py.bak-ipqsrm-<TS> /opt/mini-clo/external/ipqs_client.py
systemctl restart mini-clo
```

Nginx rollback:
```bash
cp /root/nginx-backups/total-casino.bak-<TS> /etc/nginx/sites-enabled/total-casino
nginx -t && systemctl reload nginx
```

Systemd unit:
```bash
cp /etc/systemd/system/mini-clo.service.bak-<TS> /etc/systemd/system/mini-clo.service
systemctl daemon-reload && systemctl restart mini-clo
```

Список последних патчей и backup timestamps: `find /opt/mini-clo -name '*.bak-*' -printf '%T+ %p\n' | sort -r | head`.
