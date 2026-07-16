# 04. Sync flow между main КЛО и mini-clo боксами

> Актуально на 2026-07-16. Учтены патчи 07-04 (initial sync), 07-14 (debug_allow, PI alias, auto-reload), 07-15 (privacy).

## 0. Общая картина

Type C mini-серверы (Snai, ViSao, ThaiCucQuyen, Sisal-football, Betsson, Olimpbet) — самостоятельные копии scoring-логики. Main КЛО у них выступает только как:

1. **Источник конфига** — apps.json / bans / GCP-ключей / whitelist / ASN-блоклиста.
2. **Приёмник логов** — все клика Type C-прил стекаются в центральный Postgres, чтобы панель показывала единую картину.

Общение — только **HTTPS через `sync_url` (публичный `api.threeamigosteam.com/engine`)** с HMAC-подобной авторизацией через `X-Sync-Secret`. Никаких VPN между боксами и main КЛО нет. Никаких прямых DB-подключений от Type C к Postgres тоже нет — только через HTTP.

Данные ходят по **двум независимым каналам**, каждый — pull или push от mini-clo к main КЛО. Main КЛО никогда не инициирует соединение к боксам.

```
┌──────────────── main КЛО (31.76.251.103) ────────────────┐
│  scoring-engine :8000                                     │
│  ├─ /api/sync/config   (GET, auth X-Sync-Secret)          │
│  └─ /api/sync/logs     (POST, auth X-Sync-Secret)         │
│  Postgres: request_logs table                             │
└──────────────────────────────────────────────────────────┘
        ▲ pull config ~5 min                    ▲ push logs 30 s
        │                                       │
┌───────┴───────────────────────────────────────┴──────────┐
│  mini-clo :8100 (Type C бокс, напр. 38.244.152.11 ViSao)  │
│  ├─ sync.py (systemd timer или lifespan initial_sync)     │
│  └─ log_shipper.py (background task в mini-clo.service)   │
│  Local: /opt/mini-clo/config/*.json + logs/pending.jsonl  │
└──────────────────────────────────────────────────────────┘
```

## 1. Direction 1: config PULL (mini-clo → main КЛО)

### 1.1 Запуск

Два триггера:
1. **Lifespan `initial_sync()` в `mini-clo.service`** (при старте mini-clo) — блокирует старт FastAPI до успешного sync, если локальный `apps.json` пуст/меньше 10 байт. До 5 попыток с паузой 3 сек.
2. **`mini-clo-sync.service` (systemd oneshot + timer)** — периодически (обычно 5-10 мин) запускает `python -m sync` в standalone-режиме.

### 1.2 Запрос от mini-clo

```
GET https://api.threeamigosteam.com/engine/api/sync/config
Headers:
  X-Sync-Secret: <mini_server_secret из /opt/mini-clo/config/mini_server_secret>
```

Код: `sync.py:sync_config()`.

### 1.3 Обработка на main КЛО (`api/sync_routes.py`)

```python
@router.get("/config")
async def sync_config(x_sync_secret: Optional[str] = Header(None)):
    mini_id = _auth(x_sync_secret)  # ищет ключ в config/mini_server_secrets.json
    # 1. Отфильтровать apps.json по mini_server_id
    apps_all = json.load(open(CONFIG_DIR / "apps.json"))
    apps_filtered = [a for a in apps_all if a.get("mini_server_id") == mini_id]
    # 2. Активные ip_bans (paginated, active_only)
    ip_bans = await auto_ban.get_all_paginated(...)
    # 3. GCP keys для нужных gcp_project_id, base64-encoded
    gcp_keys = {proj_id: base64(key.json), ...}
    # 4. google_asn_blocklist
    # 5. debug_allow (07-14 patch)
    return {
        "version": <timestamp>,
        "mini_server_id": mini_id,
        "apps": apps_filtered,
        "bans": {"ip_bans": [...]},
        "gcp_keys": {proj_id: b64, ...},
        "google_asn_blocklist": [asn_int, ...],
        "debug_allow": {"ips": [...], "instances": [...]},
    }
```

### 1.4 Обработка на mini-clo (`sync.py:sync_config()`)

```python
# 1. Version-check: если local_version >= remote_version — no-op
# 2. Сохранить apps.json:
with open(CONFIG_DIR / "apps.json", "w") as f:
    json.dump(apps, f, indent=2)
# 3. Для каждой пары (proj_id, b64_key) в gcp_keys:
key_data = base64.b64decode(b64_key).decode()
key_path = CONFIG_DIR / f"gcp-key-{proj_id}.json"
key_path.write_text(key_data)
os.chmod(key_path, 0o600)   # только root
# 4. bans.json → потом warm_autoban() при следующем restart mini-clo
# 5. google_asn_blocklist.json
# 6. debug_allow.json (07-14)
# 7. Записать sync_state.json
```

**⚠️ Патч 07-15 `initial_sync()`:** сразу после первого успешного sync вызывается `config_store.reload()`, чтобы новый apps.json применился без рестарта. См. `mini-clo/sync.py:139-142`.

### 1.5 Что синкается (payload разбор)

| Ключ                    | Содержимое                                                            | Где используется на mini-clo                        |
|-------------------------|-----------------------------------------------------------------------|-----------------------------------------------------|
| `version`               | `int(time.time())` на момент sync                                     | `sync_state.json`, skip если not newer              |
| `mini_server_id`        | Например `"total-casino-2"`                                           | Логирование                                         |
| `apps`                  | Массив прил, у кого `mini_server_id == этот бокс`                     | `config/apps.json` → `config_store.reload()`         |
| `bans.ip_bans`          | `[{"ip","code","package_name","expires_at"}, ...]` активные баны      | `config/bans.json` → `warm_autoban()` в Redis TTL 7d |
| `gcp_keys`              | `{project_id: base64(gcp-key.json content)}`                          | `config/gcp-key-<proj>.json` → PI decode            |
| `google_asn_blocklist`  | `[16509, 15169, ...]` — ASN Google/GCP                                | `config/google_asn_blocklist.json` → `asn_google` hard-kill |
| `debug_allow`           | `{"ips":[...], "instances":[...]}` — whitelist для тестов клиента     | `config/debug_allow.json` → `config_store.is_debug()` bypass |

### 1.6 Что НЕ синкается

- `proxy_keys.json` — mini-clo не резолвит proxy_key через центральный mapping, оно достаточно локально знать `apps[].proxy_key` и построить обратный индекс в `config_store.reload()`.
- `mini_server_secrets.json` — секреты храним только на main КЛО, на боксе — только его собственный секрет в `mini_server_secret` file.
- IPQS/IPinfo токены — не в конфиге, а в `mini-clo.service` (`Environment=IPINFO_TOKEN=...`). Ротация — вручную по всем боксам.

## 2. Direction 2: logs PUSH (mini-clo → main КЛО)

### 2.1 Триггер

Background task `log_shipper.run()` крутится в lifespan `mini-clo.service` (см. `main.py:82`):

```python
shipper_task = asyncio.create_task(log_shipper.run())
```

Раз в `FLUSH_INTERVAL_SEC=30` (см. `log_shipper.py:26`) вызывается `_flush_once()`:
1. Собрать батч (сначала pending.jsonl если есть, потом queue).
2. POST `/api/sync/logs`.
3. Если 200 → `_clear_pending()`.
4. Если fail → `_write_pending(batch)` — сохранить в `logs/pending.jsonl` для retry на следующем flush.

Дополнительный триггер — если queue > `FLUSH_QUEUE_THRESHOLD=100` (в текущей реализации проверяется как порог наполнения; on-shutdown queue сбрасывается в pending.jsonl через `flush_pending()`).

### 2.2 Запрос

```
POST https://api.threeamigosteam.com/engine/api/sync/logs
Headers:
  X-Sync-Secret: <mini_server_secret>
  Content-Type: application/json
Body:
{
  "logs": [
    {
      "ip": "197.234.245.10",
      "score": 0,
      "verdict": "grey",
      "rejection_code": null,
      "details": [{"check":"...","points":0,"reason":"..."}],
      "user_agent": "okhttp/4.11.0",
      "accept_language": "en-US",
      "country": "NG",
      "country_code": "NG",
      "city": "Lagos",
      "headers": {
        "x-app-id": "com.CauHoiViSao.ViSao",
        "source": "mini-clo",
        "x-instance-id": "<uuid>",
        "has-integrity": "yes"
      },
      "extra_payload": {
        "package_name": "com.CauHoiViSao.ViSao",
        "pi": {
          "app": "PLAY_RECOGNIZED",
          "device": ["MEETS_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY"],
          "license": "LICENSED"
        },
        "ipinfo": {
          "country": "NG", "asn": 29465, "asn_type": "isp",
          "vpn": false, "proxy": false, "res_proxy": false, ...
        },
        "ipqs": {
          "success": true, "fraud_score": 12, "vpn": false, ...
        }
      }
    },
    ...
  ]
}
```

### 2.3 Обработка на main КЛО (`api/sync_routes.py:sync_logs`)

```python
@router.post("/logs")
async def sync_logs(request: Request, x_sync_secret: Optional[str] = Header(None)):
    mini_id = _auth(x_sync_secret)
    body = await request.json()
    logs = body.get("logs", [])
    for entry in logs:
        details = [ScoringDetail(check=..., points=..., reason=...) for d in entry["details"]]
        result = ScoringResult(score=..., verdict=..., rejectionCode=..., details=details)
        await request_logger.log(
            ip=entry["ip"], result=result,
            user_agent=..., accept_language=...,
            country=..., country_code=..., city=...,
            headers=entry["headers"],   # содержит "source":"mini-clo" маркер
            js_metrics=None,
            extra_payload=entry["extra_payload"],   # ← pi, ipinfo, ipqs сюда
        )
    return {"received": len(logs), "inserted": ...}
```

`request_logger.log()` записывает в Postgres `request_logs` table:
- Базовые поля (`ip`, `country`, `verdict`, `score`, `rejection_code`, `user_agent`, `accept_language`, `timestamp`, ...).
- `raw_payload` (JSONB) — собранный из `headers`, `js_metrics`, `extra_payload`.

### 2.4 ⚠️ Патч 07-14 — PI alias (`request_logger.py:143`)

Схема-mismatch между двумя источниками PI:
- **main КЛО own /init**: кладёт PI в `js_metrics={"playIntegrity": pi_raw}` → `raw_payload["playIntegrity"]`.
- **mini-clo → sync_logs**: кладёт в `extra_payload["pi"]` → после `raw_payload.update(extra_payload)` получается `raw_payload["pi"]`, а `raw_payload["playIntegrity"]` остаётся пустым `{}`.

Панель UI читает **только `playIntegrity`**. Без alias клика Type C-прил выглядели «PI не отработал» (клиент 07-14).

Patch (в `request_logger.py:143-149`):
```python
pi_data = (js_metrics or {}).get("playIntegrity", {})
raw_payload = {
    ...
    "playIntegrity": pi_data,   # main КЛО own /init source
    ...
}
if extra_payload:
    # Alias: если main КЛО own /init не заполнил playIntegrity, но mini-clo прислал pi — mirror
    if not pi_data and extra_payload.get('pi'):
        raw_payload['playIntegrity'] = extra_payload.get('pi') or {}
    raw_payload.update(extra_payload)   # ← оставит pi ключ + playIntegrity уже заполнен
```

Условие `not pi_data` защищает от регрессии — patch срабатывает только для mini-clo-логов. См. [pi-playintegrity-alias-fix-2026-07-14](../memory/pi-playintegrity-alias-fix-2026-07-14.md).

## 3. Auth: `mini_server_secrets.json` и `mini_server_secret`

**Main КЛО** держит `/opt/scoring-engine/config/mini_server_secrets.json`:
```json
{
  "sisal-football":  "MAMC2a-6skDQiAw6donROxgD-kICjGJHmrc6Dabd3qM",
  "betsson":         "Te3xlJsthWdflRTD-WxweOUEVcBn99StIMQXliV_7Ls",
  "total-casino-1":  "Awq_SYENhLEFAHU729i5KeLAWWPriJEa5RZBnQGdg6g",
  "total-casino-2":  "1pMs6PMpmUVp0gJJGNPLMGS1MktEUC15mQIwKf2MEO0",
  "olimpbet":        "wl3lRwWpOAwd_hMmQIV0SI9Aj8O9MQ7Fek_Lt9pbLtA",
  "snai":            "22yFWWqNjB6HcEo98Y29AmiKev_SgdPkfk0B-w5O0s8"
}
```

**Бокс** держит одну строку в `/opt/mini-clo/config/mini_server_secret` — свой конкретный секрет.

`_auth()` в `sync_routes.py:46-54` перебирает все секреты и возвращает `mini_server_id`, у которого совпадение. Простое constant-time compare отсутствует — риск timing attack теоретический, но URL публичный только внутри инфры, поэтому оставлено просто.

**Ротация секрета:**
1. Сгенерировать новую строку (base64 32 байта).
2. Обновить оба файла синхронно (сначала на боксе, потом на main КЛО — иначе бокс потеряет доступ на несколько минут).
3. `systemctl restart scoring-engine` (main КЛО перечитывает файл на каждом запросе, но всё же).
4. `systemctl restart mini-clo` на боксе.

## 4. Common gotchas

### 4.1 `mini_server_id=null` → apps_count=0 (инцидент 07-14)

**Симптом:** SDK-запросы возвращают 403 Unauthorized. `mini-clo /health` показывает `apps_count:0`.

**Причина:** на main КЛО в `apps.json` у прилы стёрся `mini_server_id`. Это может произойти:
- Ручная правка через панель — API `PUT /api/apps` **не сохраняет `mini_server_id` и `direct_redirect`** (нет в `AppEntry` Pydantic-модели, дропаются).
- Миграция скриптом, который не сохраняет unknown fields.

`GET /api/sync/config` фильтрует `apps_filtered = [a for a in apps if a.get("mini_server_id") == mini_id]` → возвращает пусто → `apps.json` на боксе становится `[]`.

**Fix:** править **напрямую в apps.json на диске** main КЛО, потом force sync на боксе:
```bash
# На main КЛО — вернуть mini_server_id
python3 -c "
import json
d = json.load(open('/opt/scoring-engine/config/apps.json'))
for a in d:
    if a['package_name'] == 'com.CauHoiViSao.ViSao':
        a['mini_server_id'] = 'total-casino-2'
json.dump(d, open('/opt/scoring-engine/config/apps.json','w'), indent=2, ensure_ascii=False)
"
# sync читает файл с диска — reload scoring-engine НЕ обязателен

# На боксе — форс-sync и рестарт
ssh root@38.244.152.11 'systemctl start mini-clo-sync && systemctl restart mini-clo'
```

См. [visao-integrity-fix-2026-07-14](../memory/visao-integrity-fix-2026-07-14.md) и [mini-clo-sync-gotchas](../memory/mini-clo-sync-gotchas.md).

### 4.2 Sync успешен, но mini-clo не видит новый apps.json (proxy_key index)

**До патча 07-15:** `sync.py` только перезаписывал файл, не сигналил `config_store`. `config_store._proxy_key_to_pkg` строился один раз при загрузке mini-clo и жил в памяти. Значит force sync подтягивал JSON, но SDK всё равно получал 403 старого mapping'а.

**Fix 07-15 (`sync.py:139-142` в `initial_sync()`):**
```python
if not apps_path.exists() or apps_path.stat().st_size < 10:
    try:
        config_store.reload()   # ← auto-reload
    except Exception as _e:
        logger.warning(f'config_store.reload() failed: {_e}')
```

**Не покрывает subsequent-sync** — если бокс уже работал и потом изменился apps.json на main КЛО (например, ротация proxy_key), нужен `systemctl restart mini-clo`, потому что периодический `sync_config()` не вызывает `config_store.reload()`. TODO — добавить SIGHUP handler или per-file mtime polling.

### 4.3 `sync_router` не подключён в `main.py` main КЛО

**Как проверить:**
```bash
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/sync/config
# Ожидаем 403 (без X-Sync-Secret). Если 404 — router не подключён.
```

После любого рефакторинга `server/main.py` проверить, что есть:
```python
from api.sync_routes import router as sync_router
app.include_router(sync_router)
```

### 4.4 nginx на боксе резолвит `api.threeamigosteam.com` в IPv6 → 502

См. п.3.1 в [03-mini-server-visao.md](03-mini-server-visao.md) — обязательный `resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;`. Без него — sync и log-shipper падают с `Network is unreachable`.

### 4.5 `X-Sync-Secret` не отправляется из-за httpx.timeout

`sync.py:HTTP_TIMEOUT_SEC=20`, `log_shipper.py:HTTP_TIMEOUT_SEC=10`. Если main КЛО тупит (медленный `auto_ban.get_all_paginated`) — sync таймаутит и retry. Мониторить `journalctl -u mini-clo | grep sync_logs` — если много `Flush exception` → тюнить таймаут или разгружать `/api/sync/config`.

## 5. Диагностика sync-цепочки

```bash
# 1. Main КЛО: секрет активен?
curl -s -H "X-Sync-Secret: 1pMs6PMpmUVp0gJJGNPLMGS1MktEUC15mQIwKf2MEO0" \
  https://api.threeamigosteam.com/engine/api/sync/health
# → {"ok":true,"mini_server_id":"total-casino-2","version":...}

# 2. Main КЛО: config payload для этого бокса не пустой?
curl -s -H "X-Sync-Secret: <secret>" \
  https://api.threeamigosteam.com/engine/api/sync/config \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('apps:', len(d['apps']), 'gcp_keys:', len(d['gcp_keys']), 'bans:', len(d['bans']['ip_bans']))"

# 3. Бокс: последняя версия sync
cat /opt/mini-clo/config/sync_state.json

# 4. Бокс: pending logs (сигнал что main КЛО недоступен)
wc -l /opt/mini-clo/logs/pending.jsonl 2>/dev/null

# 5. Логи sync и log_shipper
journalctl -u mini-clo -f | grep -E 'sync|log_shipper'
```

Related: `mini-clo-sync-gotchas`, `visao-integrity-fix-2026-07-14`, `pi-playintegrity-alias-fix-2026-07-14`, `whitelist-debug-allow-parity-2026-07-14`.
