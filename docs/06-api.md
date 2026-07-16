# API endpoints — справочник (main КЛО + mini-clo)

Полный перечень всех HTTP endpoints с request/response schema, auth, примерами curl.

**Базовые URL**:
- Main КЛО: `https://api.threeamigosteam.com` (origin `31.76.251.103:8000` за nginx + CF Worker).
- Mini-clo ViSao: `https://totalsupergame.com` (origin `38.244.152.11`, mini-clo `127.0.0.1:8100` за nginx).

**Auth headers**:
- `X-Admin-Key` — админ-API панели (main КЛО), see `main.py:ADMIN_PREFIXES`.
- `X-Sync-Secret` — mini-clo → main КЛО `/api/sync/*` (per-`mini_server_id`).
- `X-Proxy-Key` — SDK → любой /init (per-app из proxy_keys.json).
- `X-Edge-Signature` + `X-Edge-Timestamp` — HMAC от CF Worker на `/init`, `/web_content`, `/api/collect`, `/api/integrity/verify`.

---

## Часть I. Main КЛО

### 1. `/init` — SDK resolve (main hot path)

**Auth**: `X-Proxy-Key` header **или** `?proxy_key=` query.
**Methods**: `GET`, `POST` (POST добавлен 2026-07-09 для SDK v4).
**Rate limit**: 100 req/min/proxy_key → 200 с safe URL.
**Middleware**: EdgeAuthMiddleware (HMAC HMAC-SHA256), RateLimitMiddleware.

**Request headers (все опциональные кроме X-Proxy-Key)**:

| Header | Что | Пример |
| --- | --- | --- |
| `X-Proxy-Key` | Ключ прилы | `pk_daf8bde087935e228e4289bfa9155af1` |
| `X-App-Id` | Package name (override когда 1 proxy_key = много прил) | `com.mazourbn.jaberbagh` |
| `X-Instance-Id` | UUID устройства (SharedPreferences) | `b3f5a1c2-...` |
| `X-Integrity-Token` | Play Integrity JWE token | `eyJhbGciOiJSUzI1...` |
| `X-Real-User-IP` | Настоящий IP клиента (от mini-server nginx, CF не трогает custom) | `102.91.103.241` |
| `X-Forwarded-For` | Стандартный | `102.91.103.241, 172.68.238.20` |
| `X-Locale` | Локаль (SDK v4) | `it-IT` |
| `Accept-Language` | Стандартный | `en-US,en;q=0.9,it;q=0.8` |
| `User-Agent` | UA | `okhttp/4.12.0` |
| `X-Edge-Signature` | HMAC от CF Worker | 64-hex |
| `X-Edge-Timestamp` | Unix seconds | `1721139600` |
| `X-CF-Country` | ISO-2 country от CF | `IT` |
| `X-CF-ASN` | ASN от CF | `12874` |

**Query params (fallback для legacy SDK)**:
- `proxy_key`, `app_id`, `instance_id`, `integrity_token`, `locale`.

**Response** — **всегда** 200 + JSON (кроме 403 при unknown proxy_key):

```json
{"url": "https://api.threeamigosteam.com/engine/go?t=aHR0cHM6Ly9jYXNpbm8u..."}
```

Или для white:
```json
{"url": "https://sportivewave.com/game_app"}
```

Или 403:
```json
{"error": "Unauthorized"}
```

**curl пример**:
```bash
curl -X POST 'https://api.threeamigosteam.com/init' \
  -H 'X-Proxy-Key: pk_daf8bde087935e228e4289bfa9155af1' \
  -H 'X-App-Id: com.mazourbn.jaberbagh' \
  -H 'X-Instance-Id: 11111111-2222-3333-4444-555555555555' \
  -H 'X-Integrity-Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...' \
  -H 'X-Real-User-IP: 102.91.103.241' \
  -H 'User-Agent: okhttp/4.12.0' \
  -H 'Accept-Language: en-NG'
```

---

### 2. `/api/init-trace` — trace mode (админский)

**Auth**: `X-Admin-Key`.
**Method**: `GET`.

Тот же pipeline как `/init` но с populated trace dict. **Не** пишет в Postgres (test probe не засоряет audit).

**Response**:
```json
{
  "verdict": "white",
  "url": "https://safe...",
  "package_name": "com.example",
  "classification": {"class": "moder_bot", "confidence": "high", "signals": ["asn_google"]},
  "trace": {
    "pipeline_steps": [
      {"step": "proxy_key_lookup", "status": "passed", "reason": "package=com.example"},
      {"step": "instance_burnt", "status": "passed", "reason": ""},
      {"step": "asn_google", "status": "fired", "reason": "ASN 15169 в blocklist"}
    ],
    "ip": "8.8.8.8", "instance_id": "...", "has_integrity": true,
    "geo": {"country": "US", "asn": 15169, "org": "AS15169 Google LLC", ...},
    "ipqs": {"fraud_score": 100, "vpn": false, "tor": false, ...},
    "country": "US", "asn": 15169, "isp": "Google LLC", "city": "Mountain View",
    "score_buckets": {"base": 100, "pi": 0, "vel": 0, "extra": 0, "total": 100},
    "hard_kill": {"code": "asn_google", "reason": "Hard-block: ASN 15169 в Google/Accenture blocklist"},
    "all_details": [{"check": "asn_google", "points": 100, "reason": "..."}],
    "rejection_code": "asn_google",
    "threshold": 70,
    "classification": {...}
  }
}
```

**curl**:
```bash
curl 'https://api.threeamigosteam.com/api/init-trace?proxy_key=pk_...' \
  -H 'X-Admin-Key: <admin-key>' \
  -H 'X-Real-User-IP: 8.8.8.8' \
  -H 'X-Instance-Id: probe-uuid' \
  -H 'User-Agent: okhttp/4.12.0'
```

---

### 3. `/engine/go` (a.k.a. `/go`) — bounce redirect

**Auth**: нет.
**Method**: `GET`.

Instant 302 на decoded target URL (base64-urlsafe в `?t=`). Fix 2026-07-04 (fix9) — раньше показывал Turnstile bounce.

**Query params**: `t=<base64-urlsafe>` (обязательно).

**Response**:
- 302 → `Location: <decoded target>`.
- 404 если `t` пуст, невалидный base64, или не начинается с `http(s)://`.

**curl**:
```bash
curl -v 'https://api.threeamigosteam.com/engine/go?t=aHR0cHM6Ly9jYXNpbm8uY29tLz9jbGlja2lkPTEyMyZnZW89SVQ='
# → HTTP/2 302, Location: https://casino.com/?clickid=123&geo=IT
```

---

### 4. `/web_content` — legacy WebView redirect

**Auth**: `X-Proxy-Key`.
**Method**: `GET`.

Возвращает 302 на resolved URL (тот же pipeline что `/init`). Для SDK v3 который открывает URL в WebView вместо parsing JSON.

Без `X-Proxy-Key` → HTML заглушка `stub.html` (200).
Unknown key → та же заглушка.

**curl**:
```bash
curl -v 'https://api.threeamigosteam.com/web_content' \
  -H 'X-Proxy-Key: pk_...' -H 'X-App-Id: com.example' \
  -H 'X-Instance-Id: uuid' -H 'X-Integrity-Token: eyJ...'
```

---

### 5. `/api/collect` (a.k.a. `/api/analytics/event`) — tracker.js pixel

**Auth**: нет (защищено EdgeAuth HMAC).
**Method**: `POST`.
**Body limit**: 65_536 bytes (413 при превышении).

**Request headers**: `X-App-Id`, `X-Package-Name`, `X-Instance-Id`, `X-Forwarded-For`.

**Body** (JSON):
```json
{
  "userAgent": "Mozilla/5.0 ...",
  "hardware": {"platform": "Linux armv8l"},
  "webgl": {"renderer": "Adreno (TM) 640", "vendor": "Qualcomm"},
  "accelerometer": {"averageDeviation": 0.15, "samples": 20},
  "input": {"mouseClicks": 5, "touchEvents": 3, "touchSupported": true, "maxActionsPerSec": 4},
  "battery": {"level": 0.87, "chargingTime": 3600},
  "timezone": "Europe/Rome",
  "language": "it-IT",
  "languages": ["it-IT", "en-US"],
  "instance_id": "..."
}
```

**Response**:
```json
{"received": true}
```

Score/verdict/details **не отдаются** (иначе модер видит вердикт в DevTools).

**Внутри**: 
1. `scoring_engine.score_js_metrics(data, ip, package_name)` — JS anti-fraud.
2. `_detect_cloak_bypass(ip, pkg, country, iid)` — сравнение country /init vs /collect (multi-network attack). Burn instance + auto_ban при mismatch.
3. `request_logger.log()` с `source="js-tracker"`.

**curl**:
```bash
curl -X POST 'https://api.threeamigosteam.com/api/collect' \
  -H 'Content-Type: application/json' \
  -H 'X-Package-Name: com.example' \
  -H 'X-Instance-Id: uuid' \
  -d '{"userAgent":"Mozilla/5.0","webgl":{"renderer":"Adreno"},"input":{"touchSupported":true}}'
```

---

### 6. `/api/integrity/nonce` (a.k.a. `/api/security/token`) — nonce issue

**Auth**: нет.
**Method**: `GET`.
**Rate limit**: 10 req/min/IP → 429.

Генерирует `sha256(token_hex(32))` nonce и сохраняет в Redis `nonce:{sha256}` c IP как value, TTL 300s. Клиент передаёт этот nonce в PI request (Google подпишет и включит в verdict).

**Response**:
```json
{"nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ttl": 300}
```

**curl**:
```bash
curl https://api.threeamigosteam.com/api/integrity/nonce
```

---

### 7. `/api/integrity/verify` (a.k.a. `/api/security/validate`) — PI decode + score

**Auth**: EdgeAuth HMAC.
**Method**: `POST`.
**Content-Type**: `application/json`.

**Body** (Pydantic strict):
```json
{
  "integrityToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",  // max 4096 chars
  "nonce": "e3b0c4..."                                            // max 128 chars, optional
}
```

`extra='forbid'` — неизвестные поля → 422.

**Внутренне**:
1. Валидация nonce в Redis (unknown/expired → 403 `integrity_invalid`, IP mismatch → 403).
2. Google PI API decode.
3. Nonce match check (token nonce vs body nonce).
4. Timestamp freshness (>120s → 403 `integrity_stale`).
5. Scoring: empty_device (soft-log 2026-07-15), virtual_only (soft-log), no BASIC (soft-log), no DEVICE with BASIC → +50, UNEVALUATED app → +100 `app_tampered`, UNRECOGNIZED_VERSION → +30, cert mismatch → +100 `cert_mismatch`, UNLICENSED → +30.
6. Final: `verdict = "white" if total >= threshold else "grey"`.
7. Redis cache PI verdict (для последующих scoring calls).

**Response** (200):
```json
{
  "verified": true,
  "score": 30,
  "verdict": "grey",
  "rejectionCode": null,
  "integrity": {
    "deviceRecognition": ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"],
    "appRecognition": "PLAY_RECOGNIZED",
    "appLicensing": "LICENSED",
    "meetsBasic": true, "meetsDevice": true, "meetsStrong": false
  },
  "details": [
    {"check": "play_integrity_license", "points": 30, "reason": "App licensing: LICENSED"}
  ]
}
```

**Response error** (403):
```json
{
  "verified": false,
  "error": "Invalid or expired nonce (possible replay attack)",
  "score": 100,
  "verdict": "white",
  "rejectionCode": "integrity_invalid"
}
```

**curl**:
```bash
NONCE=$(curl -s https://api.threeamigosteam.com/api/integrity/nonce | jq -r .nonce)
curl -X POST 'https://api.threeamigosteam.com/api/integrity/verify' \
  -H 'Content-Type: application/json' \
  -H 'X-App-Id: com.example' \
  -d "{\"integrityToken\":\"eyJ...\",\"nonce\":\"$NONCE\"}"
```

---

### 8. `/api/integrity/status` — PI availability

**Auth**: `X-Admin-Key`.
**Method**: `GET`.

**Response**:
```json
{"available": true, "packageName": "configured"}
```

---

### 9. `/api/integrity/reload` — hot-reload GCP keys

**Auth**: `X-Admin-Key`.
**Method**: `POST`.

Перечитывает `config/gcp-key*.json` без рестарта. Вызывается после загрузки нового ключа через панель.

**Response**:
```json
{"loaded_projects": ["betclic-497407", "stake-497708", ...], "count": 32}
```

---

### 10. `/api/sync/config` — mini-clo pull config

**Auth**: `X-Sync-Secret` (per mini_server_id).
**Method**: `GET`.

Возвращает конфиг **только** для apps где `mini_server_id == <matched id from secret>`.

**Response**:
```json
{
  "version": 1721139600,
  "mini_server_id": "visao-total",
  "apps": [
    {
      "id": "...", "name": "Total Casino", "package_name": "com.CauHoiViSao.ViSao",
      "safe_url": "https://safe...", "target_url": "https://target...",
      "require_integrity": true, "cloak_consumed_enabled": true,
      "gcp_project_id": "total-casino-497709",
      "proxy_key": "pk_...", "auth_token": "...", "mini_server_id": "visao-total",
      ...
    }
  ],
  "bans": {
    "ip_bans": [
      {"ip": "1.2.3.4", "code": "asn_google", "package_name": null, "expires_at": "2026-07-17T00:00:00Z"}
    ]
  },
  "gcp_keys": {
    "total-casino-497709": "<base64(gcp-key-<file>.json)>"
  },
  "google_asn_blocklist": [15169, 16591, 396982, ...],
  "debug_allow": {"ips": ["37.9.54.205"], "instances": []}
}
```

**curl** (с mini-server):
```bash
curl -s 'https://api.threeamigosteam.com/api/sync/config' \
  -H "X-Sync-Secret: $(cat /opt/mini-clo/config/mini_server_secret)"
```

---

### 11. `/api/sync/logs` — mini-clo push logs

**Auth**: `X-Sync-Secret`.
**Method**: `POST`.
**Body**: `{"logs": [<log entry>, ...]}`.

Каждый `<log entry>`:
```json
{
  "ip": "1.2.3.4",
  "score": 100, "verdict": "white", "rejection_code": "ipinfo_vpn",
  "details": [{"check": "ipinfo_vpn", "points": 100, "reason": "..."}],
  "user_agent": "okhttp/4.12.0",
  "accept_language": "it-IT",
  "country": "IT", "country_code": "IT", "city": "Rome",
  "headers": {"x-app-id": "com.example", "source": "mini-clo",
              "x-instance-id": "uuid", "has-integrity": "yes"},
  "extra_payload": {
    "package_name": "com.example",
    "pi": {"app": "PLAY_RECOGNIZED", "device": ["MEETS_BASIC_INTEGRITY"], "license": "LICENSED"},
    "ipinfo": {...}, "ipqs": {...}
  }
}
```

**Response**:
```json
{"received": 50, "inserted": 50}
```

---

### 12. `/api/sync/health`

**Auth**: `X-Sync-Secret`.
**Method**: `GET`.

**Response**:
```json
{"ok": true, "mini_server_id": "visao-total", "version": 1721139600}
```

---

### 13. `/api/apps` — CRUD прил

**Auth**: `X-Admin-Key`.

#### 13.1. `GET /api/apps`
Список всех прил.

```json
[
  {"id":"...","name":"Betclic Sports","package_name":"com.mazourbn.jaberbagh",
   "safe_url":"...","target_url":"...","proxy_key":"pk_...","auth_token":"...",
   "require_integrity":true, ...}
]
```

#### 13.2. `POST /api/apps`
Создать. **Body** — `AppEntryCreate` (см. `models.py:112`).
```json
{
  "name": "New App", "package_name": "com.example",
  "cert_sha256": "AAAA...", "gcp_project_id": "gcp-proj-id",
  "safe_url": "https://safe...", "target_url": "https://target...",
  "white_flow_type": "redirect_safe",
  "excluded_countries": ["FR"], "allowed_countries": [],
  "require_integrity": true, "cloak_consumed_enabled": false,
  "soft_pi_countries": [], "block_google_asn": true, "block_vpn_asn": true,
  "block_ipqs": true, "block_pi_unevaluated_combo": true,
  "skip_nonce_replay": false, "disable_lang_check": false,
  "endpoint": "https://brand-domain.com", "sdk_path": "/init"
}
```

Response — созданный `AppEntry` (см. `models.py:51`).

409 если package_name уже существует.

#### 13.3. `PUT /api/apps/{app_id}`
Обновление. Body — partial dict (любые поля из `AppEntry` кроме `id`, `created_at`).

#### 13.4. `DELETE /api/apps/{app_id}`
Удаление + автоматическое удаление proxy_key из `proxy_keys.json`.

Response: `{"success": true, "id": "..."}`.

#### 13.5. `PUT /api/apps/{app_id}/panic`
Toggle `panic_mode`.
Response: `{"success": true, "panic_mode": true}`.

#### 13.6. `POST /api/apps/{app_id}/health-check`
Пробует SDK-запрос на `{endpoint}{sdk_path}` (POST, `okhttp/4.12.0` UA, фейковые headers). Проверяет что nginx на mini-server поднял location.

Response:
```json
{
  "ok": true, "url": "https://totalsupergame.com/init",
  "status_code": 200, "latency_ms": 234,
  "content_type": "application/json",
  "is_json": true, "has_url_field": true,
  "response_snippet": "{\"url\":\"...\"}"
}
```

#### 13.7. `POST /api/apps/{app_id}/dal-check`
Digital Asset Links check — тянет `/.well-known/assetlinks.json` с `app.endpoint`, находит запись для `package_name`, сверяет `sha256_cert` с `app.cert_sha256`, отдельно GET-ит `{sdk_path}` браузерным UA (должен вернуть 200 HTML — лендинг). Ровно то что делает Google Play scanner.

Response:
```json
{
  "ok": true,
  "assetlinks_url": "https://totalsupergame.com/.well-known/assetlinks.json",
  "landing_url": "https://totalsupergame.com/init",
  "assetlinks_reachable": true, "package_registered": true, "sha_match": true,
  "path_accessible": true, "path_status_code": 200, "path_content_type": "text/html; charset=utf-8",
  "path_html_size": 12345,
  "expected_sha256": "24B00E2FB7FA457B7CDBB05DA6...", "actual_sha256s": ["24B00E..."],
  "errors": []
}
```

---

### 14. `/api/dashboard/*` — панель метрик

**Auth**: `X-Admin-Key`.

#### 14.1. `GET /api/dashboard/metrics`
Aggregated: total, greyRate, whiteRate, avgScore, uniqueIPs, requestsPerHour, ...

#### 14.2. `GET /api/dashboard/feed`
Query: `search`, `verdict=all|grey|white`, `rejectionCode`, `country`, `app` (package_name), `dateFrom`, `dateTo`, `page` (≥1), `pageSize` (1-200, default 50).

Возвращает paginated list request_logs (JOIN JSONB payload). Auto-refresh каждые 3 сек в панели когда `page=1` и фильтры пустые.

Response:
```json
{
  "entries": [{
    "id": "uuid", "timestamp": "2026-07-16T12:34:56.789Z",
    "ip": "1.2.3.4", "country": "IT", "countryCode": "IT", "city": "Rome",
    "deviceModel": "", "os": "",
    "score": 25, "verdict": "grey", "rejectionCode": null,
    "packageName": "com.example",
    "rawPayload": {...}
  }],
  "total": 12345, "page": 1, "pageSize": 50, "totalPages": 247
}
```

#### 14.3. `GET /api/dashboard/traffic`
Traffic по часам за последние 24h. `[{hour: "12:00", grey: 123, white: 45}, ...]`.

#### 14.4. `GET /api/dashboard/rejections`
Top rejection codes за 24h. `[{code: "asn_google", count: 234}, ...]`.

#### 14.5. `GET /api/dashboard/app-stats`
Per-app aggregates. `[{packageName: "com.example", total: 1234, grey: 567, white: 667, greyRate: 0.46}, ...]`.

#### 14.6. `GET /api/dashboard/app-stats/{package_name:path}`
Детально по одной приле: hourly traffic, top rejections, top countries, top ASNs, PI verdicts distribution.

---

### 15. `/api/audit/logs` — audit journal

**Auth**: `X-Admin-Key`.
**Method**: `GET`.
**Query**: `search`, `verdict`, `rejectionCode`, `country`, `app`, `dateFrom`, `dateTo`, `anonymousType`, `page` (≥1), `pageSize` (1-100, default 25).

Тот же shape что `/api/dashboard/feed` но с полными фильтрами для аудита.

---

### 16. `/api/config` — engine config

**Auth**: `X-Admin-Key`.

#### 16.1. `GET /api/config`
```json
{
  "scoreThreshold": 70,
  "ipqsFailOpen": false,
  "minPlayIntegrity": "MEETS_DEVICE_INTEGRITY",
  "batteryChargeTimeout": 1800,
  "accelerometerIdleTime": 300,
  "clickSpeedLimit": 10,
  "timezoneDriftHours": 2,
  "weights": {
    "vpnProxyTor": 25, "suspiciousCity": 15, "englishWebView": 10,
    "suspiciousHosting": 20, "mouseWithoutTouch": 30, "timezoneMismatch": 15
  }
}
```

#### 16.2. `PUT /api/config`
Body — весь `EngineConfig`. Response: `{"success": true}`.

---

### 17. `/api/offers` — default offer config (для прил без per-app safe/target)

**Auth**: `X-Admin-Key`.

#### 17.1. `GET /api/offers`
```json
{
  "safeUrl": "https://play.google.com/store/apps/details?id=com.example.safe",
  "targetUrl": "https://api.example.com/offer/target",
  "whiteFlowType": "redirect_safe"
}
```

#### 17.2. `PUT /api/offers`
Body — весь `OfferConfig`.

---

### 18. `/api/debug-allow` — whitelist force-grey

**Auth**: `X-Admin-Key`.

#### 18.1. `GET /api/debug-allow`
```json
{"ips": ["37.9.54.205"], "instances": ["dev-instance-uuid"]}
```

#### 18.2. `PUT /api/debug-allow`
Body: `{"ips": [...], "instances": [...]}`. Пустые строки и не-string дропаются. Синкается на mini-clo через `/api/sync/config` с 2026-07-14.

---

### 19. `/api/lists/*` — CRUD blocklists

**Auth**: `X-Admin-Key`.

#### 19.1. `GET /api/lists`
Список всех blocklists с count элементов.

#### 19.2. `GET /api/lists/{name}`
Полный список items. Пример `name`: `countries_block`, `cities_block`, `device_models_block`, `codenames_block`, `gpu_block`, `isp_block`, `user_agents_block`, `ip_ranges_block`, `tor_exits`, `test_builds_block`.

#### 19.3. `PUT /api/lists/{name}`
Body: `{"items": ["item1", "item2", ...]}`. Записывается в `lists/{name}.txt` (по строке на item). Watcher (interval 5s) автоматически перечитает без рестарта.

---

### 20. `/api/health` — простой uptime

**Auth**: нет.

```json
{"status": "ok", "uptime": 12345, "lists_loaded": 12}
```

---

### 21. `/api/health-ext/*` — health checks внешних API

**Auth**: `X-Admin-Key`.
**Endpoints**: `/ipqs`, `/ipinfo`, `/play_integrity`, `/redis`, `/postgres`, `/cf_kv`.

Возвращают `{ok, service, latency_ms, message, details}`. Используется панелью `/dashboard/defense` (кнопка "Health check" на карточках).

**curl** (все параллельно):
```bash
for svc in ipqs ipinfo play_integrity redis postgres; do
  curl -s "https://api.threeamigosteam.com/api/health-ext/$svc" \
    -H "X-Admin-Key: $ADMIN_KEY" | jq
done
```

---

### 22. `/api/bans/*` — 3-tier ban store

**Auth**: `X-Admin-Key`.

#### 22.1. `GET /api/bans`
Query: `page`, `pageSize`, `active_only=true|false`, `search`, `code`, `package_name`.
Response: paginated `AutoBannedEntry` (см. `db_models.py:75`).

#### 22.2. `POST /api/bans`
Manual ban.
Body:
```json
{
  "ip": "1.2.3.4",
  "package_name": "com.example",     // null = global
  "code": "manual_ban",
  "reason": "Модер отследен вручную",
  "ttl_sec": 604800,                  // 7d
  "banned_by": "admin@example.com"
}
```

#### 22.3. `DELETE /api/bans/{id}`
Удалить ban (Redis + Postgres).

---

### 23. `/api/honeypot/*` — CF KV баны (365d)

**Auth**: `X-Admin-Key`.

Аналогично `/api/bans` но через CF Workers KV API. Для permanent-подобных banов, edge-level enforcement (blocked до достижения origin).

---

### 24. `/api/cf/*` — CF KV rotation

**Auth**: `X-Admin-Key`.

- `POST /api/cf/rotate/panic-mode` — обновить `PANIC_MODE` в CF KV (глобальный kill switch на edge).
- `POST /api/cf/rotate/client-secret` — ротация `CLIENT_SECRET`.
- `POST /api/cf/rotate/blocked-asns` — обновить BLOCKED_ASNS set.

---

### 25. `/api/reports/*` — Docs Hub

**Auth**: `X-Admin-Key`.

Свободные MD отчёты, `author_email` injects из панели (NextAuth session). Edit/Delete — только автор.

- `GET /api/reports` — список.
- `POST /api/reports` — `{title, body_md, tags: []}`.
- `PUT /api/reports/{id}` — обновление (проверка `author_email`).
- `DELETE /api/reports/{id}`.

---

### 26. `/api/gh-doc/*` — session state → MD generator

**Auth**: `X-Admin-Key`.

Утилита для сохранения текущего state системы (apps, config, bans) в markdown для передачи документации.

---

### 27. `/api/analytics/*` — pivot queries

**Auth**: `X-Admin-Key`.

Специфичные aggregation queries для панели (heatmaps, funnels, cohorts).

---

### 28. `/api/auto-ban/*` — auto_ban admin routes (`api/auto_ban_routes.py`)

**Auth**: `X-Admin-Key`.

- Bulk operations, DLQ view, stats.

---

### 29. Legacy `/` и `/score-debug`

**`GET /`** — v2 SDK gateway (устаревший до 2026-05). Читает X-* headers, вызывает `score_request`, применяет `white_flow_type`. Больше не используется живыми прилами.

**`GET /score-debug`** и **`GET /analytics/config`** — debug endpoint. **Auth**: `X-Admin-Key`. Returns `{score, verdict, targetUrl}` без deploy'а вердикта (P0-3 2026-06-21: раньше без auth — passive verdict oracle для модеров).

---

### 30. `/tracker.js` и `/analytics.js`

**Auth**: нет.
**Method**: `GET`.

Отдаёт `js-scripts/tracker.min.js` (или `.js` fallback) c `Cache-Control: public, max-age=3600`.

---

## Часть II. Mini-clo (ViSao — `38.244.152.11`, порт `127.0.0.1:8100`)

Mini-clo — cut-down версия main КЛО для distributed scoring. Скачивает config от main КЛО, делает PI decode локально (google keys синхронизированы), возвращает scoring через тот же protocol что main КЛО (`{"url": "..."}`).

### 1. `POST /init` (и `GET /init`)

**Auth**: `X-Proxy-Key`.
**Method**: `POST`, `GET`.

Тот же contract как main КЛО `/init` — возвращает `{"url": "..."}`.

**Pipeline** (упрощён по сравнению с main КЛО):

1. Auth (`X-Proxy-Key` → package_name из mini-clo `config/apps.json`).
2. App lookup + panic_mode.
3. Extract IP/UA/instance_id/locale/integrity_token.
4. Debug bypass (`config_store.is_debug(ip, instance_id)` → force grey).
5. `is_autobanned(pkg, ip)` — Redis GET `autoban:{pkg|_}:{ip}`.
6. `is_instance_burnt(pkg, iid)` — **DISABLED (2026-07-14) aligned with max-conversion**.
7. IPinfo lookup → hard-kills (vpn, proxy, res_proxy non-CGNAT, tor, hosting).
8. `country_not_allowed` / excluded_countries.
9. `lang_country_mismatch` (для require_integrity + !disable_lang_check).
10. IPQS lookup → hard-kills (tor unconditional, vpn/fraud для require_integrity+block_ipqs).
11. Velocity guard (Redis, для require_integrity): per-instance >12/5min, per-IP >60/5min, per-subnet >15 iids/15min.

    **Note**: mini-clo сохранил старые strict thresholds, main КЛО в max-conversion mode их разослал (12→100, 15→100, 60→300). Синхронизировать через backport в `mini-clo/redis_client.py:velocity_check()`.

12. Play Integrity verify (**всегда декодирует если token есть**, 2026-07-14 fix — раньше skip при hard-kill).
13. Verdict: `grey` если `pi_ok=True`, иначе `white`. Rejection: `integrity_missing`/`pi_init_failed`.
14. `cloak_consumed` (opt-in).
15. `mark_instance_burnt` для BURN_CODES (реально пишет в Redis, main КЛО отключил).
16. URL selection: если `direct_redirect=True` → raw target с clickid+geo, иначе bounce через `BOUNCE_URL_BASE` (по умолчанию `https://api.threeamigosteam.com/engine`, для ViSao — `https://totalsupergame.com`).
17. Log entry → `log_shipper.enqueue()` (batch flush каждые 30s на `main-klo/api/sync/logs`).

**Response** (тот же shape):
```json
{"url": "https://totalsupergame.com/go?t=aHR0cHM6Ly9jYXNpbm8u..."}
```

**curl**:
```bash
curl -X POST 'https://totalsupergame.com/init' \
  -H 'X-Proxy-Key: pk_ViSaoTotalKey_...' \
  -H 'X-App-Id: com.CauHoiViSao.ViSao' \
  -H 'X-Instance-Id: uuid' \
  -H 'X-Integrity-Token: eyJ...' \
  -H 'User-Agent: okhttp/4.12.0'
```

### 2. `POST /web_content` (и `GET /web_content`)

**Auth**: нет.
**Method**: POST/GET.

Placeholder. Возвращает `{"received": true}`. Реального redirect handling нет (mini-clo не хостит landing).

### 3. `GET /health`

**Auth**: нет.

**Response**:
```json
{
  "ok": true,
  "apps_count": 1,
  "pi_keys": 1
}
```

Проверяется main КЛО через ssh curl или monitoring системой.

---

## Часть III. Nginx на mini-server (ViSao) — как SDK попадает в mini-clo

Файл: `mini-server-visao/nginx/sites-enabled__total-casino.conf`.

**Логика Type C сплиттера**:

```nginx
server {
    listen 443 ssl http2;
    server_name totalsupergame.com;

    # okhttp UA (SDK v3/v4) → перевести на @sdk_proxy
    if ($http_user_agent ~* "okhttp") {
        return 418;
    }
    error_page 418 = @sdk_proxy;

    # POST body (mini-clo /init v4 POST) → на @sdk_proxy напрямую
    if ($request_method = POST) {
        return 418;
    }

    # Всё остальное (браузеры Chrome CT) → Next.js landing на :3000
    location / {
        proxy_pass http://127.0.0.1:3000;
        # ... стандартный headers
    }

    location = /go {
        # bounce redirect — прокидываем в тот же landing (Next handler отдаёт 302)
        proxy_pass http://127.0.0.1:3000;
    }

    # SDK path
    location @sdk_proxy {
        rewrite ^ /init break;    # unify: любой okhttp path → /init
        proxy_pass http://127.0.0.1:8100;  # mini-clo
        proxy_set_header X-Real-User-IP $remote_addr;  # обход CF (CF не трогает custom headers)
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }

    location = /.well-known/assetlinks.json {
        alias /var/www/assetlinks.json;
        default_type application/json;
    }
}
```

Дополнительно `cloudflare-realip.conf` (стандартный CF IP allow-list для `set_real_ip_from`).

---

## Часть IV. HTTP status codes — какой когда возвращаем

| Code | Когда |
| --- | --- |
| **200** | `/init` — всегда (даже при 100% score → safe URL, чтобы не палить cloak) |
| **200** + `{"received": true}` | `/api/collect` — всегда (не палим scoring) |
| **302** | `/go`, `/web_content` (v3), legacy `/` for grey |
| **403** | `/init` unknown proxy_key, `/api/integrity/verify` invalid nonce / stale token, `/api/sync/*` invalid X-Sync-Secret |
| **404** | Все `/api/{apps,config,...}` без правильного X-Admin-Key (path masking) |
| **413** | `/api/collect` body > 65k |
| **422** | Pydantic валидация (extra field в `/api/integrity/verify`, invalid types) |
| **429** | `/api/integrity/nonce` >10/min/IP |
| **503** | `/api/integrity/verify` Redis nonce store unavailable |

---

## Часть V. Полный список кастомных headers (SDK v3/v4)

| Header | Кто ставит | Что содержит |
| --- | --- | --- |
| `X-Proxy-Key` | SDK build config | `pk_<32-hex>` — main auth |
| `X-App-Id` | SDK | package_name (для override когда 1 pk = много прил) |
| `X-Sid` | SDK | auth_token из apps.json (secondary auth, checked mini-clo) |
| `X-Instance-Id` | SDK (SharedPreferences UUID) | стабильный per-device |
| `X-Integrity-Token` | Google Play Integrity API | JWE (~1-2KB) |
| `X-App-Version` | SDK | Version code / name |
| `X-Locale` | SDK v4 | `en-US`, `it-IT`, ... |
| `X-Tz` | SDK | `Europe/Rome` |
| `X-Ts` | SDK | Unix millis at request |
| `X-Real-User-IP` | Mini-server nginx (custom, обходит CF) | real IP клиента |
| `X-Package-Name`, `X-Device-Model`, `X-Device-Codename`, `X-Device-Info`, `X-Graphics-Info`, `X-GPU-Renderer`, `X-Build-Product`, `X-OS-Version`, `X-Country`, `X-Country-Code`, `X-City`, `X-ISP` | Legacy v2 SDK, `/` gateway | детальная info о девайсе |
| `X-Edge-Signature`, `X-Edge-Timestamp` | CF Worker | HMAC-SHA256(EDGE_SECRET) |
| `X-CF-Country`, `X-CF-ASN` | CF Worker | ISO2 country, ASN (число) |
| `X-Admin-Key` | Панель (BFF proxy) | секрет ADMIN_KEY |
| `X-Sync-Secret` | Mini-clo | per-mini_server_id secret |

---

## Часть VI. Примеры полного flow

### VI.1. Successful grey flow (real Italian user на Fastweb IT)

```
1. APK → POST https://totalsupergame.com/init
   Headers: X-Proxy-Key, X-App-Id: com.CauHoiViSao.ViSao,
            X-Instance-Id: uuid, X-Integrity-Token: eyJ...,
            User-Agent: okhttp/4.12.0
            
2. Nginx: match okhttp UA → return 418 → error_page @sdk_proxy → rewrite /init
   → proxy_pass http://127.0.0.1:8100/init
   + inject X-Real-User-IP=<real>

3. Mini-clo /init:
   - resolve_proxy_key → package_name=com.CauHoiViSao.ViSao
   - app.panic_mode=False
   - ip=85.18.0.133 (Fastweb IT)
   - is_debug → False
   - is_autobanned → False
   - IPinfo → country=IT, asn=12874, vpn=false, proxy=true (CGNAT), res_proxy=false, hosting=false
   - Country allowed (IT ∉ excluded)
   - lang OK (accept-language: it-IT)
   - IPQS → fraud_score=45, tor=false, vpn=false → OK
   - Velocity OK (первый /init за минуту)
   - PI decode: PLAY_RECOGNIZED + MEETS_DEVICE_INTEGRITY + LICENSED → pi_ok=True
   - Verdict = "grey"
   - cloak_consumed disabled
   - URL = "https://totalsupergame.com/go?t=<base64(target?clickid=uuid&geo=IT)>"
   - log_shipper.enqueue({...})

4. Return {"url": "https://totalsupergame.com/go?t=..."}

5. Chrome CT opens URL → nginx /go → proxy_pass Next :3000
   → Next handler decode base64 → 302 → Keitaro → казино
```

### VI.2. Blocked white flow (модер с VPN на Google ASN)

```
1. Curl → POST https://api.threeamigosteam.com/init
   Headers: X-Proxy-Key: pk_stolen, X-App-Id: com.example,
            X-Instance-Id: probe-uuid, X-Integrity-Token: (пусто)
            User-Agent: okhttp/4.12.0

2. Main КЛО /init:
   - resolve_proxy_key → package_name=com.example
   - app.require_integrity=True, block_google_asn=True
   - ip=34.28.5.10 (GCP)
   - is_debug → False
   - is_autobanned → False (первый заход)
   - IPinfo → country=US, asn=15169 (Google), hosting=true
   - Hard-kill: asn_google → verdict=white
   - request_logger.log (rejection=asn_google, score=100)
   - auto_ban.emit(ip=34.28.5.10, pkg=None (global), code=asn_google, ttl=7d)

3. Return {"url": "https://safe-url-of-app.com/..."}

4. Следующий запрос с того же IP → autoban_hit → instant white без scoring.
```

### VI.3. Panel — создание новой прилы

```bash
# 1. Create
curl -X POST 'https://api.threeamigosteam.com/api/apps' \
  -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{
    "name":"New Casino App",
    "package_name":"com.newcasino.game",
    "cert_sha256":"AAAA...",
    "gcp_project_id":"newcasino-123456",
    "safe_url":"https://apple.com",
    "target_url":"https://newcasino-track.com/click",
    "require_integrity":true,
    "block_google_asn":true, "block_vpn_asn":true, "block_ipqs":true,
    "allowed_countries":["IT"],
    "endpoint":"https://brand-domain.com",
    "sdk_path":"/init"
  }'
# Response: {"id":"uuid","proxy_key":"pk_<autogen>","auth_token":"<autogen>",...}

# 2. Upload GCP key через панель — appends config/gcp-key-<proj>.json

# 3. Hot-reload PI keys
curl -X POST 'https://api.threeamigosteam.com/api/integrity/reload' \
  -H "X-Admin-Key: $ADMIN_KEY"

# 4. DAL check
curl -X POST 'https://api.threeamigosteam.com/api/apps/{app_id}/dal-check' \
  -H "X-Admin-Key: $ADMIN_KEY"

# 5. Health check (SDK probe)
curl -X POST 'https://api.threeamigosteam.com/api/apps/{app_id}/health-check' \
  -H "X-Admin-Key: $ADMIN_KEY"
```
