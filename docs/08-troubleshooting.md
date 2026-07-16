# 08. Troubleshooting — типовые проблемы и решения

> Актуально на 2026-07-16. Организовано по симптому: сначала — что видит клиент/APK, затем root cause и fix.

## 1. `403 Unauthorized` от SDK на Type C mini-server

**Симптом.** APK шлёт `POST /game` (или `/sports`, `/football_data`, ...), в ответ `403 {"error":"Unauthorized"}` или `403 {"error":"App config not found"}`.

**Диагностика:**
```bash
ssh root@<box-ip>
curl -s http://127.0.0.1:8100/health
# apps_count:0 ← подтверждает
grep -c <package_name> /opt/mini-clo/config/apps.json
# 0 ← подтверждает
```

### Причина A — `mini_server_id=null` на main КЛО

Sync-запрос фильтрует apps по `mini_server_id`. Если поле стёрлось (миграция панели, ручная правка), sync возвращает пустой список. См. [visao-integrity-fix-2026-07-14](../memory/visao-integrity-fix-2026-07-14.md).

**⚠️ Панельный API `PUT /api/apps` не персистит `mini_server_id` и `direct_redirect`** — эти поля отсутствуют в Pydantic-модели `AppEntry` и дропаются на сохранении. Правки — **напрямую в `apps.json` на диске**.

**Fix:**
```bash
# На main КЛО:
python3 -c "
import json
p='/opt/scoring-engine/config/apps.json'
d=json.load(open(p))
for a in d:
    if a['package_name'] == '<pkg>':
        a['mini_server_id'] = '<mini_id>'   # напр. 'total-casino-2'
json.dump(d, open(p,'w'), indent=2, ensure_ascii=False)
"
# На боксе:
systemctl start mini-clo-sync.service
systemctl restart mini-clo   # обязательно — sync записал файл, но config_store не reload'ается
```

### Причина B — proxy_key не в `proxy_keys.json`

После patch 07-15 (`cross-app-leak-fix`) `_resolve()` на main КЛО валидирует, что `X-App-Id` в `allowed_packages` для этого proxy_key. На Type C mini-clo проверяется `_proxy_key_to_pkg` map, но если proxy_key вообще отсутствует — 403.

**Fix.** Добавить в `proxy_keys.json` на main КЛО:
```json
"pk_<key>": {
  "package_name": "<pkg>",
  "name": "<display>",
  "allowed_packages": ["<pkg>"]
}
```
Форс-sync на бокс + рестарт mini-clo.

### Причина C — `config_store` не reload'нулся после sync

`sync.py` только пишет файл, не сигналит store (кроме auto-reload в `initial_sync()` для холодного старта, patch 07-15). Если бокс уже работал и вы делаете **subsequent** sync — рестарт обязателен.

**Fix.** `systemctl restart mini-clo`. TODO — SIGHUP handler или mtime polling.

## 2. `405 Method Not Allowed` от mini-server nginx

**Симптом.** APK шлёт POST на SDK-путь, nginx возвращает 405. В `/var/log/nginx/access.log`: `POST /game 405 ...`.

**Причина.** В nginx `location = /game` не описан или не поддерживает POST. Некоторые старые конфиги имели только GET, потому что legacy SDK v3 ходил `GET ?app_id=&sid=`. SDK v4 шлёт `POST` с body-headers.

**Fix.** Убедиться, что `location = /game` (или ваш путь) содержит UA-split (см. [03-mini-server-visao.md](03-mini-server-visao.md) §3.5) без ограничения метода. FastAPI `mini-clo/init_routes.py:70-71` имеет обе декорации:
```python
@router.post("/init")
@router.get("/init")
async def init_resolve(request: Request):
```

На main КЛО — patch 07-09 (`max-conversion mode`, см. `api/init_routes.py:1182-1200`) добавил `@router.post("/init")` кроме GET. Если апгрейдили main КЛО с revert — проверить, что POST есть.

## 3. Cross-app leak — прила X получает URL прилы Y

**Симптом (клиентский тест 07-15).** Подставили в APK Sisal endpoint `footballapisnai.com/sports` (Snai бокс) + `X-Sid` Sisal → получили Sisal `target_url`. Master-key эффект — 1 утекший proxy_key даёт доступ ко всем прилам.

**Root cause (до 07-15).** Patch 07-10 (`xappid-fix-shared-proxy-key`) добавил приоритет `X-App-Id` над proxy_key mapping, но **без проверки владельца**. Любая прила из apps.json проходила.

**Fix (07-15, `cross-app-leak-fix-2026-07-15`).** Расширена схема `proxy_keys.json` — `allowed_packages` list. В `_resolve()` (`api/init_routes.py:591-603`):
```python
allowed = key_data.get("allowed_packages") or [key_data["package_name"]]
if x_app_id:
    if x_app_id not in allowed:
        logger.warning(f"xappid_cross_leak_blocked pk={proxy_key[:12]}... x_app_id={x_app_id} allowed={allowed}")
        return None, None, None
    package_name = x_app_id
```

**Verify.** `POST /init X-Proxy-Key=Snai X-App-Id=Sisal` → 403 + в журнале `xappid_cross_leak_blocked`.

**⚠️ Побочный эффект — Betclic hadyarba.** APK шлёт `X-App-Id=com.mszourub.hadyarba` (одна «a»), а в apps.json — `com.mszourub.hadyarbaa` (две «a»). После patch APK получает 403. Решение — переименовать в apps.json+proxy_keys.json или пересобрать APK. См. memory.

## 4. Play Integrity decode падает

### 4.1 `HttpError 400 - invalidPackageName`

**Причина.** `X-App-Id` не совпадает с `packageName`, привязанным к GCP-project'у в Play Integrity console. Или прила в apps.json указывает не тот `gcp_project_id`.

**Fix.** В Google Cloud Console → Play Integrity → Integrations → убедиться, что нужный `package_name` привязан к service account'у, чей ключ лежит в `gcp-key-<proj>.json`. Проверить `apps.json[].gcp_project_id`.

### 4.2 `HttpError 400 - Invalid input`

**Причина.** `integrity_token` битый / истёк / для другого GCP project.

**Норм ожидание для тестовых `dummy` токенов** — mini-clo продолжает pipeline, hard-kill = `integrity_missing` вместо PI-verdict.

### 4.3 SSL / TLS ошибка при вызове Google PI API

**Причина.** Устаревшие CA сертификаты на боксе.

**Fix.**
```bash
apt install -y ca-certificates
update-ca-certificates
systemctl restart mini-clo
```

### 4.4 Timeout — `SocketTimeoutException` в APK

**Причина.** Google PI `decodeIntegrityToken` без таймаута вешал main КЛО. Patch 07-07 ([pi-decode-timeout-fix](../memory/pi-decode-timeout-fix.md)) обернул в `asyncio.wait_for(..., timeout=8.0)`, плюс HTTP-таймаут на Google client 10s. На mini-clo — то же.

**Верификация.** `journalctl -u mini-clo | grep 'PI verify failed.*timeout'` — должно быть редкие вспышки (Google API интермиттентно тупит). Если постоянно — увеличить `wait_for` до 10-12 с (но помнить, что SDK-таймаут APK = 15 с).

Также есть Redis-cache PI-вердиктов (`pi_verdict:{package}:{iid}`, TTL 6h) в main КЛО (`init_routes.py`) — cache hit пропускает Google-decode, freshness/nonce-replay тоже пропускаются (иначе false pi_stale hard-kill).

## 5. `502 Bad Gateway` от бокса — IPv6 upstream fail

**Симптом.** `curl -sk https://totalsupergame.com/go?t=...` → 502. В `error_log`: `connect() failed (101: Network is unreachable) while connecting to upstream, ..., upstream: "https://[2606:4700:...]:443"`.

**Причина.** Cloudflare отдаёт AAAA (IPv6) первой для `api.threeamigosteam.com`, а у бокса нет IPv6-route.

**Fix.** В nginx-конфиг на верхнем уровне файла:
```nginx
resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
```
См. [p7-nginx-ipv6-clickid-fix-2026-07-10](../memory/p7-nginx-ipv6-clickid-fix-2026-07-10.md). После `nginx -s reload` residual IPv6 errors 4-8/60s ещё несколько минут (старые worker'ы дообслуживают keepalive-коннекты), потом 0.

**⚠️ Grabli.** `resolver` не разрешён внутри `upstream {}` блока. Правильно — на http/server-уровне.

## 6. `clickid`+`geo` не долетают до Keitaro

**Симптом.** В Keitaro клиента клика приходят с голым `target_url` без `?clickid=...&geo=...`. Клиент не может связать конверсии с юзерами/потоками.

**Причина** (07-10 регрессия). Deploy 09.07 14:31 МСК `mini-id-fix` убрал enrichment.

**Fix (07-10, restored).** В `main-klo/api/init_routes.py` в двух местах (`debug_bypass` ~L680 и main-flow перед base64-encode ~L1011):
```python
_sep = "&" if "?" in target_url else "?"
_geo_c = (geo.country if geo else "")
target_url = f"{target_url}{_sep}clickid={instance_id}&geo={_geo_c}"
_t = base64.urlsafe_b64encode(target_url.encode()).decode()
url = f"https://api.threeamigosteam.com/engine/go?t={_t}"
```

На mini-clo (`init_routes.py:314-330`) — то же самое в grey-branch. Проверить оба места.

**Verify.** Из клиентского теста: декодировать `t=` из URL в JSON-ответе — должно быть `<target>?clickid=UUID&geo=CC`.

## 7. Docker bridge IP `172.18.0.1` → `geo_unknown` в БД

**Симптом (07-15).** В `request_logs` 490 записей/7d с `ip='172.18.0.1'`, `rejection_code='geo_unknown'`. Клиент видит мусор в панели.

**Причина.** Health-checks / cron / panel-side fetch без `X-Forwarded-For` → FastAPI `request.client.host` возвращает docker bridge → ipinfo не резолвит private → hard-kill.

**Fix (07-15, `two-filters-relax-2026-07-15`).** В `main-klo/api/init_routes.py:634-648` — fail-early skip для private IP:
```python
_priv_prefixes = ("127.", "10.", "172.16.", ... "192.168.", "::1", "fc00:", "fd00:", "0.0.0.0")
if ip.startswith(_priv_prefixes):
    logger.info(f"skip_internal_ip ip={ip} pkg={_pkg_log} host={...} — health/probe, no logging")
    _safe = (app.safe_url if app and app.safe_url else config_store.offers.safeUrl)
    return package_name, "white", _safe
```

Запрос отдаётся safe_url без scoring и без записи в БД. Panel остаётся чистой.

## 8. `Duplicate resolver` / `duplicate server name` при `nginx -t`

**Симптом.** После правки конфига `nginx -t` ругается на дубликаты.

**Причина.** В `/etc/nginx/sites-enabled/` лежат `.bak` файлы, которые подхватываются glob'ом `include /etc/nginx/sites-enabled/*` (см. `nginx.conf`). nginx матчит их как валидные конфиги → duplicate.

**Fix.** Держать backup'ы **вне** `sites-enabled/`:
```bash
mkdir -p /root/nginx-backups
mv /etc/nginx/sites-enabled/*.bak* /root/nginx-backups/
nginx -t && systemctl reload nginx
```

Правило деплоя: `cp /etc/nginx/sites-enabled/X /root/nginx-backups/X.bak-$(date +%s)` **перед** любыми правками, а не в тот же каталог.

## 9. Whitelist `debug_allow` не работает на mini-clo боксах

**Симптом (07-14).** Тестовый IP клиента добавлен в панель → на main КЛО работает (force grey), а на Type C прилах через mini-clo — не работает, клика режутся hard_kill.

**Причина.** До patch 07-14 `debug_allow` жил только на main КЛО. mini-clo `config.py:is_debug()` возвращал hardcoded `False`, файла `debug_allow.json` на боксе не было, sync его не отдавал.

**Fix (`whitelist-debug-allow-parity-2026-07-14`).** 4 части:
1. `main-klo/api/sync_routes.py` — добавлен `debug_allow` в payload.
2. `mini-clo/config.py` — реальный `is_debug()` + `_load_debug()`.
3. `mini-clo/sync.py` — save `debug_allow.json`.
4. `mini-clo/init_routes.py` — bypass block перед hard_kill state init.

**Verify.**
```bash
# На боксе:
cat /opt/mini-clo/config/debug_allow.json
# → {"ips":["37.9.54.205"], "instances":[...]}

# Тест SDK-запроса с whitelist IP:
curl -sk -X POST https://<domain>/<sdk-path> \
  -H 'User-Agent: okhttp/4.11.0' \
  -H 'X-App-Id: <pkg>' \
  -H 'X-Real-IP: 37.9.54.205' \
  ...
# → 200 {"url":"...engine/go?t=..."} — grey URL

# journalctl -u mini-clo | grep DEBUG
# → [37.9.54.205] init: pkg=... DEBUG bypass -> grey
```

## 10. Docker/Next.js :3000 голым в интернет (RCE-риск)

**Симптом (kodratak 07-10, motocross 07-12).** CERT-Bund присылает жалобу за timestamps сканирования CVE-2025-55182. `docker logs` контейнера содержит попытки `wget <malware>`.

**Причина.** `docker-compose.yml` объявляет `ports: '3000:3000'` (0.0.0.0), ufw выключен → :3000 доступен извне. Next.js 15.1.6 уязвим (CVE-2025-29927, patched 15.2.3).

**Fix (по важности).**
1. `ufw allow 22,80,443/tcp; ufw default deny incoming; ufw --force enable`.
2. В `docker-compose.yml`: `ports: '127.0.0.1:3000:3000'`. `docker compose down && up -d`.
3. Обновить Next.js до **15.5.20**:
   ```bash
   docker run --rm -v /opt/<landing>:/app node:20-slim \
     npm install --package-lock-only next@^15.2.3
   docker compose up -d --build
   ```

**⚠️ НЕ ставить наивно `cloudflare-allow.conf`** (`allow CF-ranges; deny all;`) на боксе с `cloudflare-realip.conf` — realip переписывает `$remote_addr` на живой IP клиента **до** allow/deny → deny срежет живых юзеров через CF. Origin-protection делать на уровне CF (WAF) либо `allow/deny` **до** `real_ip_header`.

Type C боксы изначально биндят Next.js на `127.0.0.1:3000` через `mini-clo` шаблон — там ок. Проверить остальные Docker-landing боксы (Stake, Sisal, gesr, Betclic, TotalTh) на `ss -tlnp | grep :3000` — должен быть `127.0.0.1:3000`, не `0.0.0.0:3000`.

## 11. `error_page 418` не срабатывает

**Симптом.** В `location = /game` описан `if ($http_user_agent ~* "okhttp") { return 418; }`, но браузер получает 418 HTML, а не JSON от mini-clo.

**Причина.** `error_page 418 = @vsao_sdk_proxy` определён в другом `location` или **дважды** на server-уровне (второй перекрывает первый).

**Fix.** Определять `error_page 418 = @<name>` **внутри самого `location {}`**, где `return 418` — детерминированно.

## 12. Debug — где смотреть логи

| Что                                | Где                                                                  |
|------------------------------------|----------------------------------------------------------------------|
| Main КЛО scoring                   | `journalctl -u scoring-engine -f`                                    |
| Main КЛО HTTP                      | `/var/log/nginx/access.log` + `error.log` на 31.76.251.103           |
| Type C mini-clo                    | `journalctl -u mini-clo -f` на боксе                                 |
| Type C nginx (SDK-запросы)         | `/var/log/nginx/visao_trace.log` (custom format с headers)           |
| Type C nginx (общий)               | `/var/log/nginx/access.log` + `error.log`                            |
| log_shipper (mini-clo → main)      | `journalctl -u mini-clo | grep -E 'log_shipper|Flushed|Flush failed'` |
| sync (config pull)                 | `journalctl -u mini-clo -u mini-clo-sync | grep sync`                |
| Postgres (клика в БД)              | `sudo -u postgres psql -d scoring -c "SELECT ... FROM request_logs"` |
| Panel-side API                     | `journalctl -u panel` (если systemd) или Vercel logs                  |

## 13. Полный health-check бокса (быстрый скрипт)

```bash
#!/bin/bash
# ~/box-health.sh — запустить на боксе
set -e

echo "== mini-clo health =="
curl -s http://127.0.0.1:8100/health | jq .

echo "== apps.json count =="
python3 -c "import json; print(len(json.load(open('/opt/mini-clo/config/apps.json'))))"

echo "== sync state =="
cat /opt/mini-clo/config/sync_state.json

echo "== gcp keys =="
ls /opt/mini-clo/config/gcp-key-*.json

echo "== pending logs =="
wc -l /opt/mini-clo/logs/pending.jsonl 2>/dev/null || echo "no pending"

echo "== nginx =="
nginx -t 2>&1

echo "== redis =="
redis-cli ping

echo "== ufw =="
ufw status verbose | grep -E '22|80|443|3000|8100'

echo "== external :3000 exposed? =="
timeout 3 curl -so /dev/null -w '%{http_code}\n' http://$(hostname -I | awk '{print $1}'):3000/ || echo "closed (good)"
```

Related: `mini-clo-sync-gotchas`, `visao-integrity-fix-2026-07-14`, `cross-app-leak-fix-2026-07-15`, `p7-nginx-ipv6-clickid-fix-2026-07-10`, `pi-decode-timeout-fix`, `whitelist-debug-allow-parity-2026-07-14`, `landing-box-3000-exposure-incident`, `two-filters-relax-2026-07-15`.
