# 09. Security — практики и защитные слои

> Актуально на 2026-07-16. Пишем не про «best practices вообще», а про уроки, вынесенные из живых инцидентов и патчей.

## 0. Threat model

Основные угрозы, которые уже реализовывались в проде:
1. **Cross-app leak** — утечка одного `proxy_key` даёт master-доступ ко всем прилам.
2. **RCE через голый Next.js :3000** — CVE-2025-29927 / CVE-2025-55182 (Next middleware).
3. **Scraping/scanning модеров через прямой доступ к mini-clo :8100** — обход nginx-фильтров.
4. **Backup файлы (`.bak`) в `sites-enabled/`** — duplicate/поломка конфига или утечка старых секретов.
5. **Timing attack на `X-Sync-Secret`** — теоретический.
6. **Ротация SSH-паролей** — 07-14 пришлось менять оптом после подозрения на утечку.
7. **GCP-ключи Play Integrity в JSON** — если утекут, атакующий может декодить любой чужой PI-токен на своём инфраструктуре и подделывать вердикты.

## 1. Cross-app protection — `allowed_packages`

**История.** Patch 07-10 (`xappid-fix-shared-proxy-key`) добавил приоритет `X-App-Id` header над `proxy_keys.json` mapping, чтобы 2 прилы Snai (`omniconvert` + `muslimazkarpro`) с общим ключом могли различаться в аналитике. Guard был **только** `config_store.get_app(x_app_id) is not None` — любая из 32 прил проходила.

**Инцидент 07-15.** Клиент собрал PoC APK: положил в Snai endpoint `footballapisnai.com/sports`, отправил `X-Sid` от Sisal. Ответ = Sisal `target_url` (`sslftblpp.com/MSv4Rx`). 1 утекший `proxy_key` = master key к 32 прилам.

**Fix (`cross-app-leak-fix-2026-07-15`).** Расширена схема `proxy_keys.json`:
```json
{
  "pk_8cd2a5cc...": {
    "package_name": "com.bft.omniconvert",
    "name": "Snai",
    "allowed_packages": [
      "com.bft.omniconvert",
      "com.calmheart.muslimazkarpro"
    ]
  },
  "pk_...": {
    "package_name": "...",
    "allowed_packages": ["..."]   // singleton для 31 обычной прилы
  }
}
```

Guard в `main-klo/api/init_routes.py:_resolve()` (L591-603):
```python
allowed = key_data.get("allowed_packages") or [key_data["package_name"]]
if x_app_id:
    if x_app_id not in allowed:
        logger.warning(f"xappid_cross_leak_blocked pk={proxy_key[:12]}... "
                       f"x_app_id={x_app_id} allowed={allowed} host={...} ip={...}")
        return None, None, None   # → 403 Unauthorized
    package_name = x_app_id
else:
    package_name = key_data["package_name"]
```

**Recommended defense-in-depth (не реализовано):**
- **Patch C на mini-clo `:8100`** — валидация `Host` header ↔ `app.allowed_domains`. Edge будет отвергать чужой домен, не полагаясь только на main КЛО.
- **Ротация всех 32 proxy_key**: считать все скомпрометированными после leak-инцидента, ротировать при следующем APK release. См. §4.

## 2. Debug whitelist (`debug_allow.json`)

**Что это.** Force-grey bypass для точечных тестов клиента. IP или `instance_id` в whitelist → все hard-kill фильтры игнорируются, verdict сразу `grey`, отдаётся `target_url` через `/engine/go` bounce.

**Где хранится.**
- Main КЛО: `/opt/scoring-engine/config/debug_allow.json` → `config_store.debug_allow`, читается в `is_debug()`.
- mini-clo: `/opt/mini-clo/config/debug_allow.json` → синкается из main КЛО через `/api/sync/config` (patch 07-14).

**Формат:**
```json
{
  "ips": ["37.9.54.205", "..."],
  "instances": ["<uuid>", "..."]
}
```

**Правила безопасного использования:**
1. **Не добавлять wildcard IP** — эффект «отключил всю antifraud цепочку». Только конкретные IP или конкретные `instance_id`.
2. **Регулярно чистить** — после каждого теста удалять запись. Whitelist не должен расти как накопитель.
3. **Аудит** — периодически проверять `journalctl -u scoring-engine | grep "DEBUG bypass"`: там видно, кто и с какого IP пользовался bypass'ом за последний день.
4. **Не давать доступ к панели третьим лицам без 2FA** — панельный API даёт CRUD на `debug_allow.json`.

Патч 07-14 (`whitelist-debug-allow-parity-2026-07-14`) сделал whitelist работающим на 6 mini-clo боксах — раньше main КЛО и Type C расходились, что приводило к жалобам «whitelist не работает на моей приле».

## 3. Sync auth: `X-Sync-Secret` + HMAC-подобная схема

**Текущая реализация.**
- `mini_server_secrets.json` на main КЛО хранит `{mini_id: secret}` (32-байтовые base64-строки).
- Бокс шлёт свой секрет в заголовке `X-Sync-Secret`.
- `_auth()` в `api/sync_routes.py:46-54` перебирает все секреты и возвращает `mini_id`, у которого совпадение.

**Что здесь безопасно:**
- Секрет — 32 байта случайных данных, brute-force непрактичен.
- Endpoint `sync_url = https://api.threeamigosteam.com/engine` — HTTPS с валидным cert Let's Encrypt.
- Логи (`journalctl -u scoring-engine`) содержат `mini_id`, но не секрет.

**Что теоретически можно улучшить:**
- **Constant-time compare.** Текущий Python `==` для строк не является constant-time. Timing attack требует ~миллионы запросов с околочувствительной точностью на публичный HTTPS endpoint через CF — крайне маловероятно. Но если параноить, использовать `secrets.compare_digest(a, b)` в цикле.
- **Rate-limiting на `/api/sync/config` и `/api/sync/logs`** — отсутствует. Атакующий с угаданным секретом может флудить логами (мусор в БД). Recommend: в CF WAF настроить rate-limit rule на эти пути (максимум 100 req/min с одного IP).
- **HMAC-подпись body** для `/api/sync/logs` — сейчас только header-secret. Если middleware в цепочке модифицирует body — не заметим. Не критично, но HMAC-SHA256 добавил бы integrity.

## 4. Ротация секретов и ключей

### 4.1 `proxy_key`

**Когда ротировать:**
- После **любого** подозрения на утечку APK (сборка попала не туда, decompile'нули).
- Обязательно после смены разработчиков APK.
- Плановая ротация — **каждые 3-6 месяцев** для всех активных прил.

**Процедура (пример для 1 прилы):**
1. Сгенерировать новый ключ: `python3 -c 'import secrets; print("pk_"+secrets.token_hex(16))'`.
2. Update `apps.json` на main КЛО (`proxy_key` field).
3. Update `proxy_keys.json` на main КЛО (заменить старую запись новой, сохранить `allowed_packages`).
4. Если это Type C бокс — заменить хардкод в nginx-конфиге на боксе (4 места: `/web_content`, `/api/collect`, `/go`, `@<name>_sdk_proxy`). Пример:
   ```bash
   ssh root@<box>
   cp /etc/nginx/sites-enabled/<site> /root/nginx-backups/<site>.bak-$(date +%s)
   sed -i 's|pk_OLD|pk_NEW|g' /etc/nginx/sites-enabled/<site>
   nginx -t && systemctl reload nginx
   ```
5. Rebuild APK с новым `proxy_key` и релиз.
6. Force sync + рестарт mini-clo на всех боксах, где эта прила: `systemctl start mini-clo-sync && systemctl restart mini-clo`.
7. Verify: старым ключом → 403, новым — 200. Панель показывает клика с новым `proxy_key`.

**⚠️ Downtime**. Между шагами 3 и 5 (relase нового APK) APK-версии с старым ключом получают 403. Либо **выкатывать APK-релиз ДО ротации ключа на сервере** (тогда старые версии продолжают работать, новые тоже, потом убираешь старый ключ), либо согласовать окно с клиентом.

**Recommendation (не реализовано).** Поддержка **двух активных ключей одновременно** в `proxy_keys.json` (rotation window ~7 дней) — сейчас `allowed_packages` расширена, но `proxy_key` один на прилу. TODO — `active_proxy_keys: [pk_new, pk_old]` с graceful window.

### 4.2 `mini_server_secret`

**Когда ротировать:**
- После подозрения на утечку с боксa.
- Плановая ротация — раз в 6-12 месяцев.

**Процедура (для 1 бокса):**
1. Сгенерировать новый: `python3 -c 'import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))'`.
2. На боксе: `echo -n '<new>' > /opt/mini-clo/config/mini_server_secret; chmod 600 ...`.
3. На main КЛО: `mini_server_secrets.json` заменить старое значение новым для соответствующего `mini_id`. `systemctl restart scoring-engine` (для reload — на самом деле `_load_secrets()` в `api/sync_routes.py:36-43` читает файл на каждый запрос, но всё же перестраховаться).
4. На боксе: `systemctl restart mini-clo mini-clo-sync`.
5. Verify: `curl -s -H "X-Sync-Secret: <new>" https://api.threeamigosteam.com/engine/api/sync/health` → 200 с новым `mini_server_id`. Старый секрет → 403.

**⚠️ Порядок важен.** Если сначала обновить main КЛО и не успеть обновить бокс, бокс потеряет sync (config устареет, log_shipper начнёт копить `pending.jsonl`). Правильный порядок:
1. Написать новое значение на бокс (файл).
2. **НЕ** рестартовать mini-clo.
3. Написать значение на main КЛО.
4. Одновременно рестартовать оба.

### 4.3 GCP-ключи Play Integrity

**Когда ротировать:**
- **Обязательно** после того как кто-то посторонний имел доступ к боксу или main КЛО.
- **Плановая** — раз в год (GCP рекомендует).
- Если Google console показывает подозрительную активность (аномально много `decodeIntegrityToken` вызовов) — немедленно.

**Процедура:**
1. Google Cloud Console → IAM & Admin → Service Accounts → выбрать SA (например `play-integrity-visao@totalcasino-visao.iam.gserviceaccount.com`) → Keys → Add Key → Create new key (JSON).
2. Скачать новый JSON, положить рядом со старым: `/opt/scoring-engine/config/gcp-key-<proj>.json.new`.
3. Проверить, что новый ключ работает — например через test-скрипт `decodeIntegrityToken` с известным токеном.
4. Атомарно заменить: `mv gcp-key-<proj>.json.new gcp-key-<proj>.json`.
5. Reload на main КЛО: `curl -X POST http://127.0.0.1:8000/api/integrity/reload`. Endpoint hot-reload'ит все `gcp-key*.json` без рестарта scoring-engine.
6. На всех Type C боксах, у кого этот `gcp_project_id` в apps.json: forse sync + restart mini-clo (sync подтянет base64-decoded новый ключ; restart — потому что `play_integrity_client._services` жив в памяти, `reload()` есть, но `sync.py` его не вызывает).
7. В Google Cloud удалить старый ключ (через несколько дней после подтверждения, что нигде не остался).

**Файл-права:** `chmod 600 /opt/mini-clo/config/gcp-key-*.json` (по умолчанию так и есть в `sync.py:103`).

### 4.4 SSH root пароли

**После инцидента 07-14** (клиент столкнулся с подозрением на leak) пароли на всех боксах были ротированы централизованно. Хранятся в encrypted store клиента (см. [infra-access](../memory/infra-access.md)).

**Рекомендация.** Перейти на **SSH-ключи** (ED25519) и запретить password auth:
```bash
# на каждом боксе:
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3... admin@team' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# /etc/ssh/sshd_config:
#   PasswordAuthentication no
#   PubkeyAuthentication yes
systemctl restart sshd
```

Отдельные ключи для каждого админа (не shared), с расшариванием через 1Password/Bitwarden.

### 4.5 IPinfo / IPQS API-токены

Хранятся в `mini-clo.service` (`Environment=IPINFO_TOKEN=...`). Ротация:
1. В IPinfo/IPQS UI сгенерировать новый токен.
2. `sed -i 's/OLD_TOKEN/NEW_TOKEN/g' /etc/systemd/system/mini-clo.service` (на каждом боксе — можно ansible/bash-loop).
3. `systemctl daemon-reload && systemctl restart mini-clo`.
4. Отозвать старый.

**Recommendation.** Вынести в файл-secret вместо unit-Environment (виден в `systemctl show mini-clo`).

## 5. Backup / audit

### 5.1 Backup nginx-конфига

**Правило:** backup **вне** `/etc/nginx/sites-enabled/`. Иначе include glob подхватит `.bak` → `duplicate server_name` при `nginx -t`.

```bash
mkdir -p /root/nginx-backups
cp /etc/nginx/sites-enabled/X /root/nginx-backups/X.bak-$(date +%s)
# правки → nginx -t → reload
```

### 5.2 Backup apps.json / proxy_keys.json

Периодически (cron daily):
```bash
0 3 * * * cp /opt/scoring-engine/config/apps.json /root/backups/apps.json.$(date +\%F)
0 3 * * * cp /opt/scoring-engine/config/proxy_keys.json /root/backups/proxy_keys.json.$(date +\%F)
find /root/backups -mtime +30 -delete
```

### 5.3 Audit — `journalctl` полезные grep'ы

```bash
# Кто пользовался debug_bypass за сутки
journalctl -u scoring-engine --since "1 day ago" | grep "DEBUG bypass"

# Cross-app leak attempts (post 07-15 patch)
journalctl -u scoring-engine --since "1 day ago" | grep xappid_cross_leak_blocked

# Sync errors (bok → main)
journalctl -u mini-clo --since "1 day ago" | grep -iE "sync.*fail|flush.*fail"

# PI decode failures (Google API)
journalctl -u scoring-engine --since "1 day ago" | grep "PI verify failed"

# Skip internal IP (health/probe трафик — не должно расти)
journalctl -u scoring-engine --since "1 day ago" | grep skip_internal_ip | wc -l
```

## 6. Общие принципы

1. **Least privilege.** GCP service accounts — только `roles/serviceusage.serviceUsageConsumer` + Play Integrity API. Никаких owner/editor.
2. **Secrets not in git.** `mini_server_secrets.json`, `proxy_keys.json`, `gcp-key-*.json`, `.env` — **никогда** не коммитить. `.gitignore` строгий.
3. **Panel authentication** — 2FA обязательно, ограничить доступ IP-whitelist по возможности.
4. **CF WAF managed rules** включены (OWASP core + Cloudflare managed) на всех зонах.
5. **CF Bot Fight Mode** — включен, но с осторожностью: agressive настройка ломает Chrome CT flow, ищите баланс.
6. **Regular Debian security updates** — `apt update && apt upgrade -y` минимум раз в 2 недели. `unattended-upgrades` для критических patches.
7. **Мониторинг** — `journalctl` grep-паттерны выше запускать через cron с алертами (Telegram bot, email) на аномалии.

## 7. Incident response — если leak подтверждён

Быстрый чек-лист:
- [ ] **Ротировать** утекший ключ / секрет / пароль немедленно (см. §4).
- [ ] Проверить `request_logs` за последние 7 дней на аномалии (много запросов с одного IP, unusual verdict-паттерны, cross-app признаки).
- [ ] `journalctl -u scoring-engine | grep xappid_cross_leak_blocked` — если атака попыталась через X-App-Id override.
- [ ] Оценить радиус: только 1 бокс или все? Один `proxy_key` или несколько?
- [ ] Уведомить клиента. Задокументировать в memory (`.md` файл в `.claude/projects/.../memory/`).
- [ ] Post-mortem: что не сработало, как ужесточить patch (например добавить `allowed_domains` guard на mini-clo).

Related: `cross-app-leak-fix-2026-07-15`, `whitelist-debug-allow-parity-2026-07-14`, `landing-box-3000-exposure-incident`, `visao-integrity-fix-2026-07-14`, `infra-access` (encrypted), `mini-clo-sync-gotchas`, `pi-decode-timeout-fix`.
