# 07. Deployment: как задеплоить новый Type C mini-server с нуля

> Актуально на 2026-07-16. Основано на текущем ViSao-боксе (38.244.152.11, домен `totalsupergame.com`).

Тип C = mini-clo :8100 (Python FastAPI) + Next.js landing :3000 + nginx-сплиттер. Подходит для новых прил, которым нужен полный локальный скоринг с Play Integrity decode на боксе.

## Prerequisites

- **VPS Debian 12** (Bookworm) с root SSH-доступом. Рекомендуется 2 vCPU, 2 GB RAM, 40 GB SSD. Провайдеры: DigitalOcean, Hetzner, PQ.
- **Домен** — купить (Namecheap / Cloudflare Registrar) и заведён на **Cloudflare** (proxy=orange cloud обязательно, чтобы APK ходил через CF).
- **Cloudflare API token** (Zone.DNS.Edit + Zone.SSL.Edit для нужной зоны) — есть в [infra-access](../memory/infra-access.md).
- **Access к main КЛО**: SSH к `31.76.251.103` (пароль в infra-access) для регистрации бокса.
- **Google Cloud Project** для Play Integrity API (один project на пакет). Если пакет — новая связка, нужно создать service account с ролью «Service Usage Consumer» + разрешить Play Integrity API, скачать JSON-ключ.
- **Package name** пакета в Play Store, `sha256` подпись APK — нужны для Play Integrity console binding.
- **Уникальный `proxy_key`** (32 hex, format `pk_<32hex>`). Например: `python3 -c 'import secrets; print("pk_"+secrets.token_hex(16))'`.
- **Уникальный `mini_server_id`** — короткая строка вроде `total-casino-3`. Регистрируется в `mini_server_secrets.json` main КЛО.
- **Уникальный `mini_server_secret`** — 32 байта base64. Пример: `python3 -c 'import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))'`.

Далее по шагам. Все команды предполагают, что вы уже на боксе как root.

## Step 1 — Обновить систему, поставить базовые пакеты

```bash
apt update && apt upgrade -y
apt install -y \
  nginx certbot python3-certbot-nginx \
  python3.12 python3.12-venv python3-pip \
  redis-server \
  git curl jq ufw \
  ca-certificates gnupg lsb-release
```

Docker (для Next.js landing) — если landing собран как Docker-образ:
```bash
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
```

## Step 2 — Firewall

**Обязательно до открытия :3000 в мир.**

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status verbose   # проверить что 3000 и 8100 не открыты
```

## Step 3 — Redis (локально)

```bash
systemctl enable --now redis-server
redis-cli ping   # → PONG
# Убедиться что слушает только localhost:
grep -E '^bind' /etc/redis/redis.conf   # должно быть "bind 127.0.0.1 ::1"
```

## Step 4 — Cloudflare DNS

Через API или UI:
- `A totalsupergame.com → <bok-IP>` proxy=on (orange cloud).
- SSL/TLS mode: **Full (strict)** — Let's Encrypt cert будет на origin.

## Step 5 — nginx skeleton + Let's Encrypt

Создать минимальный `/etc/nginx/sites-available/total-casino`:
```nginx
server {
    listen 80;
    listen [::]:80;
    server_name totalsupergame.com;
    root /var/www/html;
}
```

Активировать:
```bash
ln -s /etc/nginx/sites-available/total-casino /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

Выпустить cert:
```bash
certbot --nginx -d totalsupergame.com --agree-tos -m ops@yourorg.com --no-eff-email
# Certbot допишет 443-server-block и redirect. Далее мы полностью перепишем конфиг.
```

## Step 6 — Cloudflare real-IP snippet

Создать `/etc/nginx/snippets/cloudflare-realip.conf` — скопировать содержимое из этого репо: `/tmp/kaliningrad-infra/mini-server-visao/nginx/cloudflare-realip.conf` (список CF-диапазонов + `real_ip_header CF-Connecting-IP; real_ip_recursive on`).

## Step 7 — Финальный `sites-enabled/total-casino`

Взять шаблон из `/tmp/kaliningrad-infra/mini-server-visao/nginx/sites-enabled__total-casino.conf` и подставить свои значения:
- `server_name` → ваш домен.
- `X-Proxy-Key` (в 4 местах: `/web_content`, `/api/collect`, `/go`, `@vsao_sdk_proxy` → тут может быть свой префикс имени, замените `vsao` на что-то уникальное) → ваш proxy_key.
- `ssl_certificate` пути от certbot.
- SDK-путь (`/game` в ViSao) — может отличаться на вашем пакете.

Проверить:
```bash
nginx -t
systemctl reload nginx
```

## Step 8 — Установить mini-clo из этого репо

```bash
mkdir -p /opt/mini-clo
cp -r /tmp/kaliningrad-infra/mini-server-visao/mini-clo/* /opt/mini-clo/
cd /opt/mini-clo
python3.12 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
```

## Step 9 — Конфиги mini-clo

```bash
mkdir -p /opt/mini-clo/config /opt/mini-clo/logs
# 1. sync_url
echo -n 'https://api.threeamigosteam.com/engine' > /opt/mini-clo/config/sync_url

# 2. mini_server_secret (только цифры/буквы, без переноса строки)
echo -n '<новый уникальный secret>' > /opt/mini-clo/config/mini_server_secret
chmod 600 /opt/mini-clo/config/mini_server_secret

# 3. Пустой apps.json — sync подтянет
echo '[]' > /opt/mini-clo/config/apps.json
```

## Step 10 — GCP-ключ для Play Integrity

Файл `gcp-key-<project_id>.json` (например `gcp-key-totalcasino-visao.json`) можно:
- Скопировать с main КЛО (`/opt/scoring-engine/config/gcp-key-<proj>.json`) — но так делаем только для bootstrap.
- Или дождаться sync: если на main КЛО ключ есть и `gcp_project_id` прописан в `apps.json` — sync его подтянет автоматически (base64-decoded).

Проверить:
```bash
ls -la /opt/mini-clo/config/gcp-key-*.json
chmod 600 /opt/mini-clo/config/gcp-key-*.json
```

## Step 11 — Systemd unit для mini-clo

Создать `/etc/systemd/system/mini-clo.service` (шаблон в этом репо: `/tmp/kaliningrad-infra/mini-server-visao/systemd/mini-clo.service`), заменить только `BOUNCE_URL_BASE=https://<ваш-домен>`. IPINFO_TOKEN / IPQS_API_KEY / REDIS_URL — общие.

Опционально создать `/etc/systemd/system/mini-clo-sync.service` (oneshot, дергает `sync.py` standalone) + `mini-clo-sync.timer` на каждые 5 минут:

```ini
# mini-clo-sync.service
[Unit]
Description=mini-КЛО periodic config sync
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/mini-clo
ExecStart=/opt/mini-clo/venv/bin/python /opt/mini-clo/sync.py
```

```ini
# mini-clo-sync.timer
[Unit]
Description=Run mini-clo-sync every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Unit=mini-clo-sync.service

[Install]
WantedBy=timers.target
```

Активировать:
```bash
systemctl daemon-reload
systemctl enable --now mini-clo-sync.timer
```

## Step 12 — Регистрация бокса на main КЛО

**На main КЛО (`31.76.251.103`):**

1. Добавить секрет в `/opt/scoring-engine/config/mini_server_secrets.json`:
   ```bash
   ssh root@31.76.251.103
   python3 -c "
   import json
   p='/opt/scoring-engine/config/mini_server_secrets.json'
   d=json.load(open(p))
   d['total-casino-3'] = '<секрет который на боксе>'   # тот же!
   json.dump(d, open(p,'w'), indent=2)
   "
   ```

2. Прописать `mini_server_id` в целевой прилы в `/opt/scoring-engine/config/apps.json`:
   ```bash
   python3 -c "
   import json
   p='/opt/scoring-engine/config/apps.json'
   d=json.load(open(p))
   for a in d:
       if a['package_name'] == '<целевой пакет>':
           a['mini_server_id'] = 'total-casino-3'
           a['proxy_key'] = 'pk_<новый>'   # если новая прила
           a['gcp_project_id'] = '<gcp project id>'
   json.dump(d, open(p,'w'), indent=2, ensure_ascii=False)
   "
   ```

3. Добавить proxy_key в `/opt/scoring-engine/config/proxy_keys.json` (patch 07-15 требует `allowed_packages`):
   ```json
   "pk_<новый>": {
     "package_name": "<пакет>",
     "name": "<display name>",
     "allowed_packages": ["<пакет>"]
   }
   ```

4. Загрузить GCP-ключ (если новый) в `/opt/scoring-engine/config/gcp-key-<proj>.json`. Reload PI:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/integrity/reload
   ```

5. (Опционально) Reload apps без рестарта scoring-engine — есть панельный endpoint. Если сомневаетесь: `systemctl restart scoring-engine`.

## Step 13 — Запустить mini-clo

**На боксе:**
```bash
systemctl daemon-reload
systemctl enable --now mini-clo.service
systemctl start mini-clo-sync.service   # первый blocking sync
systemctl status mini-clo
```

Убедиться:
```bash
curl -s http://127.0.0.1:8100/health
# → {"ok":true,"apps_count":1,"pi_keys":1}   ← если apps_count=0 — п.4.1 в 04-sync-flow.md
```

## Step 14 — Landing (Next.js)

Вариант A (docker):
```bash
mkdir -p /opt/landing && cd /opt/landing
# распаковать образ / clone репо с landing
# docker-compose.yml обязательно ports: '127.0.0.1:3000:3000'
docker compose up -d
```

Вариант B (standalone systemd):
```bash
# next build --output=standalone
# положить в /opt/landing/ .next/, server.js
cat > /etc/systemd/system/total-casino.service <<'EOF'
[Unit]
Description=Total Casino Next.js landing
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/landing
Environment=NODE_ENV=production
Environment=HOSTNAME=127.0.0.1
Environment=PORT=3000
ExecStart=/usr/bin/node server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now total-casino
```

Проверить: `curl -s http://127.0.0.1:3000/` — должно вернуть HTML лендинга.

## Step 15 — Тестирование end-to-end

### 15.1 nginx UA-split (браузерный запрос)

```bash
curl -sI https://totalsupergame.com/game -H 'User-Agent: Mozilla/5.0'
# → 200 + Content-Type: text/html  (Next.js landing)
```

### 15.2 SDK-запрос (okhttp UA) — должен пойти на mini-clo :8100

```bash
curl -sk -X POST https://totalsupergame.com/game \
  -H 'User-Agent: okhttp/4.11.0' \
  -H 'X-App-Id: <пакет>' \
  -H 'X-Sid: test-sid-uuid' \
  -H 'X-Instance-Id: test-instance-uuid' \
  -H 'X-Integrity-Token: dummy_will_fail_pi_but_pipeline_ok' \
  -H 'X-Locale: en-US'
# Ожидаемый ответ:
# 200 {"url":"<safe_url>"}   ← white потому что PI dummy отклонится, но 200 подтверждает
#                              что SDK-путь работает: nginx → mini-clo → scoring → response
```

Проверить логи одновременно в двух консолях:
```bash
tail -f /var/log/nginx/visao_trace.log         # nginx trace
journalctl -u mini-clo -f                       # scoring
```

Должны увидеть в mini-clo:
- `HDRTRACE` строка (если пакет ViSao/CauHoiViSao).
- `IPinfo <ip>: country=... asn=...`.
- `Integrity [...]: app=... device=...` (Google PI ответит `HttpError 400 invalid token` — норм для dummy).
- `[<ip>] init: pkg=<pkg> pi=False verdict=white rej=integrity_missing ...`.

### 15.3 Sync working

```bash
# 1. Локальный apps.json содержит целевую прилу
grep <пакет> /opt/mini-clo/config/apps.json

# 2. sync_state.json обновлён недавно
cat /opt/mini-clo/config/sync_state.json

# 3. log_shipper flush — сделать несколько запросов, потом проверить
journalctl -u mini-clo | grep 'Flushed'
# → Flushed N/M logs (N > 0)
```

### 15.4 Логи на main КЛО

```bash
# На main КЛО — Postgres
ssh root@31.76.251.103
sudo -u postgres psql -d scoring -c "
SELECT COUNT(*) FROM request_logs
WHERE headers->>'source' = 'mini-clo'
  AND headers->>'x-app-id' = '<пакет>'
  AND timestamp > NOW() - INTERVAL '5 minutes';"
# → > 0 — значит log_shipper дошёл
```

### 15.5 Панель клиента

Открыть панель, найти прилу в списке apps, посмотреть feed запросов за последние 5 минут — там должны появиться тестовые клика с verdict=white и rejection=integrity_missing.

## Post-deploy checklist

- [ ] `ufw status verbose` показывает `deny :3000`, `deny :8100`
- [ ] `curl http://<box-ip>:3000/` извне → **timeout/refused** (не 200)
- [ ] `curl http://<box-ip>:8100/health` извне → **timeout/refused**
- [ ] Cloudflare зона включена (orange cloud), SSL mode Full (strict)
- [ ] Панель клиента видит клика через новую прилу
- [ ] Backup nginx-конфига **вне** `/etc/nginx/sites-enabled/` — иначе nginx include glob подхватит `.bak` файлы (см. [08-troubleshooting.md](08-troubleshooting.md))
- [ ] Мониторинг: `journalctl -u mini-clo --since "1 hour ago" | grep -Ei 'error|fail'` — должно быть 0 или только known-fail-open (`IPQS lookup failed` при пустом IP и т.п.)

Related: `mini-server-architecture`, `visao-integrity-fix-2026-07-14`, `mini-clo-sync-gotchas`, `cross-app-leak-fix-2026-07-15`.
