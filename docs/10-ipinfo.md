# IPinfo — интеграция и фильтры

## Обзор

**IPinfo.io** — основной внешний источник данных об IP в системе с июля 2026 (Phase A/B/C rollout, задачи 235-237). Заменил IPQS (retired 16.07.2026, биллинг истёк, silent fail-open через null-stub `external/ipqs_client.py`).

Используется для:
- Определения ASN и ISP → фильтр `asn_google` (hard-kill Google-owned IP).
- Определения hosting/vpn/proxy → tiered scoring в `scoring_engine.py`.
- Определения residential proxy (`res_proxy`) → soft-signal (не hard-kill, чтобы не резать реальных returning users).
- Geo enrichment (country, city, region) → используется в pipeline фильтров gео и в audit logs.

## Что даёт ipinfo (поля из API)

Endpoint `https://ipinfo.io/{ip}?token=$IPINFO_TOKEN` возвращает JSON:
```
{
  "ip": "1.2.3.4",
  "hostname": "...",
  "city": "Berlin",
  "region": "Berlin",
  "country": "DE",
  "loc": "52.52,13.40",
  "org": "AS15169 Google LLC",
  "postal": "10115",
  "timezone": "Europe/Berlin",
  "asn": {"asn": "AS15169", "name": "Google LLC", "domain": "google.com", "type": "hosting"},
  "company": {"name": "Google LLC", "domain": "google.com", "type": "hosting"},
  "privacy": {"vpn": false, "proxy": false, "tor": false, "relay": false, "hosting": true, "service": ""},
  "abuse": {...},
  "domains": {...}
}
```

Ключевые поля: `asn.asn`, `asn.type`, `privacy.{vpn,proxy,tor,relay,hosting}`, `country`.

## Setup — IPINFO_TOKEN

Токен хранится в `/opt/scoring-engine/.env`:
```
IPINFO_TOKEN=<32-char-hex>
```
Как получить — https://ipinfo.io → Dashboard → Access Token. Пакет Business ($249/mo) обязателен для поля `privacy` (vpn/proxy/tor detection). Standard пакет отдаёт только ASN/geo.

**Ротация**: заменить значение в `.env` + `systemctl restart scoring-engine`. Кеш ipinfo (Redis) очистится естественно через TTL.

**Rate limits**: Business = 500k req/mo (~16k/day). При привышении API возвращает 429 → код обрабатывает fail-open (см. секцию «Fail-open»).

## Wire-up на main КЛО

Файл: `/opt/scoring-engine/external/ipinfo_client.py`

Класс `IPInfoClient` с методом `lookup(ip: str) -> Optional[IPInfoResult]`.

Вызывается из `api/init_routes.py` в pipeline `/init` (после IP extraction, до scoring). Результат кладётся в scoring context — далее его используют:
- `scoring_engine.py` — начисляет points по privacy-полям и типу ASN.
- Rejection code assignment — если суммарный score превысил AUTOBAN_SCORE и trigger был ipinfo-based, ставится соответствующий `rejection_code`.

Кэш — Redis, ключ `ipinfo:{ip}`, TTL 1 час.

## Wire-up на mini-clo

Файл: `/opt/mini-clo/external/ipinfo_client.py` (идентичный код на всех Type C mini-clo боксах).

Env var `IPINFO_TOKEN` в systemd unit `/etc/systemd/system/mini-clo.service`. mini-clo делает свой lookup для advanced scoring на edge (задача 239 — Advanced scoring на mini-КЛО, 6 features). Backup fallback если API недоступен — soft continue.

## Фильтры и rejection codes

### `asn_google` (hard-kill)

Если `asn.asn` в blocklist из `/opt/scoring-engine/config/google_asn_blocklist.json` (AS15169, AS396982, AS36040, etc.) → hard-kill, `rejection_code="asn_google"`. Цель — не отдавать grey кликам с Google-owned IPs (Play Store crawlers, cloud probes).

### `ipinfo_hosting`

Если `privacy.hosting=true` OR `asn.type="hosting"` → soft-signal, points в scoring engine. По умолчанию tiered (не hard-kill).

### `ipinfo_vpn`

Если `privacy.vpn=true` → добавляется в scoring. Hard-kill если суммарный score > threshold (обычно для protected apps с `block_ipinfo_vpn=true`).

### `ipinfo_proxy`

Если `privacy.proxy=true` → аналогично vpn.

### `ipinfo_res_proxy` (soft everywhere)

Если `privacy.relay=true` OR определён residential proxy маркер (CGNAT + suspicious org) → **soft-only** (задача 250, res_proxy → soft everywhere). Не hard-kill даже для protected apps — режет реальных returning users на мобильных сетях EU (Vodafone, Orange CGNAT).

Rollback (если модеры проходят через residential): изменить handling в `scoring_engine.py` (backup: `.bak-respsoft-*`).

## ASN whitelist

Файл: `/opt/scoring-engine/config/google_asn_blocklist.json`

Формат:
```json
["AS15169", "AS396982", "AS36040", "AS45566", ...]
```

Также есть per-app override: `apps.json` содержит поле `asn_whitelist: ["AS1234"]` — если IP клика в этих ASN, `asn_google` не срабатывает (для конкретной прилы). Используется когда нужно пропустить конкретный CDN/оператор.

Для mini-clo — тот же файл синкается через `/api/sync/config` (см. `docs/04-sync-flow.md`).

## Per-app overrides (`block_ipinfo_*`)

В `apps.json` для каждой прилы:
```json
{
  "package_name": "com.example.app",
  "block_ipinfo_vpn": true,
  "block_ipinfo_proxy": true,
  "block_ipinfo_hosting": false,
  ...
}
```

По умолчанию для новых прил: `block_ipinfo_hosting=true`, остальные `false` (клиент включает вручную для protected прил).

## Кэширование в Redis

Ключи:
- `ipinfo:{ip}` — TTL 3600s (1 час), value = JSON-serialized `IPInfoResult`.
- `ipinfo_asn:{asn}` — TTL 24 hours, для ускорения группированных запросов.

Cache eviction: при заполнении LRU. Проверить размер: `redis-cli DBSIZE`.

## Fail-open поведение

Если `IPINFO_TOKEN` пустой → `ipinfo_client.lookup()` возвращает None → все ipinfo-based checks skip → scoring continues без данных ipinfo. Клик проходит **без** hard-kill по ipinfo (но может провалить другие фильтры: PI, velocity, etc.).

Если API отвечает 429/500/timeout → тот же fail-open. Логируется `logger.warning("ipinfo lookup failed for X: <err>")`.

**НЕ fail-closed** — приоритет клиента: пропустить возможного bot vs заблокировать реального юзера. Fail-closed можно включить в `ipinfo_client.py` (закомментировано в конце файла).

## Мониторинг success rate

За 24h:
```bash
journalctl -u scoring-engine --since '24 hours ago' | grep -c 'ipinfo.*OK'
journalctl -u scoring-engine --since '24 hours ago' | grep -c 'ipinfo lookup failed'
```

Sample response:
```bash
journalctl -u scoring-engine --since '5 min ago' | grep -i 'ipinfo' | tail -5
```

Panel UI (задача 237): `/dashboard/audit` показывает per-request ipinfo data (asn, country, privacy flags) в раскрывающемся `raw_payload`.

## Миграция с IPQS

**Почему сменили**: IPQS billing истёк 2026-07 (клиент не оплатил), API отвечал `success:false, "insufficient credits"`. Код `ipqs_client.py` НЕ проверял `success` → трактовал как «чистый IP» → все `fraud_score=0` → фильтр de facto выключен. Fail-open молча.

**Что ipinfo даёт вместо**: `privacy.vpn/proxy/tor/relay` покрывает основной use-case IPQS (~95%). `fraud_score` (tiered 0-100) ipinfo не отдаёт — вместо этого scoring_engine собирает свой score из privacy-полей + ASN type + geo mismatch.

**Что осталось**: `ipqs_client.py` заменён на **null-stub** (`external/ipqs_client.py`) — все методы возвращают None → callers skip → нет network calls. Backup оригинала: `.bak-ipqsrm-*`.

**IPQS refs в коде** (14 файлов): imports/references сохранены как noop чтобы не ломать сигнатуры функций. Полное удаление ссылок опционально (можно сделать бачем следующим relase-ом).

## Rollback

Вернуть IPQS (если понадобится):
```bash
sshpass -p 'sFRzOlhOcTyq' ssh root@31.76.251.103 \
  "cp /opt/scoring-engine/external/ipqs_client.py.bak-ipqsrm-1784187428 \
      /opt/scoring-engine/external/ipqs_client.py && \
   echo 'IPQS_API_KEY=<old_key>' >> /opt/scoring-engine/.env && \
   systemctl restart scoring-engine"
```

Внимание: старый ключ **не оплачен**, IPQS будет возвращать `success:false` пока не пополнить credits. Restore имеет смысл только с новым/оплаченным ключом.
