# Фильтры и scoring — полный справочник

Документ описывает пайплайн решения `/init` от auth до финального verdict. Основной файл: `main-klo/api/init_routes.py` (~1225 строк, функция `_resolve()`), с делегированием базовых скор-проверок в `main-klo/scoring_engine.py`.

**Формула вердикта**:
```
total_score = base_score + pi_score + velocity_score + extra_score
threshold   = config_store.engine.scoreThreshold           # default 70
verdict     = "white" if total_score >= threshold else "grey"
```

`AUTOBAN_SCORE = 100` — любой hard-kill моментально флипает вердикт (score ≥ 70).

**Grey** = отдаём оффер (bounce URL c enrichment `?clickid=<iid>&geo=<country>`).
**White** = отдаём `safe_url` прилы.

---

## 1. Пайплайн — 6 стадий

```
┌─────────────────────────────────────────────────────────────────────────┐
│  1. AUTH        → resolve_proxy_key + X-App-Id cross-app leak guard    │
│  2. GATES       → panic_mode, skip_internal_ip, debug_bypass, autoban  │
│  3. HARD-KILL   → 8 фильтров (первый match = white + AUTOBAN)          │
│  4. BASE SCORE  → scoring_engine.score_request()                        │
│  5. PI VERIFY   → strict / soft / lenient (Google API decode)          │
│  6. VELOCITY +  → Redis counters + Soft-PI extras + cloak_consumed     │
│     FINAL       → total_score >= threshold ? white : grey              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Стадия 2 — Gates (early exits)

### 2.1. `panic_mode`

Флаг `app.panic_mode` (тумблер в панели `PUT /api/apps/{id}/panic`). Мгновенный white + `safe_url`, без логирования scoring. **Использовать только на реально забаненной приле.**

### 2.2. `skip_internal_ip`

Приватные IP (`127.*`, `10.*`, `172.16-31.*`, `192.168.*`, `::1`, `fc00:*`, `fd00:*`, `0.0.0.0`) → white без логирования. Health checks / docker bridge / cron probes без `X-Forwarded-For`. Добавлено 2026-07-15 после жалобы клиента (490 rejections/7d от 172.18.0.1).

### 2.3. `debug_bypass` (whitelist)

`config/debug_allow.json` — IP или instance_id → **force grey** + оффер. Обходит все фильтры. Точечная дырка под тест разработчиков. Синкается на mini-clo с 2026-07-14.

### 2.4. `autoban_hit` (negative cache)

3-tier модель (Redis 24h → Postgres 24h-7d → CF-KV 365d). Если `(ip, package)` в banlist — instant white без вызова IPinfo/IPQS/PI (экономит quota). `AUTOBAN_ENFORCE` env-var (по умолчанию `true`).

`AUTOBAN_CODES_G1` — всегда попадают в banlist:
- `asn_google`, `asn_vpn`, `ipqs_vpn` (Tor unconditional), `ipinfo_vpn`, `ipinfo_hosting`, `tor_exit`.

`AUTOBAN_CODES_G2` (за флагом `AUTOBAN_G2_READY`):
- `pi_nonce_replay`, `pi_unlicensed`, `pi_capturing`, `pi_controlling`, `pi_unevaluated_combo`, `velocity_block`.

`GLOBAL_AUTOBAN_CODES` — банятся без привязки к package (`package_key=None`):
- `asn_google`, `asn_vpn`, `tor_exit`, `ipqs_vpn` (Tor).

**Grey → `mark_grey(ip, pkg)`** (Redis 1h negative-negative cache) — защита от ошибочного бана легит IPs.

---

## 3. Стадия 3 — Hard-kill chain (8 фильтров)

Проверки идут строго по порядку, **первый match** = white + AUTOBAN_SCORE. Файл: `api/init_routes.py:788-870`.

### 3.1. `instance_burnt` (**DISABLED**)

Ранее — instance помечен burnt в Redis (`instance_burnt:{pkg}:{iid}`) на 24h после PI hard-kill (`pi_nonce_replay`, `pi_unlicensed`, `pi_capturing`, `pi_controlling`, `soft_pi_extra`). Закрывал CA IPv6 attack pattern (grey без PI между white с replay токеном).

**2026-07-09 (max-conversion mode)**: `_mark_instance_burnt()` и `_is_instance_burnt()` — no-op. Клиентское решение не морозить возвраты юзера. Механизм оставлен (можно вернуть одной строкой).

### 3.2. `missing_instance_id`

Условие: `require_pi_app && block_ipqs=True && not instance_id`. Real users всегда шлют instance_id (SDK v3 генерит + SharedPreferences). Отсутствие = manual probe (curl модера) или bypass attempt.

`.strip()` закрывает whitespace bypass (2026-06-22 F4 fix): `"  "` → `""` → hard-kill срабатывает.

### 3.3. `ipqs_vpn` (Tor — unconditional)

Условие: `ipqs_res.success && ipqs_res.tor == True`. Для **всех** прил (защищённых и незащищённых). Zero FP: никто не запускает Tor exit на Android телефоне.

### 3.4. `geo_unknown` (fail-closed)

Условие: `require_pi_app && block_google_asn && (asn == 0 || geo is None) && not geo_unknown_exempt`. `geo_unknown_exempt = geo.country in app.soft_pi_countries_any_asn`.

Раньше при `ipinfo timeout → asn=0` Google/датацентр проходил. Теперь fail-closed для protected прил, кроме exemption для NG-релакса.

### 3.5. `asn_google`

Условие: `block_google_asn && asn in google_asn_blocklist`. Файл: `config/google_asn_blocklist.json`.

ASN 15169 (Google), 16591 (Google Fibre), 396982 (Google Cloud), 45566 (Accenture FTL), + подсети Firebase Test Lab / GCP Robo Crawler.

### 3.6. `asn_vpn`

Условие: `require_pi_app && block_vpn_asn && asn in vpn_asn_blocklist`. Файл: `config/vpn_asn_blocklist.json`.

M247 (9009), NordVPN (63023), Surfshark (62240), ExpressVPN, ProtonVPN, Vultr (20473), OVH (16276), Hetzner (24940), DigitalOcean (14061), Contabo, Choopa.

Добавлено 2026-06-21 после Sisal-incident (модер прошёл через M247, IPinfo не пометил как hosting).

### 3.7. `ipqs_vpn`

Условие: `require_pi_app && block_ipqs && ipqs_res.success && ipqs_res.vpn == True`.

### 3.8. `ipqs_fraud`

Условие: `require_pi_app && block_ipqs && ipqs_res.success && ipqs_res.fraud_score >= 90`.

Tuning (2026-06-22): раньше блокировали при `proxy=true` или `bot=true` → 50% FP на реальных CGNAT юзерах (Fastweb IT 85.18.0.133, Bouygues FR 176.150.1.1, MTN NG 102.91.103.241, Airtel NG 105.112.101.6). Теперь только сильные сигналы vpn / fraud_score≥90.

---

## 4. Стадия 4 — Базовый scoring (`scoring_engine.score_request()`)

Файл: `main-klo/scoring_engine.py:199-737`. **Все проверки накапливаются в `total_score`**, verdict флипается при `total >= scoreThreshold` (default 70).

### 4.1. Blocked ASN (hardcoded set)

```python
BLOCKED_ASNS = {
    "15169", "16591", "396982",   # Google
    "8075", "714",                # Microsoft, Apple
    "16509", "14618",             # AWS
    "13335",                      # Cloudflare
    "14061", "24940", "63949", "16276",   # DigitalOcean, Hetzner, Linode, OVH
    "136907", "32934", "36459", "20473",  # Huawei, Facebook, Github, Vultr
}
```
Points = 100, `rejection="asn_blocked"`.

### 4.2. `no_client_secret`

Нет `client_secret` (X-Client-Secret / proxy_key) — points = 100, `rejection="no_client_secret"`.

### 4.3. `lang_country_mismatch_soft` (2026-07-05 tuned)

`_check_lang_country_mismatch(accept_language, country)`:
- Парсит все языки из `Accept-Language: "ru-RU,en-US;q=0.9,fr;q=0.8"` → `[ru, en, fr]`.
- Проверяет каждый через `LANG_HARDKILL_MAP` (полная карта в `scoring_engine.py:90-142`). Если хотя бы один совпадает со страной → OK.
- Если **все** распознанные языки указывают на чужие страны → mismatch.

Points = **20** (был AUTOBAN до 2026-07-05 — резал легит multi-lingual юзеров: UA беженцы в PL, DE туристы в IT, RU-speaking в LV/EE). Теперь soft: модер с VPN всё равно ловится по совокупности (res_proxy_soft 15 + hosting + 20 = 55+).

Skip: `app.disable_lang_check=True` или пустой `Accept-Language`.

### 4.4. `user_agent_block`

Матч по `lists/user_agents_block.txt`. Points = 100, `rejection="bot_user_agent"`.

### 4.5. `device_hardban` (permanent)

Хардкод в `HARDBAN_DEVICE_MARKERS`:
```python
"oneplus 8 pro", "oneplus8pro", "in2020", "in2021", "in2023", "in2025",
"s24 ultra", "sm-s928", "galaxy s24 ultra"
```
Матч в `f"{device_model} {user_agent}".lower()`. Points = 100, `rejection="device_blocked"`. Клиентский запрос — известные устройства модеров.

### 4.6. `ua_device_block` / `device_model_block`

Матч в `lists/device_models_block.txt`. Points = **40** (не hard, но проходят как признак). `google_device` флаг ставится если совпало с `pixel|nexus|google|chromebook`.

### 4.7. `codename_block`

`lists/codenames_block.txt` (например `goldfish`, `ranchu`, `vbox86p`). Points = 100, `rejection="emulator_detected"`.

### 4.8. `gpu_block`

`lists/gpu_block.txt` (`swiftshader`, `llvmpipe`, `mesa`, `ANGLE`). Points = 100, `rejection="emulator_gpu"`.

### 4.9. `device_gpu_mismatch`

Файл `config/gpu_model_map.json` — карта ~100 семейств → допустимые GPU. Если модель есть в карте, но её GPU не в whitelist → подмена фингерпринта. Points = 100, `rejection="device_spoof"`.

### 4.10. `gpu_rotation`

Redis `SADD fp:{pkg}:{ip}:{model}` c TTL 1h. Если 2+ разных GPU per (IP, model, pkg) → антидетект-ферма. Points = 100, `rejection="device_spoof"`.

### 4.11. `test_build_block`

`lists/test_builds_block.txt`. Points = 100, `rejection="test_build_detected"`.

### 4.12. `referer_block` (Google referer)

`GOOGLE_REFERERS = ["google.com/", "accounts.google.com", "support.google.com", "play.google.com/console", "admin.google.com"]`. Points = 100, `rejection="google_referer"`.

### 4.13. `ip_range_block`

CIDR из `lists/ip_ranges_block.txt`. Points = 100, `rejection="ip_range_blocked"`.

### 4.14. `tor_exit_list` (independent от IPQS)

`lists/tor_exits.txt` — обновляется cron'ом каждые 6h с `https://check.torproject.org/torbulkexitlist`. Дополняет IPQS (иногда IPQS пропускает свежие Tor exits). Points = 100, `rejection="tor_exit"`.

### 4.15. IPinfo hard-kills

| Флаг | Points | Rejection |
| --- | --- | --- |
| `ipinfo.vpn = true` | 100 (`weights.vpnProxyTor`) | `vpn_detected` |
| `ipinfo.proxy = true` | 100 | `proxy_detected` |
| `ipinfo.tor = true` | 100 | `tor_detected` |
| `ipinfo.hosting = true` | 100 (`weights.suspiciousHosting`) | `suspicious_hosting` |

### 4.16. IPinfo `res_proxy` (residential proxy) — **всегда soft**

Points = **15** (`RES_PROXY_SOFT_POINTS`), без `rejection_code`.

Раньше был hard-kill для non-CGNAT-heavy стран. **2026-07-08**: IPinfo Max флагает 99.9% трафика (мобильных операторов), как hard-kill режет живых в MQ/GF/US/LB. Мусор из не-целевых стран ловит гео, реальных ботов — PI+velocity.

`CGNAT_HEAVY_COUNTRIES` (frozenset ~60 стран): CI, NG, BD, IN, ZA, PH, ID, PK, VN, NP, SN, GH, PL, IT, RO, HU, BG, RS, HR, SI, SK, CZ, LV, LT, EE, AR, CL, MX, PE, BR, CO, UY, EC, VE, PY, BO, DO, DE, FR, ES, PT, BE, NL, AT, CH, LU, IE, DK, SE, NO, FI, GR, CY, MT.

### 4.17. IPQS — tiered scoring (2026-06-22)

| Условие | Points | Rejection |
| --- | --- | --- |
| `ipqs.vpn OR ipqs.tor` | 100 (`weights.vpnProxyTor`) | `vpn_detected` |
| `ipqs.fraud_score >= 90` | 50 | — (hard-kill выше в init) |
| `ipqs.fraud_score >= 75` | 10 | — (soft, не флипает 70 threshold) |
| `ipqs.proxy && !vpn && !tor` | 15 | — (soft, CGNAT FP protection) |
| `ipqs.bot_status = true` | 25 | — (soft, CGNAT FP protection) |

### 4.18. `country_not_allowed` (whitelist)

Если `app.allowed_countries` не пуст и `country ∉ allowed_countries` (при известном country) → points 100, `rejection="country_not_allowed"`. Fail-open при `country=""` (пусть решают остальные фильтры).

### 4.19. `country_block` (blacklist)

Матч в `lists/countries_block.txt`, если не в `app.excluded_countries`. Points = 100, `rejection="country_blocked"`.

### 4.20. `city_block`

Матч в `lists/cities_block.txt`. Points = 15 (`weights.suspiciousCity`).

### 4.21. `isp_block`

Матч substring в `lists/isp_block.txt`. Points = 20 (`weights.suspiciousHosting`), `rejection="suspicious_hosting"`.

### 4.22. `pi_cache_device_soft` (DISABLED 2026-07-15)

Раньше — если в Redis PI cache для (ip, pkg) есть empty `deviceRecognitionVerdict` → `device_compromised`. Теперь soft-log, points = 0. Клиентское решение.

### 4.23. `device_velocity`

Redis `INCR dfv:{pkg}:{model}:{gpu}:{build}` c TTL 1h. Threshold `> 30`. Points = 100, `rejection="device_velocity"`.

### 4.24. `not_webview`

Если UA есть, `client_secret` есть, но UA не содержит `wv)` и не `okhttp`, и нет SDK маркеров (`instance_id`, `has_integrity`) → браузерный заход. Points = 40.

### 4.25. `google_device_combo`

`google_device` + любой ещё scoring сигнал (`total - device_pts > 0`) → total = 100, `rejection="google_device_combo"`.

---

## 5. Стадия 5 — Play Integrity verify

Файл: `api/init_routes.py:286-499`.

### 5.1. Выбор режима

```python
if not require_pi:
    pi_mode = 'lenient'
elif _is_soft_pi_eligible(app, geo, ipqs_res):
    pi_mode = 'soft'
else:
    pi_mode = 'strict'
```

**`_is_soft_pi_eligible()`** возвращает True если ВСЕ условия:
- `app.soft_pi_countries` не пуст.
- `geo.country.upper() in app.soft_pi_countries`.
- ASN in `mobile_asn_whitelist[country]` (кроме `soft_pi_countries_any_asn` — NG-relax).
- НЕТ `ipinfo.vpn/proxy/tor/hosting`.
- IPQS `fraud_score < 75`, `bot_status=False`, `vpn/proxy/tor=False`.

### 5.2. Verdict decoding (`external/play_integrity.py`)

Класс `IntegrityVerdict` парсит JSON-ответ от Google. Ключевые поля:

```python
verdict.package_name             # requestPackageName
verdict.nonce                    # nonce (v3) или requestHash (v4)
verdict.timestamp_millis
verdict.app_recognition          # PLAY_RECOGNIZED / UNRECOGNIZED_VERSION / UNEVALUATED
verdict.certificate_sha256       # list
verdict.device_recognition       # list: MEETS_BASIC_INTEGRITY, MEETS_DEVICE_INTEGRITY, MEETS_STRONG_INTEGRITY, MEETS_VIRTUAL_INTEGRITY
verdict.device_activity_level    # LEVEL_1..4 / UNEVALUATED (PI v3)
verdict.app_licensing            # LICENSED / UNLICENSED / UNEVALUATED
verdict.play_protect_verdict     # NO_ISSUES / PLAY_PROTECT_OK / UNEVALUATED / NO_DATA (PI v3)
verdict.apps_detected            # list, содержит CAPTURING/CONTROLLING (PI v3)

# Helpers
verdict.meets_basic / meets_device / meets_strong
verdict.is_virtual_only          # VIRTUAL без DEVICE/STRONG
verdict.is_empty_device          # пустой deviceRecognitionVerdict
verdict.is_recognized_app        # PLAY_RECOGNIZED
verdict.is_licensed              # LICENSED
verdict.is_activity_unevaluated
verdict.is_play_protect_unevaluated_or_nodata
verdict.has_capturing_app / has_controlling_app
```

### 5.3. Hard-kills PI (во всех режимах strict/soft/lenient)

| Check | Условие | Reason |
| --- | --- | --- |
| `pi_missing` | strict + `!token && play_integrity.available` | Нет PI токена при strict |
| `pi_init_failed` | Verdict не декодируется | fail-closed |
| `pi_package_mismatch` | `verdict.package_name != package_name` | Cross-app replay |
| `pi_stale_or_future_token` | `token_age_ms < -5000 || > 120000` | Stale или future replay |
| `pi_timestamp_invalid` | Не парсится `timestamp_millis` | fail-closed |
| `pi_nonce_replay` | Redis SETNX `pi_nonce_seen:{nonce}` TTL 15s not added | Duplicated nonce. Skip per-app `skip_nonce_replay=True` |
| `pi_unlicensed` | `app_licensing == "UNLICENSED"` | Reviewer sideload из Play Console |
| `pi_capturing` | `has_capturing_app` | Screen recording (reviewer evidence) |
| `pi_controlling` | `has_controlling_app` | Robo/UiAutomator automation |
| `pi_unevaluated_combo` | `block_pi_unevaluated_combo && activity=UNEVALUATED && playProtect=UNEVALUATED/NO_DATA && first_init` | Свежий scanner sandbox. **`_is_first_init()` = no-op (2026-07-09)** |

### 5.4. Mode-specific PI checks

**`strict`**:
- Не `meets_device` → +100 `pi_not_device_integrity`.
- Не `is_recognized_app` → +100 `pi_app_not_recognized`.

**`soft`**:
- `is_virtual_only` → +100 `pi_virtual`.
- `is_empty_device` → +100 `pi_empty_soft` (stripped APK / Frida-patched).
- Не `meets_basic` → +100 `pi_basic_failed_soft`.
- Иначе → +0 `pi_soft_accepted`.

**`lenient`**:
- `is_empty_device` → +100 `pi_empty_device`.
- Не `meets_basic && !is_empty_device` → +100 `pi_basic_failed`.
- `is_virtual_only` → +100 `pi_virtual`.
- `app_recognition == "UNEVALUATED"` → +100 `pi_app_unevaluated`.

---

## 6. Стадия 6 — Velocity + Soft-PI extras

### 6.1. `_velocity_check(ip, instance_id)` — только для `require_pi`

3 counter'а в Redis (все fail-open при недоступности):

| Ключ | TTL | Threshold | Rejection |
| --- | --- | --- | --- |
| `vel:inst:{iid}` INCR | 300s | **> 100** (было 12) | `velocity_instance` |
| `vel:sub:{subnet}` SADD iid | 900s | **> 100** (было 15) | `velocity_subnet` |
| `vel:ip:{ip}` INCR | 300s | **> 300** (было 60) | `velocity_ip` |

Каждое срабатывание = +100. Rejection code = `velocity_block`.

`_subnet_key(ip)`: `/24` для IPv4, `/64` для IPv6 (canonical через `ipaddress` модуль).

**Max-conversion mode (2026-07-09)**: thresholds повышены в 5-7 раз чтобы не резать нормальные usage patterns (real users с бурстами).

### 6.2. Soft-PI extras (только если `soft_eligible`)

- **`asn_rotation`** — SADD `asnrot:{iid}` per instance, TTL 1h. Threshold `> 2 разных ASN`. Points = 100. **DISABLED 2026-07-09**.
- **`soft_ua_emulator`** — UA содержит `sdk_gphone|emulator|genymotion|aosp_atd|goldfish|ranchu` даже на mobile ASN. Points = 100.
- **`soft_ua_google_device`** — UA содержит `pixel|nexus|google sdk` в NG/CI/SN. Points = 100 (Pixel в Лагосе редок).

При срабатывании — `_mark_instance_burnt()` (сейчас no-op) + `rejection = "soft_pi_extra"`.

### 6.3. `cloak_consumed` (opt-in per-app)

Активируется через `app.cloak_consumed_enabled=True`. Только если vertict изначально `grey`.

```python
SETNX cloak_consumed:{pkg}:{iid} = json({"ts", "ip", "verdict": "grey"})  ex=86400
```

Первый /init → SETNX success → `consumed=False` → отдаём grey. 2-й+ за 24h → SETNX fail → `consumed=True` → флип на white + `rejection="cloak_consumed"`.

**Кейс**: Google reviewer с реальным телефоном + Bright Data residential пройдёт все 5 слоёв (ASN/Geo/UA/PI/velocity). Единственная защита — память что мы уже обслужили этот instance. Re-scan / follow-up review видит safe.

---

## 7. PI verdict — расшифровка

### 7.1. `deviceRecognitionVerdict` (list)

| Значение | Что означает | Real-world use |
| --- | --- | --- |
| Empty `[]` | Google не оценил устройство | stripped APK, Frida-patched PI, cloned Play Store, свежий sandbox |
| `["MEETS_VIRTUAL_INTEGRITY"]` | Только эмулятор | LDPlayer, BlueStacks, Genymotion, FTL emulator |
| `["MEETS_BASIC_INTEGRITY"]` | Устройство ок, но не signed by Google | AOSP, custom ROM, rooted, sideload |
| `["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"]` | Google-certified устройство | Реальный consumer Android |
| `+ "MEETS_STRONG_INTEGRITY"` | Hardware-backed key attestation | Modern Pixel, Samsung Knox, etc |

**Soft mode пропускает** BASIC (юзеры в NG на Itel/Tecno стабильно дают BASIC).
**Strict mode требует** DEVICE минимум.

### 7.2. `appRecognitionVerdict`

| Значение | Что | Как трактуем |
| --- | --- | --- |
| `PLAY_RECOGNIZED` | APK установлен из Play Store, unmodified | OK, реальный юзер |
| `UNRECOGNIZED_VERSION` | Package name знаем, но version не в Play | Sideload той же прилы (Betsson с 1xbet.ng и т.п.) — soft |
| `UNEVALUATED` | Не проверено | В strict mode = hard-kill, в soft/lenient = OK |

### 7.3. `appLicensingVerdict`

| Значение | Что | Трактовка |
| --- | --- | --- |
| `LICENSED` | Юзер установил через свой Google account | Real user |
| `UNLICENSED` | Sideload или ADB install (typicallyfrom Play Console review) | **Reviewer flow → hard-kill во всех режимах** |
| `UNEVALUATED` | Not checked | OK (Play Protect может не успеть) |

### 7.4. `environmentDetails.playProtectVerdict` (PI v3)

- `NO_ISSUES`, `PLAY_PROTECT_OK` — real user active device.
- `POSSIBLE_RISK`, `MEDIUM_RISK`, `HIGH_RISK` — Play Protect обнаружил PHA.
- `UNEVALUATED`, `NO_DATA`, `""` — fresh sandbox / scanner profile.

### 7.5. `environmentDetails.appAccessRiskVerdict.appsDetected` (PI v3)

- `KNOWN_CAPTURING` — есть screen recording app (reviewer пишет evidence).
- `KNOWN_CONTROLLING` — есть UiAutomator/Robo/MoonAccessibility (automation framework).
- `KNOWN_OVERLAYS` — accessibility overlay.
- `UNKNOWN_CAPTURING/CONTROLLING/OVERLAYS` — не в Play, но детект по signature.

Наши hard-kills: `has_capturing_app`, `has_controlling_app` (matched через substring `"CAPTURING"`/`"CONTROLLING"`).

### 7.6. `deviceIntegrity.recentDeviceActivity` (PI v3)

- `LEVEL_1` (<10 запросов PI за час) — normal user.
- `LEVEL_2/3/4` — active user (типично 10-100+ per hour).
- `LEVEL_UNEVALUATED` / `UNEVALUATED` — Google не собрал ещё данные (fresh device < 30 min OR scanner sandbox).

Combo `activity=UNEVALUATED + playProtect=UNEVALUATED/NO_DATA` на **первом** /init = scanner signature (real user активного Pixel/Galaxy обычно имеет хотя бы один populated). Gate `first_init` защищает legitimate первые установки.

---

## 8. Score calculation — итоговая формула

```python
# Bucket 1: base (scoring_engine)
base_score = сумма всех points из ScoringDetail списка

# Bucket 2: PI verify
pi_score = 0 или AUTOBAN_SCORE (100)

# Bucket 3: velocity (только require_pi)
vel_score = 0-300 (сумма 3 counters)

# Bucket 4: soft-PI extras
extra_score = 0-300

# Combined
total_score = base_score + pi_score + vel_score + extra_score

# Threshold check (default 70)
threshold = config_store.engine.scoreThreshold
verdict = "white" if total_score >= threshold else result.verdict  # изначально grey
```

**scoreBuckets в raw_payload**:
```json
{"base": 25, "pi": 0, "vel": 0, "extra": 0, "total": 25}
```

Панель `/dashboard/audit` показывает buckets как badges на строке клика.

---

## 9. Полный справочник rejection codes

### 9.1. Auth / config

| Code | Причина | Bucket |
| --- | --- | --- |
| `no_client_secret` | Нет X-Client-Secret / proxy_key | base |
| `unknown_proxy_key` | proxy_key не найден в config | — (403 без лога) |
| `integrity_missing` | Не пришёл X-Integrity-Token при require_pi | pi |

### 9.2. Hard-kill (init pipeline)

| Code | Bucket | Fired by |
| --- | --- | --- |
| `panic_mode` | — | app.panic_mode=True |
| `debug_bypass` | 0 | debug_allow.json (verdict=grey) |
| `autoban_hit` | 100 | auto_ban.is_banned() |
| `missing_instance_id` | 100 | Protected app без X-Instance-Id |
| `ipqs_vpn` | 100 | IPQS Tor unconditional / VPN для protected |
| `ipqs_fraud` | 100 | IPQS fraud_score ≥ 90 для protected |
| `geo_unknown` | 100 | Protected + asn=0/geo=None |
| `asn_google` | 100 | ASN в google_asn_blocklist |
| `asn_vpn` | 100 | ASN в vpn_asn_blocklist |

### 9.3. Scoring (base bucket)

| Code | Points | Fired by |
| --- | --- | --- |
| `asn_blocked` | 100 | BLOCKED_ASNS hardcoded |
| `bot_user_agent` | 100 | user_agents_block.txt |
| `device_blocked` | 40-100 | device_models_block или HARDBAN_DEVICE_MARKERS |
| `emulator_detected` | 100 | codenames_block |
| `emulator_gpu` | 100 | gpu_block |
| `device_spoof` | 100 | gpu_model_map mismatch или gpu_rotation |
| `test_build_detected` | 100 | test_builds_block |
| `google_referer` | 100 | Referer = google.com/... |
| `ip_range_blocked` | 100 | CIDR из ip_ranges_block |
| `tor_exit` | 100 | tor_exits.txt |
| `vpn_detected` | 100 | ipinfo.vpn или ipqs.vpn |
| `proxy_detected` | 100 | ipinfo.proxy |
| `tor_detected` | 100 | ipinfo.tor |
| `suspicious_hosting` | 20/100 | ipinfo.hosting или isp_block |
| `country_not_allowed` | 100 | country ∉ app.allowed_countries |
| `country_blocked` | 100 | countries_block.txt |
| `city_blocked` | 15 | cities_block.txt (JS metrics only) |
| `device_velocity` | 100 | dfv counter > 30/h |
| `google_device_combo` | 100 | Pixel/Nexus + любой второй признак |

### 9.4. PI (pi bucket)

| Code | Fired by |
| --- | --- |
| `pi_missing` | strict + no token |
| `pi_init_failed` | verdict не декодируется |
| `pi_package_mismatch` | Cross-app PI replay |
| `pi_stale_or_future_token` | age < -5s || > 120s |
| `pi_timestamp_invalid` | Не парсится |
| `pi_nonce_replay` | SETNX pi_nonce_seen fail |
| `pi_unlicensed` | UNLICENSED |
| `pi_capturing` | KNOWN_CAPTURING |
| `pi_controlling` | KNOWN_CONTROLLING |
| `pi_unevaluated_combo` | UNEVALUATED×2 on first_init |
| `pi_not_device_integrity` | strict без MEETS_DEVICE |
| `pi_app_not_recognized` | strict без PLAY_RECOGNIZED |
| `pi_virtual` | Только VIRTUAL_INTEGRITY |
| `pi_empty_soft` / `pi_empty_device` | Пустой deviceRecognition |
| `pi_basic_failed` / `pi_basic_failed_soft` | Не MEETS_BASIC |
| `pi_app_unevaluated` | app_recognition = UNEVALUATED (lenient) |

### 9.5. Velocity / extras

| Code | Fired by |
| --- | --- |
| `velocity_block` | Любой из velocity_instance / velocity_subnet / velocity_ip |
| `soft_pi_extra` | asn_rotation / soft_ua_emulator / soft_ua_google_device |
| `cloak_consumed` | 2-й /init для того же instance за 24h (opt-in) |

### 9.6. Integrity endpoint

| Code | Fired by |
| --- | --- |
| `integrity_invalid` | Nonce unknown/expired, nonce-IP mismatch, nonce mismatch, verify failed |
| `integrity_stale` | Token > 120s |
| `cert_mismatch` | certificate_sha256 не совпадает с app.cert_sha256 (APK переподписан) |
| `app_tampered` | app_recognition = UNRECOGNIZED / UNEVALUATED |
| `device_compromised` | **DISABLED 2026-07-15** (пустой verdict / VIRTUAL / no BASIC) |

### 9.7. JS metrics (`/api/collect` → `score_js_metrics`)

Soft threshold `JS_SENSOR_THRESHOLD = 50`. Verdict white if `soft_score >= 50` **или** любой hard-ban.

Hard: `js_ip_range_block`, `js_webgl_gpu`, `js_country_block`, `js_city_block`, `js_isp_block`, `js_ipinfo_vpn/proxy/hosting`.

Soft: `js_static_device` (акселерометр deviation < 0.08 m/s²), `js_mouse_no_touch`, `js_fake_battery` (level=1.0 && chargingTime=0), `js_timezone_mismatch`, `js_bot_speed` (>10 actions/sec), `js_no_touch_support`, `js_lang_country_mismatch`, `js_multi_language` (≥3 langs), `js_exotic_lang_from_moderator_country`, `js_ipinfo_res_proxy_soft`.

Верхний threshold verdict: `behavioral_score`.

---

## 10. Настройки — где что менять

| Что | Файл | Ключ |
| --- | --- | --- |
| Score threshold | панель `/dashboard/config` или `PUT /api/config` | `scoreThreshold` (default 70) |
| Веса скоринга | тот же | `weights.{vpnProxyTor, suspiciousCity, englishWebView, suspiciousHosting, mouseWithoutTouch, timezoneMismatch}` |
| Timezone drift допуск | тот же | `timezoneDriftHours` (default 2) |
| Debug whitelist | панель `/dashboard/debug` или `PUT /api/debug-allow` | `{ips: [...], instances: [...]}` |
| Blocklists (страны/города/девайсы/GPU/ISP/UA/CIDR/Tor) | панель `/dashboard/lists` или `PUT /api/lists/{name}` | items[] |
| ASN blocklists (Google / VPN) | ручное редактирование `config/*_asn_blocklist.json` + hot-reload через SIGHUP или рестарт |
| Mobile ASN whitelist | ручное `config/mobile_asn_whitelist.json` |
| Per-app флаги (require_integrity, block_*, soft_pi_countries, ...) | панель `/dashboard/apps/{package}` или `PUT /api/apps/{id}` |
| Panic mode | панель кнопка или `PUT /api/apps/{id}/panic` |
