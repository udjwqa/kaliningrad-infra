# Scoring Engine — Ядро фильтрации APK-трафика

Бэкенд на FastAPI, который принимает запросы, прогоняет их через скоринговую систему и решает — пустить юзера на реальный продукт (серая ссылка) или отправить на заглушку (белая ссылка).

Работает в связке с [админ-панелью](https://github.com/notsoobvioussss/amigos_koko) — оттуда можно менять конфиги, пороги, веса и стоп-листы без перезагрузки сервера.

---

## Как это работает

Запрос приходит на `GET /` → движок вытаскивает заголовки → прогоняет через 3 слоя проверок → начисляет баллы → если набрал выше порога — это бот/модератор (белый трафик), если ниже — реальный юзер (серый трафик).

### 3 слоя проверок:

**Слой 1 — Статические заголовки:**
- Нет `X-Client-Secret` → +100 (автобан, не наш клиент)
- User-Agent содержит бот-подстроку (Googlebot, bingbot) → +100
- Язык `en` в Accept-Language → +10 (вес настраивается)
- Модель Pixel/Google → +40
- Кодовое имя эмулятора (goldfish, ranchu) → +100
- GPU эмулятора (SwiftShader, VirtualBox) → +100

**Слой 2 — Внешние API:**
- **IPinfo** — определяет VPN, proxy, tor, hosting по IP. Также даёт реальную страну, город и ISP
- **IPQS** (опционально) — fraud score, бот-детект, VPN/proxy

**Слой 3 — Гео-проверки:**
- Страна в чёрном списке → +100
- Город модерации (Mountain View, Dublin) → +15
- ISP-хостинг (Google LLC, Amazon) → +20

### Вердикт:
- `score >= threshold` → **white** (бот/модератор) → заглушка/403/404
- `score < threshold` → **grey** (реальный юзер) → целевой продукт

Все запросы пишутся в **PostgreSQL** — потом их можно смотреть через audit log в админке.

---

## Стек

- **Python 3.9+** + **FastAPI** + **uvicorn**
- **PostgreSQL** + **SQLAlchemy async** + **asyncpg**
- **httpx** — async клиент для IPinfo/IPQS
- **Pydantic v2** — валидация моделей

---

## Структура проекта

```
server/
├── main.py                 # Точка входа FastAPI
├── config.py               # Конфигурация (config.json)
├── scoring_engine.py       # Ядро скоринга (3 слоя проверок)
├── request_logger.py       # Логгер (PostgreSQL + in-memory)
├── lists_manager.py        # Hot-reload стоп-листов (mtime каждые 5 сек)
├── database.py             # SQLAlchemy async engine
├── db_models.py            # Модель RequestLog
├── models.py               # Pydantic модели
├── api/
│   ├── gateway.py          # GET / (главный вход) + /score-debug
│   ├── config_routes.py    # GET/PUT /api/config + /api/offers
│   ├── lists_routes.py     # GET/PUT /api/lists
│   ├── audit_routes.py     # GET /api/audit/logs (фильтры + пагинация)
│   ├── dashboard_routes.py # GET /api/dashboard/metrics + /feed + /rejections
│   └── health.py           # GET /api/health
├── external/
│   ├── ipinfo_client.py    # Async IPinfo клиент + TTL кеш
│   └── ipqs_client.py      # Async IPQS клиент (опционально)
├── lists/                  # 7 текстовых стоп-листов
│   ├── countries_block.txt
│   ├── cities_block.txt
│   ├── user_agents_block.txt
│   ├── device_models_block.txt
│   ├── codenames_block.txt
│   ├── isp_block.txt
│   └── gpu_block.txt
├── .env                    # Переменные окружения
├── requirements.txt
└── README.md
```

---

## API Endpoints

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/` | Главный вход — скоринг + редирект |
| GET | `/score-debug` | Debug — показывает скоринг без редиректа |
| GET | `/api/health` | Статус сервера |
| GET/PUT | `/api/config` | Конфигурация движка (пороги, веса) |
| GET/PUT | `/api/offers` | Настройки ссылок (safe/target URL) |
| GET | `/api/lists` | Все стоп-листы |
| PUT | `/api/lists/{id}` | Обновить стоп-лист |
| GET | `/api/audit/logs` | Журнал аудита (фильтры + пагинация) |
| GET | `/api/dashboard/metrics` | Метрики за 24ч |
| GET | `/api/dashboard/feed` | Последние запросы (in-memory) |
| GET | `/api/dashboard/rejections` | Статистика причин отказов |

---

## Быстрый старт (dev)

```bash
cd server

# Создай .env
cp .env.example .env
# Впиши свои ключи

# Установи зависимости
pip install -r requirements.txt

# Подними PostgreSQL и создай БД
psql -c "CREATE USER panel WITH PASSWORD 'panel';"
psql -c "CREATE DATABASE panel OWNER panel;"

# Запуск
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Проверь
curl http://localhost:8000/api/health
```

---

## Деплой на Ubuntu 24.04

```bash
# 1. Python + PostgreSQL
sudo apt update && sudo apt install -y python3 python3-pip python3-venv postgresql

# 2. Настрой БД
sudo -u postgres psql -c "CREATE USER panel WITH PASSWORD 'panel';"
sudo -u postgres psql -c "CREATE DATABASE panel OWNER panel;"

# 3. Склонируй и настрой
cd /opt
git clone <repo-url> scoring-engine
cd scoring-engine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Создай .env
cp .env.example .env
nano .env

# 5. Запусти
uvicorn main:app --host 127.0.0.1 --port 8000

# Или через systemd (рекомендуется):
# Создай /etc/systemd/system/scoring-engine.service
```

### Systemd сервис:

```ini
[Unit]
Description=Scoring Engine FastAPI
After=postgresql.service

[Service]
User=root
WorkingDirectory=/opt/scoring-engine
Environment="PATH=/opt/scoring-engine/venv/bin"
ExecStart=/opt/scoring-engine/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable scoring-engine
sudo systemctl start scoring-engine
```

---

## Переменные окружения (.env)

```env
# IPinfo (обязательно для гео-проверок)
IPINFO_TOKEN=твой_токен
IPINFO_CACHE_TTL_SECONDS=86400
IPINFO_REQUEST_TIMEOUT_SECONDS=5
IPINFO_FAIL_OPEN=true

# IPQS (опционально, если пусто — пропускается)
IPQS_API_KEY=
IPQS_REQUEST_TIMEOUT_SECONDS=5

# PostgreSQL
DATABASE_URL=postgresql+asyncpg://panel:panel@localhost:5432/panel
```

---

## Тестирование

```bash
# Бот — должен получить white (заглушка)
curl http://localhost:8000/score-debug -H "User-Agent: Googlebot"

# Чистый юзер — grey (продукт)
curl http://localhost:8000/score-debug \
  -H "User-Agent: Mozilla/5.0 Android" \
  -H "X-Client-Secret: mykey" \
  -H "Accept-Language: ru-RU"

# Реальный IP через IPinfo
curl http://localhost:8000/score-debug \
  -H "X-Client-Secret: key" \
  -H "X-Forwarded-For: 8.8.8.8"
```

---

## Связь с админ-панелью

Фронт подключается к бэкенду через `NEXT_PUBLIC_API_URL`. Когда в панели выключен mock toggle — данные идут с этого сервера. Конфиги, списки, аудит логи — всё реальное.
