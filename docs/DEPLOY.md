# Деплой Qorǵau на Railway

Два сервиса из одного репозитория (api + bot) плюс управляемый Postgres.
API применяет схему БД сам при старте — отдельного шага миграции нет.

## Шаги (≈10 минут, всё в браузере)

### 1. Проект и база
1. railway.app → **New Project** → **Deploy from GitHub repo** → `funster-a/qorgau`.
   (Railway попросит доступ к GitHub — дай на этот репозиторий.)
2. В проект добавь Postgres: **Create → Database → Add PostgreSQL**.

### 2. Сервис api
Railway создаст один сервис из репозитория — это будет api.
- **Settings → Build**: убедись, что Builder = Dockerfile, и задай переменную
  `RAILWAY_DOCKERFILE_PATH=api/Dockerfile` (Variables).
- **Variables**:
  | Переменная | Значение |
  |---|---|
  | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (reference на сервис Postgres) |
  | `GROQ_API_KEY` | твой ключ gsk_... |
  | `GROQ_MODEL` | `llama-3.3-70b-versatile` |
  | `ADMIN_TOKEN` | придумай строку — закроет /admin/* от чужих |
  | `BOT_API_KEY` | придумай строку — общий секрет api↔bot |
  | `PII_ENC_KEY` | придумай длинную строку — ключ шифрования зоны PII |
- **Settings → Networking → Generate Domain** → получишь `https://<имя>.up.railway.app`.
- **Settings → Health check**: path `/healthz`.

Если Postgres ругнётся на SSL: добавь к DATABASE_URL `?sslmode=require`
(публичный прокси) или `?sslmode=disable` (internal-адрес `postgres.railway.internal`).

### 3. Сервис bot
- **Create → GitHub Repo** → тот же `funster-a/qorgau` (второй сервис).
- Variables: `RAILWAY_DOCKERFILE_PATH=bot/Dockerfile`,
  `TELEGRAM_BOT_TOKEN`, `API_URL=https://<домен-api-из-шага-2>`, `BOT_API_KEY` (тот же).
- Домен боту НЕ нужен (long polling, сам ходит в Telegram).

### 4. Проверка
```
curl https://<домен>/healthz          → {"status":"ok","db":true,...}
открыть https://<домен>/              → чекер
открыть https://<домен>/demo.html     → пульт (ввести ADMIN_TOKEN)
в Telegram боту: /start, прислать скам-СМС
```

## Что где живёт

| Окружение | Postgres | Grafana | Веб | Бот |
|---|---|---|---|---|
| Локально | docker :55432 | docker :3000 | :8080 (go run) | go run |
| Railway | managed | — (локально/скринкаст) | api-домен | worker |

Grafana на Railway не тянем: для демо радар показываем с локальной Grafana
(данные можно направить на Railway-Postgres, задав ей тот же DATABASE_URL)
или бэкап-скринкастом.

## Автодеплой
Каждый push в master пересобирает оба сервиса. Откат — в Railway UI
(Deployments → Redeploy предыдущий).
