# Архитектура Qorǵau

> Целевая картинка того, что строим на хакатоне. Зелёное — работает,
> жёлтое — в разработке этой ночью, синее — Vision (продаём со сцены как роадмап).

## Общая схема

```mermaid
flowchart LR
    subgraph CH["Каналы-сенсоры"]
      WEB["Веб-чекер<br/>+ пульт демо"]
      TG["Telegram-бот<br/>/subscribe → предупреждения"]
      APK["Android WebView-apk"]
      WA["WhatsApp"]:::vision
      CALL["Звонилка / call-screening"]:::vision
    end

    subgraph API["Backend API (Go, один бинарь)"]
      AN["POST /analyze<br/>rate-limit → Groq LLM<br/>→ эвристический фолбэк"]
      ST["GET /stats/*<br/>GET /campaigns/active"]
      TF["GET /threat-feed"]
      PP["GET /privacy/proof"]
      AD["POST /admin/*<br/>seed · spike · flags"]
      TICK["Фоновые тикеры:<br/>детектор аномалий (z-score)<br/>TTL-чистка PII"]
    end

    subgraph ENG["AI-ядро"]
      PROMPT["engine/prompt.md<br/>few-shot, живёт вне кода"]
      HEUR["Правила-фолбэк<br/>(работает без сети)"]
      EVAL["engine/testset.json<br/>замер точности (KPI-2)"]
    end

    subgraph DB["PostgreSQL — две зоны"]
      PII[("pii: сырьё<br/>pgcrypto, TTL 24ч<br/>+ подписчики бота")]
      ANZ[("analytics: обезличенное<br/>signal · ioc · campaign")]
    end

    subgraph OUT["Выходы"]
      GRAF["Grafana-радар<br/>8 панелей, provisioning"]
      BC["TG-broadcast<br/>при новой кампании"]
      BANKS["API для банков/операторов"]:::vision
      DNS["VPN/DNS блок-лист"]:::vision
    end

    WEB --> AN
    TG --> AN
    APK --> WEB
    AN --> PROMPT
    AN --> HEUR
    AN --> PII
    AN --> ANZ
    TICK --> ANZ
    ANZ --> GRAF
    TICK -->|"новая кампания"| BC
    TF --> BANKS
    ANZ --> TF

    classDef vision fill:#26324a,stroke:#4a5f85,color:#9db2d5;
```

## Поток одного обращения

```mermaid
sequenceDiagram
    autonumber
    actor U as Пользователь
    participant W as Веб / Бот
    participant A as API
    participant G as Groq LLM
    participant P as Зона PII
    participant Z as Зона analytics
    participant T as Тикер аномалий
    participant S as Подписчики TG

    U->>W: подозрительная СМС
    W->>A: POST /analyze
    A->>P: сырьё (pgp_sym_encrypt, TTL 24ч)
    A->>G: классификация (таймаут 5с, 1 ретрай)
    alt Groq недоступен / force_degraded
        A->>A: эвристический фолбэк (degraded=true)
    end
    A->>A: normalize() + маскирование индикаторов
    A->>Z: обезличенный сигнал + IoC
    A-->>W: вердикт ≤5с (KPI-1)
    loop каждые 60с
        T->>Z: z-score по каждой схеме
        alt всплеск (z≥3 или ≥3× среднего)
            T->>Z: campaign(active)
            T-->>S: broadcast «⚠ Новая волна»
        else спад
            T->>Z: campaign → closed
        end
    end
```

## Зоны данных (комплаенс — фишка на защите)

```mermaid
flowchart TB
    RAW["Сырой текст сообщения"] -->|"pgp_sym_encrypt<br/>+ expires_at = now()+24ч"| PII[("pii.raw_submission")]
    RAW -->|"классификация"| FEAT["Только признаки:<br/>схема · риск · флаги · регион"]
    RAW -->|"извлечение + маскирование<br/>+7 7** *** ** 12 · домен целиком"| IOC2["Индикаторы"]
    FEAT --> ANZ[("analytics.signal")]
    IOC2 --> ANIOC[("analytics.ioc")]
    PII -->|"TTL-чистка каждые 10 мин"| DEL["Удалено навсегда"]
    ANZ --> GRAF["Grafana / threat-feed"]
    style PII fill:#3a1f2b,stroke:#7a3b52
    style ANZ fill:#1d3a2f,stroke:#2f7a5b
```

## Разделение работы (люди + агенты)

| Зона | Файлы | Кто |
|------|-------|-----|
| Бэкенд + AI-ядро + бот + БД | `api/`, `bot/`, `engine/`, `db/` | агент-бэк |
| Фронт (чекер + пульт демо) | `web/` | агент-фронт |
| Контракт, интеграция, деплой, доки, git | `docs/`, Dockerfile'ы, коммиты | оркестратор |

Правило: агент не выходит за свои директории. Контракт — `docs/API.md`,
менять его код не может: сначала правка контракта, потом кода.

## Деплой (Railway)

```mermaid
flowchart LR
    GH["GitHub: funster-a/qorgau"] -->|"auto-deploy"| R1["Railway: api<br/>(api/Dockerfile,<br/>web+engine+db внутри)"]
    GH -->|"auto-deploy"| R2["Railway: bot<br/>(bot/Dockerfile)"]
    RPG[("Railway Postgres")] --- R1
    R2 -->|"API_URL"| R1
    U2["Жюри / QR-код"] --> R1
```

API применяет схему БД сам при старте (bootstrap из `db/schema.sql`),
поэтому на Railway не нужен initdb. Grafana для демо — локально
(docker compose), на сцене показываем localhost или скрин-запись.
