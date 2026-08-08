# Контракт API Qorǵau (v2 — зафиксирован для параллельной разработки)

> Этот файл — источник истины для фронта и бэка. Менять поля — только через
> правку этого файла ПЕРЕД правкой кода. Все ответы — JSON, UTF-8.
> База: тот же origin, что и веб (API отдаёт web/ статикой). Локально: `http://localhost:8080`.

## Публичные эндпоинты

### POST /analyze
Запрос:
```json
{ "text": "строка 1..4000 симв.", "channel": "web|tg", "region": "Almaty | '' " }
```
Ответ 200:
```json
{
  "risk_score": 0,
  "risk_level": "low|medium|high",
  "scheme_code": "bank_security|card_block|prize_payout|relative_help|phishing_link|investment|gov_payout|remote_install|other|not_scam",
  "scheme_title": "строка",
  "impersonated_brand": "строка или \"\"",
  "flags": ["строка"],
  "explanation": "строка",
  "recommended_actions": ["строка"],
  "iocs": [ { "type": "phone|domain|iban", "value_masked": "строка" } ],
  "lang": "ru|kz",
  "degraded": false
}
```
Ошибки: `400` пустой/длинный текст; `429` rate limit (JSON `{"error":"rate_limited","retry_after_sec":N}`).

### GET /stats/summary
```json
{
  "total": 0,
  "last_24h": 0,
  "high_share_24h": 0,
  "degraded_share_24h": 0,
  "campaigns_active": 0,
  "top": [ { "scheme": "code", "title": "строка", "count": 0 } ],
  "regions": [ { "region": "Almaty", "count": 0 } ]
}
```
Доли — проценты 0..100, целые.

### GET /stats/timeseries?hours=24
`[ { "t": "RFC3339", "scheme": "code", "count": 0 } ]`

### GET /campaigns/active
`[ { "id": "uuid", "scheme": "code", "title": "строка", "started_at": "RFC3339", "peak": 0, "status": "active" } ]`

### GET /threat-feed
Обезличенный фид индикаторов для банков/операторов (Vision-фича, продаётся со сцены):
```json
{
  "generated_at": "RFC3339",
  "indicators": [
    { "type": "domain|phone|iban", "value": "маскированное значение",
      "count": 0, "first_seen": "RFC3339", "last_seen": "RFC3339",
      "schemes": ["bank_security"] }
  ]
}
```

### GET /privacy/proof
Живое доказательство разделения зон (показываем жюри):
```json
{
  "pii":       { "rows": 0, "ttl_hours": 24, "encrypted": true,
                 "sample": { "created_at": "RFC3339", "expires_at": "RFC3339",
                             "raw_text_encrypted_preview": "\\xc30d0409..." } },
  "analytics": { "rows": 0, "sample_signal": { "scheme_code": "...", "risk_score": 0,
                 "flags": [], "region": "...", "created_at": "RFC3339" } }
}
```
`sample` может быть `null`, если зона пуста.

### GET /healthz
`{"status":"ok","db":true,"llm":"groq|degraded"}`

## Служебные эндпоинты для бота
Защита: если задан env `BOT_API_KEY`, требуется заголовок `X-Bot-Key`. Иначе открыто (MVP).

- `POST /bot/subscribe`   `{ "chat_id": 123 }` → `{"ok":true}`
- `POST /bot/unsubscribe` `{ "chat_id": 123 }` → `{"ok":true}`
- `GET  /bot/subscribers` → `{ "chat_ids": [123, 456] }`

chat_id хранится в зоне `pii` (это идентификатор), не в `analytics`.

## Админ-эндпоинты (пульт демо)
Защита: если задан env `ADMIN_TOKEN`, требуется заголовок `X-Admin-Token`. Иначе открыто (MVP).

- `POST /admin/seed`  `{ "history_hours": 24, "per_hour": 6 }` — засеять правдоподобную историю
  (разные схемы/регионы/риски + not_scam + индикаторы). Ответ `{"ok":true,"inserted":N}`.
- `POST /admin/spike` `{ "scheme": "bank_security", "count": 25 }` — впрыснуть всплеск за последние
  минуты (с одинаковым доменом-индикатором) → детектор поднимет кампанию на ближайшем тике.
- `POST /admin/clear` `{}` — очистить analytics (signal/ioc/campaign) для чистого прогона демо.
- `GET  /admin/flags` / `POST /admin/flags`:
```json
{ "force_degraded": false, "broadcast_enabled": true, "rate_limit_enabled": true }
```
  POST принимает частичный объект — меняет только переданные флаги.
- `GET /admin/recent?limit=20` — последние сигналы:
  `[ { "created_at": "RFC3339", "scheme": "code", "title":"", "risk_score": 0, "risk_level": "", "region": "", "channel": "", "degraded": false } ]`

## Статика
- `/` — чекер (web/index.html)
- `/demo.html` — пульт управления демо
- Всё из `web/` отдаётся как есть.

## Договорённости
- Пустые строки вместо null в строковых полях ответа /analyze.
- Все времена — UTC RFC3339.
- CORS: `*` (WebView-apk и file:// на подстраховке).
- Фронт не хардкодит хост: same-origin, для file:// — localhost:8080.
