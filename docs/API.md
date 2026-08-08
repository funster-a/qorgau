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

## Qorǵau Shield (DNS-защита)

### GET|POST /dns-query
DoH-резолвер по RFC 8484 (wireformat; GET с `?dns=<base64url>` и POST
`application/dns-message`). Если запрошенный домен в блок-листе — ответ NXDOMAIN;
иначе запрос проксируется в вышестоящий DoH (Cloudflare). Клиентские IP НЕ
логируются — только агрегированные счётчики по доменам.

### GET /shield/blocklist
`{ "updated_at": "RFC3339", "count": 0, "domains": ["kaspi-secure.xyz"] }`
Источники: analytics.ioc (домены из жалоб) + сид-файл db/blocklist_seed.txt.

### GET /shield/stats
`{ "blocked_today": 0, "blocklist_count": 0, "top_blocked": [ { "domain": "...", "count": 0 } ] }`

### GET /shield/apple.mobileconfig
Генерирует профиль iOS (payload DNSSettings, DNSProtocol=HTTPS, ServerURL —
наш /dns-query на текущем домене). Content-Type: application/x-apple-aspen-config.

## Проверка пароля по утечкам

### GET /leaks/password/{prefix5}
Прокси к HIBP range API (k-anonymity). `{prefix5}` — первые 5 hex-символов
SHA-1 пароля (считается В БРАУЗЕРЕ, сам пароль на сервер не уходит).
Ответ — текст HIBP как есть: строки `SUFFIX:COUNT`. Кэшируется в памяти 1ч.
404 от HIBP → пустое тело 200.

## Киллер-анализаторы (ссылка / скриншот / голос)

Все три возвращают ту же форму, что `/analyze` (risk_score, risk_level,
scheme_code, scheme_title, flags, explanation, recommended_actions, iocs,
lang, degraded), плюс свои доп. поля. Пишут обезличенный сигнал в analytics
так же, как /analyze (channel: "link" | "image" | "voice").

### POST /analyze/link
Разбор ссылки БЕЗ перехода на неё (пассивно, без headless-браузера).
Запрос: `{ "url": "http://kaspi-bonus.xyz/win", "region": "" }`
Доп. поля ответа:
```json
{
  "domain": "kaspi-bonus.xyz",
  "domain_age_days": 4,            // из whois creation date; -1 если неизвестно
  "registrar": "строка или ''",
  "ssl": { "present": true, "self_signed": false, "issuer": "...",
           "age_days": 2, "valid": true },   // из TLS-хендшейка на :443
  "brand_similarity": [ { "brand": "kaspi.kz", "distance": 2 } ], // Левенштейн
  "in_blocklist": false           // домен уже в блок-листе Shield
}
```
Сигналы риска: возраст домена < 30 дней (+сильно), самоподписанный/битый серт,
похожесть на бренд КЗ (distance ≤ 3), уже в блок-листе, рискованная TLD-зона.
Таймауты: whois 5с, TLS 4с. Всё опционально — при неудаче поле пустое/-1,
вердикт всё равно выдаётся (эвристика по тому, что удалось узнать).

### POST /analyze/image
Скриншот чата/сайта → распознавание (Groq vision). Запрос:
`{ "image_base64": "data:image/png;base64,...", "region": "" }` (≤5 МБ).
Доп. поля: `extracted_text` (что увидела модель), `ui_spoofing` (bool —
похоже на подделку интерфейса банка/госоргана). При недоступности vision —
`degraded: true` и попытка эвристики по извлечённому тексту, если он есть.

### POST /analyze/audio
Голосовое/запись звонка → Whisper-транскрипция → анализ текста. Запрос:
multipart/form-data, поле `audio` (ogg/mp3/wav/m4a, ≤10 МБ), опц. `region`.
Доп. поля: `transcript` (расшифровка), `lang`. «Интонация давления» —
по словам-маркерам в тексте (срочно/немедленно/только сейчас), не по звуку
(Whisper даёт текст). Бот принимает голосовые Telegram напрямую.

## Гео-радар

### GET /stats/regions
`[ { "region": "Almaty", "total": 0, "high": 0, "share_high": 0 } ]`
Для тепловой карты Казахстана. share_high — % высокого риска 0..100.

## Этап «ДО»: проверка номера и карты, тренажёр

### POST /check/phone
`{ "phone": "+7 701 234 56 78" }` → 
```json
{ "phone_masked": "+7 7** *** ** 78", "reports": 12, "risk_level": "high|medium|low",
  "first_seen": "RFC3339|null", "last_seen": "RFC3339|null",
  "schemes": [ { "scheme": "bank_security", "title": "...", "count": 5 } ],
  "verdict": "текст для человека", "recommended_actions": ["..."] }
```
Считает по analytics.ioc (type='phone') — сколько раз этот номер встречался
в жалобах. reports=0 → risk_level low + честный текст «в базе не встречался».

### POST /check/card
`{ "card": "4400 4302 1234 5678" }` →
```json
{ "card_masked": "4400 **** **** 5678", "luhn_valid": true,
  "bin": { "bank": "Kaspi Bank", "country": "KZ", "brand": "VISA", "known": true },
  "reports": 0, "risk_level": "low|medium|high",
  "verdict": "...", "recommended_actions": ["..."] }
```
Luhn считаем сами; BIN — по локальной таблице db/bins_kz.json (~30 БИНов банков КЗ,
известные + маркер known:false для неизвестных). Полный номер НЕ хранится и НЕ
логируется, в analytics.ioc пишется только маска (type='card').

### POST /trainer/start
`{ "scenario": "bank_security|relative_help|prize_payout|investment|job_offer|random", "lang": "ru|kz" }`
→ `{ "session_id": "uuid", "scenario": "bank_security", "title": "Звонок из «службы безопасности»",
     "intro": "описание ситуации для пользователя", "opening": "первая реплика мошенника" }`

### POST /trainer/reply
`{ "session_id": "uuid", "message": "ответ пользователя" }` →
```json
{ "reply": "следующая реплика мошенника или ''",
  "finished": false,
  "turn": 3,
  "mistakes": [ { "quote": "меня зовут Айгуль", "why": "назвали имя", "severity": "medium" } ],
  "score": 0,                 // 0..100, заполняется при finished
  "debrief": "разбор: что сделал верно, где повёлся, как надо было",
  "red_flags_shown": ["давление срочностью", "запрос кода из СМС"] }
```
LLM играет мошенника (безопасно: сценарий-игра, ВСЕГДА заканчивается разбором;
максимум 8 ходов, потом finished=true). Состояние сессий — в памяти, TTL 1ч.
При недоступности LLM — сценарий из заранее заготовленных реплик (degraded).

## Этап «ВО ВРЕМЯ»: живой помощник и защита близкого

### POST /live/hint
Живой суфлёр во время звонка: пользователь вставляет фразы звонящего.
`{ "session_id": "uuid|''", "phrase": "назовите код из СМС", "history": ["..."] }` →
```json
{ "level": "danger|warn|ok", "title": "Просят код из СМС",
  "hint": "Немедленно кладите трубку. Код из СМС — это подпись под операцией.",
  "manipulations": ["запрос OTP", "давление срочностью"],
  "cumulative_risk": 85 }
```
Быстрый путь: сначала мгновенная эвристика по маркерам (без сети), затем, если
LLM доступен — уточнение. Отвечать ≤1.5с, это «реальное время».

### POST /guard/link  — привязать близкого
`{ "guardian_chat_id": 123, "code": "" }` → `{ "code": "QG-4821", "expires_in_sec": 900 }`
Опекун получает код; подопечный вводит его в боте (`/protect QG-4821`) →
`POST /guard/confirm { "code": "QG-4821", "ward_chat_id": 456 }` → `{ "ok": true }`.
Хранение — зона `pii` (это идентификаторы): таблица `pii.guard_link`.

### GET /guard/links?chat_id=123
`{ "wards": [ { "ward_chat_id": 456, "linked_at": "RFC3339" } ],
   "guardians": [ { "guardian_chat_id": 123, "linked_at": "RFC3339" } ] }`

### Алерт опекуну
Внутренняя логика: если у пользователя есть опекун и его проверка дала
`risk_level: high` — API кладёт запись в `pii.guard_alert`; бот поллит
`GET /guard/alerts` (X-Bot-Key) → `[ { "id":"uuid", "guardian_chat_id":123,
"scheme_title":"...", "risk_score":98, "created_at":"RFC3339" } ]` и рассылает,
затем `POST /guard/alerts/ack {"ids":["uuid"]}`. Текст сообщения НЕ передаётся —
опекун видит только факт и тип угрозы (приватность подопечного).

## Этап «ПОСЛЕ»: юридическая первая помощь

### POST /help/chat
`{ "session_id": "uuid|''", "message": "я перевёл 200000 тенге", "situation": {
   "lost_money": true, "gave_otp": false, "gave_card": true, "installed_app": false } }` →
```json
{ "session_id": "uuid", "reply": "ответ ИИ-юриста простым языком",
  "steps": [ { "order": 1, "title": "Заблокируйте карту", "detail": "...",
               "urgency": "now|today|week", "done_hint": "..." } ],
  "contacts": [ { "name": "Kaspi Bank", "phone": "+7 727 000 00 00", "kind": "bank" } ],
  "degraded": false }
```
Контакты — из локального db/contacts_kz.json (банки КЗ, полиция 102, 1414,
финпол/АФМ). Никаких выдуманных телефонов: только те, что в файле.

### GET /help/places?lat=43.23&lon=76.94&kind=police|bank|lawyer
`[ { "name": "...", "kind": "police", "address": "...", "lat": 0, "lon": 0,
     "distance_km": 1.2, "phone": "" } ]`
Данные — из локального db/places_kz.json (заготовленный набор по крупным
городам: отделения полиции, ЦОНы, юрпомощь). Без внешних API.

## Статика
- `/` — чекер (web/index.html)
- `/demo.html` — пульт управления демо
- Всё из `web/` отдаётся как есть.

## Договорённости
- Пустые строки вместо null в строковых полях ответа /analyze.
- Все времена — UTC RFC3339.
- CORS: `*` (WebView-apk и file:// на подстраховке).
- Фронт не хардкодит хост: same-origin, для file:// — localhost:8080.
