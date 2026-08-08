-- Qorǵau — схема БД. Две зоны: pii (сырьё) и analytics (обезличенное).
-- Разделение зон — ключевая архитектурная фишка (GDPR/152-ФЗ) на защите.

CREATE SCHEMA IF NOT EXISTS pii;
CREATE SCHEMA IF NOT EXISTS analytics;

-- === ЗОНА PII: только сырьё, короткий TTL, сюда не ходит аналитика ===
CREATE TABLE IF NOT EXISTS pii.raw_submission (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_text    TEXT NOT NULL,              -- в проде: шифровать (pgcrypto). В MVP допустимо plain + TTL.
    channel     TEXT NOT NULL,              -- tg | web
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL        -- created_at + PII_TTL
);
-- Очистка по TTL (запускать по крону / фоновым тикером в API):
-- DELETE FROM pii.raw_submission WHERE expires_at < now();

-- === ЗОНА ANALYTICS: обезличенные признаки, живёт долго ===
CREATE TABLE IF NOT EXISTS analytics.scheme (
    code      TEXT PRIMARY KEY,
    title_ru  TEXT NOT NULL
);

INSERT INTO analytics.scheme (code, title_ru) VALUES
    ('bank_security',  'Фейковая служба безопасности банка'),
    ('card_block',     'Блокировка карты / счёта'),
    ('prize_payout',   'Выигрыш / компенсация / выплата'),
    ('relative_help',  'Родственник в беде'),
    ('phishing_link',  'Фишинговая ссылка'),
    ('investment',     'Инвестиции / лёгкий заработок'),
    ('gov_payout',     'Госвыплата / пособие'),
    ('remote_install', 'Просьба установить приложение удалённого доступа'),
    ('other',          'Другое / не определено'),
    ('not_scam',       'Похоже, не мошенничество')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS analytics.signal (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scheme_code         TEXT NOT NULL REFERENCES analytics.scheme(code),
    risk_score          INT  NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level          TEXT NOT NULL,             -- low | medium | high
    flags               JSONB NOT NULL DEFAULT '[]',
    impersonated_brand  TEXT,
    region              TEXT,
    lang                TEXT NOT NULL DEFAULT 'ru',
    degraded            BOOLEAN NOT NULL DEFAULT false,  -- вердикт из фолбэка
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_signal_scheme_time ON analytics.signal (scheme_code, created_at);

CREATE TABLE IF NOT EXISTS analytics.ioc (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id   UUID NOT NULL REFERENCES analytics.signal(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,             -- domain | phone | iban | url
    value_hash  TEXT NOT NULL             -- хэш/маска, НЕ сырьё
);

CREATE TABLE IF NOT EXISTS analytics.campaign (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scheme_code  TEXT NOT NULL REFERENCES analytics.scheme(code),
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    peak_value   INT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'  -- active | closed
);

-- === Витрины для Grafana ===
-- Динамика по схемам (по часам):
CREATE OR REPLACE VIEW analytics.v_signals_hourly AS
SELECT date_trunc('hour', created_at) AS bucket,
       scheme_code,
       count(*) AS cnt
FROM analytics.signal
GROUP BY 1, 2;

-- Топ схем:
CREATE OR REPLACE VIEW analytics.v_top_schemes AS
SELECT s.scheme_code, sc.title_ru, count(*) AS cnt
FROM analytics.signal s
JOIN analytics.scheme sc ON sc.code = s.scheme_code
GROUP BY 1, 2
ORDER BY cnt DESC;
