-- Демо-сид для дашборда и детекции аномалии.
-- Наполняет analytics.signal историей за сутки + «всплеск» по схеме bank_security за последний час.
-- Запуск: psql "$DATABASE_URL" -f db/seed_demo.sql
--
-- Внимание: сид пишет ТОЛЬКО в analytics — обезличенные признаки.
-- В pii.raw_submission он не кладёт ничего, потому что сырьё не должно жить в демо-данных.

-- Фоновая история (равномерно за 24 часа, разные схемы и регионы)
INSERT INTO analytics.signal (scheme_code, risk_score, risk_level, flags, region, lang, created_at)
SELECT
  s.code,
  s.score,
  -- Уровень выводим из балла, иначе панель «доля высокого риска» покажет ерунду.
  CASE WHEN s.score >= 60 THEN 'high' WHEN s.score >= 30 THEN 'medium' ELSE 'low' END,
  '[]'::jsonb,
  (ARRAY['Almaty','Astana','Shymkent','Karaganda','Aktobe'])[1 + floor(random() * 5)::int],
  CASE WHEN random() < 0.2 THEN 'kz' ELSE 'ru' END,
  now() - (random() * interval '24 hour')
FROM (
  SELECT
    (ARRAY['prize_payout','phishing_link','investment','card_block','relative_help','gov_payout','remote_install'])
      [1 + floor(random() * 7)::int] AS code,
    (20 + floor(random() * 75))::int AS score
  FROM generate_series(1, 120)
) s;

-- Немного «не мошенничества» — чтобы на защите было видно, что сервис не кричит на всё подряд.
INSERT INTO analytics.signal (scheme_code, risk_score, risk_level, flags, region, lang, created_at)
SELECT 'not_scam', floor(random() * 15)::int, 'low', '[]'::jsonb,
       (ARRAY['Almaty','Astana','Shymkent'])[1 + floor(random() * 3)::int], 'ru',
       now() - (random() * interval '24 hour')
FROM generate_series(1, 30);

-- ВСПЛЕСК: bank_security за последний час (это поднимет кампанию)
INSERT INTO analytics.signal (scheme_code, risk_score, risk_level, flags, impersonated_brand, region, lang, created_at)
SELECT
  'bank_security', (90 + floor(random() * 10))::int, 'high',
  '["запрос кода из СМС","давление срочностью","маскировка под банк"]'::jsonb,
  'Kaspi',
  (ARRAY['Almaty','Astana','Shymkent'])[1 + floor(random() * 3)::int], 'ru',
  now() - (random() * interval '55 minute')
FROM generate_series(1, 25);

-- Индикаторы для всплеска: один и тот же домен в разных обращениях — почерк одной кампании.
INSERT INTO analytics.ioc (signal_id, type, value_hash)
SELECT id, 'domain', 'kaspi-secure.xyz'
FROM analytics.signal
WHERE scheme_code = 'bank_security' AND created_at > now() - interval '1 hour';

INSERT INTO analytics.ioc (signal_id, type, value_hash)
SELECT id, 'phone', '+7 7** *** ** 78'
FROM analytics.signal
WHERE scheme_code = 'bank_security' AND created_at > now() - interval '1 hour'
  AND random() < 0.6;

-- Зафиксировать кампанию (если детектор ещё не сработал)
INSERT INTO analytics.campaign (scheme_code, peak_value)
SELECT 'bank_security', 25
WHERE NOT EXISTS (SELECT 1 FROM analytics.campaign WHERE scheme_code = 'bank_security' AND status = 'active');
