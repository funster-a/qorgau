// store.go — PostgreSQL: подключение, bootstrap схемы (для Railway без initdb),
// запись сигнала (pii + analytics), TTL-чистка PII.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

// openDB подключается к Postgres и применяет схему при необходимости.
// БД опциональна: при ошибке API продолжает работать без записи.
func openDB() {
	if dbURL == "" {
		log.Println("DATABASE_URL пуст — работаю без записи в БД")
		return
	}
	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("db open error: %v (продолжаю без БД)", err)
		db = nil
		return
	}
	if err = db.Ping(); err != nil {
		log.Printf("db ping error: %v (продолжаю без БД)", err)
		db = nil
		return
	}
	log.Println("db connected")
	if err := bootstrapSchema(); err != nil {
		log.Printf("bootstrap схемы: %v", err)
	}
}

// bootstrapSchema применяет db/schema.sql, если базовой таблицы нет.
// Нужен для Railway: там нет docker-entrypoint-initdb. Схема идемпотентна.
func bootstrapSchema() error {
	var reg sql.NullString
	if err := db.QueryRow(`SELECT to_regclass('analytics.scheme')::text`).Scan(&reg); err != nil {
		return err
	}
	if reg.Valid && reg.String != "" {
		// Схема на месте — добиваем только новые объекты (идемпотентные ALTER/CREATE).
		stmts := []string{
			`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
			`ALTER TABLE analytics.signal ADD COLUMN IF NOT EXISTS channel TEXT NOT NULL DEFAULT 'web'`,
			`ALTER TABLE analytics.campaign ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ`,
			`CREATE TABLE IF NOT EXISTS pii.subscriber (chat_id BIGINT PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		}
		for _, s := range stmts {
			if _, err := db.Exec(s); err != nil {
				return fmt.Errorf("миграция %q: %w", s[:30], err)
			}
		}
		log.Println("схема БД на месте (миграции применены)")
		return nil
	}
	path := findSchemaPath()
	if path == "" {
		return fmt.Errorf("db/schema.sql не найден (задайте SCHEMA_PATH)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := db.Exec(string(b)); err != nil {
		return fmt.Errorf("применение схемы из %s: %w", path, err)
	}
	log.Printf("схема БД применена из %s (bootstrap)", path)
	return nil
}

func findSchemaPath() string {
	paths := []string{}
	if p := os.Getenv("SCHEMA_PATH"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, filepath.Join("db", "schema.sql"), filepath.Join("..", "db", "schema.sql"))
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// store пишет сырьё в pii (шифрованно, с TTL) и обезличенный сигнал в analytics.
func store(req AnalyzeRequest, res AnalyzeResponse) error {
	channel := orDefault(req.Channel, "web")
	if _, err := db.Exec(
		`INSERT INTO pii.raw_submission (raw_text, channel, expires_at)
		 VALUES (pgp_sym_encrypt($1, $2), $3, $4)`,
		req.Text, piiEncKey, channel, time.Now().Add(piiTTL),
	); err != nil {
		return err
	}
	flagsJSON, _ := json.Marshal(res.Flags)
	var signalID string
	if err := db.QueryRow(
		`INSERT INTO analytics.signal
		 (scheme_code, risk_score, risk_level, flags, impersonated_brand, region, lang, channel, degraded)
		 VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9) RETURNING id`,
		res.SchemeCode, res.RiskScore, res.RiskLevel, flagsJSON,
		res.ImpersonatedBrand, req.Region, orDefault(res.Lang, "ru"), channel, res.Degraded,
	).Scan(&signalID); err != nil {
		return err
	}
	for _, ioc := range res.IOCs {
		db.Exec(`INSERT INTO analytics.ioc (signal_id, type, value_hash) VALUES ($1,$2,$3)`,
			signalID, ioc.Type, ioc.ValueMasked)
	}
	return nil
}

// ttlCleaner удаляет просроченное сырьё из pii каждые 10 минут (BR-1).
func ttlCleaner() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		if res, err := db.Exec(`DELETE FROM pii.raw_submission WHERE expires_at < now()`); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("TTL: удалено %d записей из pii", n)
			}
		}
	}
}
