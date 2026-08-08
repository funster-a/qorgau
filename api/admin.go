// admin.go — пульт демо (/admin/*) и служебные эндпоинты бота (/bot/*).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ---------- флаги (in-memory, потокобезопасно) ----------

type Flags struct {
	ForceDegraded    bool `json:"force_degraded"`
	BroadcastEnabled bool `json:"broadcast_enabled"`
	RateLimitEnabled bool `json:"rate_limit_enabled"`
}

var (
	flagsMu sync.RWMutex
	flags   = Flags{ForceDegraded: false, BroadcastEnabled: true, RateLimitEnabled: true}
)

func getFlags() Flags {
	flagsMu.RLock()
	defer flagsMu.RUnlock()
	return flags
}

func handleFlags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, getFlags())
	case http.MethodPost:
		// Частичное обновление: меняем только переданные поля.
		var patch struct {
			ForceDegraded    *bool `json:"force_degraded"`
			BroadcastEnabled *bool `json:"broadcast_enabled"`
			RateLimitEnabled *bool `json:"rate_limit_enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		flagsMu.Lock()
		if patch.ForceDegraded != nil {
			flags.ForceDegraded = *patch.ForceDegraded
		}
		if patch.BroadcastEnabled != nil {
			flags.BroadcastEnabled = *patch.BroadcastEnabled
		}
		if patch.RateLimitEnabled != nil {
			flags.RateLimitEnabled = *patch.RateLimitEnabled
		}
		cur := flags
		flagsMu.Unlock()
		log.Printf("флаги обновлены: %+v", cur)
		writeJSON(w, cur)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------- защита заголовком ----------

// requireKey: если expected пуст (MVP) — эндпоинт открыт, иначе сверяем заголовок.
func requireKey(header string, expected *string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if *expected != "" && r.Header.Get(header) != *expected {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// ---------- /bot/* ----------

func handleBotSubscribe(w http.ResponseWriter, r *http.Request) {
	botChatOp(w, r, `INSERT INTO pii.subscriber (chat_id) VALUES ($1) ON CONFLICT DO NOTHING`)
}

func handleBotUnsubscribe(w http.ResponseWriter, r *http.Request) {
	botChatOp(w, r, `DELETE FROM pii.subscriber WHERE chat_id=$1`)
}

func botChatOp(w http.ResponseWriter, r *http.Request, query string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ChatID int64 `json:"chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChatID == 0 {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := db.Exec(query, req.ChatID); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func handleBotSubscribers(w http.ResponseWriter, r *http.Request) {
	ids := []int64{}
	if db != nil {
		rows, err := db.Query(`SELECT chat_id FROM pii.subscriber ORDER BY created_at`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				rows.Scan(&id)
				ids = append(ids, id)
			}
		}
	}
	writeJSON(w, map[string]any{"chat_ids": ids})
}

// ---------- /admin/seed — правдоподобная история для демо ----------

type seedScheme struct {
	code   string
	weight int
	brand  string
	flags  []string
}

var seedSchemes = []seedScheme{
	{"bank_security", 18, "Kaspi", []string{"просят назвать код из СМС", "звонок «службы безопасности»"}},
	{"phishing_link", 14, "", []string{"подозрительный домен"}},
	{"prize_payout", 10, "Kaspi", []string{"обещание выигрыша"}},
	{"investment", 10, "КазМунайГаз", []string{"нереалистичный доход"}},
	{"card_block", 8, "Halyk", []string{"угроза блокировки"}},
	{"relative_help", 7, "", []string{"сценарий «родственник в беде»"}},
	{"gov_payout", 6, "eGov", []string{"фейковая госвыплата"}},
	{"remote_install", 4, "", []string{"удалённый доступ к устройству"}},
	{"other", 3, "", []string{}},
	{"not_scam", 20, "", []string{}},
}

var seedRegions = []struct {
	name   string
	weight int
}{
	{"Almaty", 30}, {"Astana", 22}, {"Shymkent", 14}, {"Karaganda", 12},
	{"Aktobe", 8}, {"Atyrau", 6}, {"", 8},
}

var seedDomains = []string{
	"kaspi-bonus.site", "egov-vyplata.xyz", "halyk-verify.top",
	"olx-pay.icu", "kazpost-track.xyz", "kmg-invest.site",
}

func pickScheme() seedScheme {
	total := 0
	for _, s := range seedSchemes {
		total += s.weight
	}
	n := rand.Intn(total)
	for _, s := range seedSchemes {
		if n < s.weight {
			return s
		}
		n -= s.weight
	}
	return seedSchemes[0]
}

func pickRegion() string {
	total := 0
	for _, r := range seedRegions {
		total += r.weight
	}
	n := rand.Intn(total)
	for _, r := range seedRegions {
		if n < r.weight {
			return r.name
		}
		n -= r.weight
	}
	return ""
}

func handleSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		HistoryHours int `json:"history_hours"`
		PerHour      int `json:"per_hour"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.HistoryHours <= 0 || req.HistoryHours > 24*14 {
		req.HistoryHours = 24
	}
	if req.PerHour <= 0 || req.PerHour > 200 {
		req.PerHour = 6
	}
	n, err := seedHistory(req.HistoryHours, req.PerHour)
	if err != nil {
		log.Printf("seed error: %v", err)
		http.Error(w, "seed failed", http.StatusInternalServerError)
		return
	}
	log.Printf("seed: вставлено %d сигналов за %dч", n, req.HistoryHours)
	writeJSON(w, map[string]any{"ok": true, "inserted": n})
}

func seedHistory(hours, perHour int) (int, error) {
	inserted := 0
	now := time.Now()
	for h := hours; h >= 1; h-- {
		hourStart := now.Add(-time.Duration(h) * time.Hour)
		// лёгкий джиттер: часы неодинаково загружены
		count := perHour - perHour/3 + rand.Intn(perHour*2/3+1)
		for i := 0; i < count; i++ {
			s := pickScheme()
			score := 30 + rand.Intn(66) // 30..95
			if s.code == "not_scam" {
				score = rand.Intn(21) // 0..20
			}
			degraded := rand.Intn(10) == 0
			channel := "web"
			if rand.Intn(100) < 55 {
				channel = "tg"
			}
			lang := "ru"
			if rand.Intn(100) < 15 {
				lang = "kz"
			}
			createdAt := hourStart.Add(time.Duration(rand.Intn(3600)) * time.Second)
			flagsJSON, _ := json.Marshal(s.flags)
			brand := ""
			if s.brand != "" && rand.Intn(100) < 70 {
				brand = s.brand
			}
			var signalID string
			err := db.QueryRow(
				`INSERT INTO analytics.signal
				 (scheme_code, risk_score, risk_level, flags, impersonated_brand, region, lang, channel, degraded, created_at)
				 VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10) RETURNING id`,
				s.code, score, levelFor(score), flagsJSON, brand, pickRegion(), lang, channel, degraded, createdAt,
			).Scan(&signalID)
			if err != nil {
				return inserted, err
			}
			inserted++
			// индикаторы: у части скам-сигналов домен или маскированный телефон
			if s.code != "not_scam" && s.code != "other" {
				switch {
				case rand.Intn(100) < 35:
					db.Exec(`INSERT INTO analytics.ioc (signal_id, type, value_hash) VALUES ($1,'domain',$2)`,
						signalID, seedDomains[rand.Intn(len(seedDomains))])
				case rand.Intn(100) < 25:
					db.Exec(`INSERT INTO analytics.ioc (signal_id, type, value_hash) VALUES ($1,'phone',$2)`,
						signalID, fmt.Sprintf("+7 7** *** ** %02d", rand.Intn(100)))
				}
			}
		}
	}
	return inserted, nil
}

// ---------- /admin/spike — впрыск всплеска для демо детектора ----------

func handleSpike(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Scheme string `json:"scheme"`
		Count  int    `json:"count"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Scheme == "" {
		req.Scheme = "bank_security"
	}
	if schemeTitle(req.Scheme) == "" || req.Scheme == "not_scam" {
		http.Error(w, "unknown scheme", http.StatusBadRequest)
		return
	}
	if req.Count <= 0 || req.Count > 500 {
		req.Count = 25
	}
	domain := fmt.Sprintf("%s-alert-%d.xyz", req.Scheme[:4], 100+rand.Intn(900))
	flagsJSON, _ := json.Marshal([]string{"волна: один и тот же домен"})
	now := time.Now()
	for i := 0; i < req.Count; i++ {
		score := 70 + rand.Intn(26)
		createdAt := now.Add(-time.Duration(rand.Intn(600)) * time.Second) // последние 10 минут
		var signalID string
		if err := db.QueryRow(
			`INSERT INTO analytics.signal
			 (scheme_code, risk_score, risk_level, flags, region, lang, channel, degraded, created_at)
			 VALUES ($1,$2,'high',$3,NULLIF($4,''),'ru',$5,false,$6) RETURNING id`,
			req.Scheme, score, flagsJSON, pickRegion(), []string{"web", "tg"}[rand.Intn(2)], createdAt,
		).Scan(&signalID); err != nil {
			http.Error(w, "spike failed", http.StatusInternalServerError)
			return
		}
		db.Exec(`INSERT INTO analytics.ioc (signal_id, type, value_hash) VALUES ($1,'domain',$2)`, signalID, domain)
	}
	log.Printf("spike: %d сигналов %s (домен %s)", req.Count, req.Scheme, domain)
	writeJSON(w, map[string]any{"ok": true, "inserted": req.Count, "domain": domain})
}

// ---------- /admin/clear ----------

func handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := db.Exec(`TRUNCATE analytics.ioc, analytics.signal, analytics.campaign`); err != nil {
		http.Error(w, "clear failed", http.StatusInternalServerError)
		return
	}
	log.Println("admin/clear: analytics очищена")
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- /admin/recent ----------

func handleRecent(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if db == nil {
		writeJSON(w, out)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := db.Query(`SELECT s.created_at, s.scheme_code, sc.title_ru, s.risk_score,
			s.risk_level, COALESCE(s.region,''), s.channel, s.degraded
		FROM analytics.signal s JOIN analytics.scheme sc ON sc.code = s.scheme_code
		ORDER BY s.created_at DESC LIMIT $1`, limit)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var created time.Time
			var scheme, title, level, region, channel string
			var score int
			var degraded bool
			rows.Scan(&created, &scheme, &title, &score, &level, &region, &channel, &degraded)
			out = append(out, map[string]any{
				"created_at": created.UTC(), "scheme": scheme, "title": title,
				"risk_score": score, "risk_level": level, "region": region,
				"channel": channel, "degraded": degraded,
			})
		}
	}
	writeJSON(w, out)
}
