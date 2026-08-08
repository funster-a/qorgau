// handlers.go — публичные эндпоинты (/analyze, /stats/*, /campaigns/active,
// /threat-feed, /privacy/proof, /healthz) и rate limit.
package main

import (
	"encoding/json"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
)

// ---------- rate limit: token bucket на IP (10 req/мин, burst 20) ----------

const (
	rlRatePerSec = 10.0 / 60.0
	rlBurst      = 20.0
)

type rlBucket struct {
	tokens float64
	last   time.Time
}

var (
	rlMu      sync.Mutex
	rlBuckets = map[string]*rlBucket{}
)

// rlAllow возвращает (разрешено, retry_after_sec).
func rlAllow(ip string) (bool, int) {
	rlMu.Lock()
	defer rlMu.Unlock()
	now := time.Now()
	b, ok := rlBuckets[ip]
	if !ok {
		b = &rlBucket{tokens: rlBurst, last: now}
		rlBuckets[ip] = b
	}
	b.tokens = math.Min(rlBurst, b.tokens+now.Sub(b.last).Seconds()*rlRatePerSec)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, int(math.Ceil((1 - b.tokens) / rlRatePerSec))
}

// rlCleaner выбрасывает давно не активные вёдра, чтобы map не рос вечно.
func rlCleaner() {
	t := time.NewTicker(5 * time.Minute)
	for range t.C {
		rlMu.Lock()
		for ip, b := range rlBuckets {
			if time.Since(b.last) > 10*time.Minute {
				delete(rlBuckets, ip)
			}
		}
		rlMu.Unlock()
	}
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- POST /analyze ----------

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if getFlags().RateLimitEnabled {
		if ok, retry := rlAllow(clientIP(r)); !ok {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{"error": "rate_limited", "retry_after_sec": retry})
			return
		}
	}
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" || len([]rune(req.Text)) > 4000 {
		http.Error(w, "empty or too long text", http.StatusBadRequest)
		return
	}

	res := classify(req.Text)
	maskAndStore(req, &res)
	writeJSON(w, res)
}

// maskAndStore проставляет заголовок схемы, маскирует индикаторы (BR-2) и пишет
// обезличенный сигнал. Единый путь записи для /analyze и киллер-анализаторов
// (link/image/audio) — чтобы все каналы попадали в analytics одинаково.
func maskAndStore(req AnalyzeRequest, res *AnalyzeResponse) {
	res.SchemeTitle = schemeTitle(res.SchemeCode)
	for i := range res.IOCs {
		res.IOCs[i].ValueMasked = mask(res.IOCs[i].Type, res.IOCs[i].Value)
		res.IOCs[i].Value = ""
	}
	res.IOCs = dedupeIOCs(res.IOCs)
	if db != nil {
		if err := store(req, *res); err != nil {
			log.Printf("store error: %v", err)
		}
	}
}

// ---------- GET /stats/regions (тепловая карта Казахстана) ----------

func handleStatsRegions(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if db == nil {
		writeJSON(w, out)
		return
	}
	// Регион по ВСЕМ обращениям (не только скам): доля high — индикатор напряжённости.
	rows, err := db.Query(`SELECT region, count(*) AS total,
			count(*) FILTER (WHERE risk_level='high') AS high
		FROM analytics.signal
		WHERE NULLIF(region,'') IS NOT NULL
		GROUP BY region HAVING count(*) > 0
		ORDER BY total DESC`)
	if err != nil {
		writeJSON(w, out)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var region string
		var total, high int
		rows.Scan(&region, &total, &high)
		share := 0
		if total > 0 {
			share = int(math.Round(100 * float64(high) / float64(total)))
		}
		out = append(out, map[string]any{
			"region": region, "total": total, "high": high, "share_high": share,
		})
	}
	writeJSON(w, out)
}

// ---------- GET /stats/summary ----------

func handleSummary(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"total": 0, "last_24h": 0, "high_share_24h": 0, "degraded_share_24h": 0,
		"campaigns_active": 0, "top": []any{}, "regions": []any{},
	}
	if db == nil {
		writeJSON(w, out)
		return
	}
	var total, last24, high24, degraded24, campaigns int
	db.QueryRow(`SELECT count(*) FROM analytics.signal`).Scan(&total)
	db.QueryRow(`SELECT count(*),
			count(*) FILTER (WHERE risk_level='high'),
			count(*) FILTER (WHERE degraded)
		FROM analytics.signal WHERE created_at > now() - interval '24 hours'`).
		Scan(&last24, &high24, &degraded24)
	db.QueryRow(`SELECT count(*) FROM analytics.campaign WHERE status='active'`).Scan(&campaigns)
	out["total"], out["last_24h"], out["campaigns_active"] = total, last24, campaigns
	if last24 > 0 {
		out["high_share_24h"] = int(math.Round(100 * float64(high24) / float64(last24)))
		out["degraded_share_24h"] = int(math.Round(100 * float64(degraded24) / float64(last24)))
	}

	top := []map[string]any{}
	if rows, err := db.Query(`SELECT scheme_code, title_ru, cnt FROM analytics.v_top_schemes LIMIT 8`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var code, title string
			var cnt int
			rows.Scan(&code, &title, &cnt)
			top = append(top, map[string]any{"scheme": code, "title": title, "count": cnt})
		}
	}
	out["top"] = top

	regions := []map[string]any{}
	if rows, err := db.Query(`SELECT region, count(*) FROM analytics.signal
			WHERE region IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 8`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var region string
			var cnt int
			rows.Scan(&region, &cnt)
			regions = append(regions, map[string]any{"region": region, "count": cnt})
		}
	}
	out["regions"] = regions
	writeJSON(w, out)
}

// ---------- GET /stats/timeseries?hours=24 ----------

func handleTimeseries(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if db == nil {
		writeJSON(w, out)
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*14 {
		hours = 24
	}
	rows, err := db.Query(`SELECT date_trunc('hour', created_at) AS bucket, scheme_code, count(*)
		FROM analytics.signal WHERE created_at > now() - $1 * interval '1 hour'
		GROUP BY 1, 2 ORDER BY 1`, hours)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var bucket time.Time
			var scheme string
			var cnt int
			rows.Scan(&bucket, &scheme, &cnt)
			out = append(out, map[string]any{"t": bucket.UTC(), "scheme": scheme, "count": cnt})
		}
	}
	writeJSON(w, out)
}

// ---------- GET /campaigns/active ----------

func handleCampaigns(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if db == nil {
		writeJSON(w, out)
		return
	}
	rows, err := db.Query(`SELECT c.id, c.scheme_code, s.title_ru, c.started_at, c.peak_value, c.status
		FROM analytics.campaign c JOIN analytics.scheme s ON s.code=c.scheme_code
		WHERE c.status='active' ORDER BY c.started_at DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, code, title, status string
			var started time.Time
			var peak int
			rows.Scan(&id, &code, &title, &started, &peak, &status)
			out = append(out, map[string]any{
				"id": id, "scheme": code, "title": title,
				"started_at": started.UTC(), "peak": peak, "status": status,
			})
		}
	}
	writeJSON(w, out)
}

// ---------- GET /threat-feed ----------

func handleThreatFeed(w http.ResponseWriter, r *http.Request) {
	indicators := []map[string]any{}
	if db != nil {
		rows, err := db.Query(`SELECT i.type, i.value_hash, count(*),
				min(s.created_at), max(s.created_at),
				array_agg(DISTINCT s.scheme_code)
			FROM analytics.ioc i JOIN analytics.signal s ON s.id = i.signal_id
			GROUP BY i.type, i.value_hash
			ORDER BY count(*) DESC, max(s.created_at) DESC LIMIT 100`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var typ, val string
				var cnt int
				var first, last time.Time
				var schemes pq.StringArray
				rows.Scan(&typ, &val, &cnt, &first, &last, &schemes)
				indicators = append(indicators, map[string]any{
					"type": typ, "value": val, "count": cnt,
					"first_seen": first.UTC(), "last_seen": last.UTC(),
					"schemes": []string(schemes),
				})
			}
		}
	}
	writeJSON(w, map[string]any{"generated_at": time.Now().UTC(), "indicators": indicators})
}

// ---------- GET /privacy/proof ----------

func handlePrivacyProof(w http.ResponseWriter, r *http.Request) {
	piiZone := map[string]any{"rows": 0, "ttl_hours": int(piiTTL.Hours()), "encrypted": true, "sample": nil}
	anZone := map[string]any{"rows": 0, "sample_signal": nil}
	if db != nil {
		var piiRows int
		db.QueryRow(`SELECT count(*) FROM pii.raw_submission`).Scan(&piiRows)
		piiZone["rows"] = piiRows
		var created, expires time.Time
		var hexPreview string
		if err := db.QueryRow(`SELECT created_at, expires_at,
				encode(substring(raw_text from 1 for 40), 'hex')
			FROM pii.raw_submission ORDER BY created_at DESC LIMIT 1`).
			Scan(&created, &expires, &hexPreview); err == nil {
			piiZone["sample"] = map[string]any{
				"created_at": created.UTC(), "expires_at": expires.UTC(),
				"raw_text_encrypted_preview": `\x` + hexPreview + "...",
			}
		}
		var anRows int
		db.QueryRow(`SELECT count(*) FROM analytics.signal`).Scan(&anRows)
		anZone["rows"] = anRows
		var scheme, region string
		var score int
		var flagsRaw []byte
		var sCreated time.Time
		if err := db.QueryRow(`SELECT scheme_code, risk_score, flags, COALESCE(region,''), created_at
			FROM analytics.signal ORDER BY created_at DESC LIMIT 1`).
			Scan(&scheme, &score, &flagsRaw, &region, &sCreated); err == nil {
			var flagsList []string
			json.Unmarshal(flagsRaw, &flagsList)
			if flagsList == nil {
				flagsList = []string{}
			}
			anZone["sample_signal"] = map[string]any{
				"scheme_code": scheme, "risk_score": score, "flags": flagsList,
				"region": region, "created_at": sCreated.UTC(),
			}
		}
	}
	writeJSON(w, map[string]any{"pii": piiZone, "analytics": anZone})
}

// ---------- GET /healthz ----------

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	dbOK := db != nil && db.Ping() == nil
	llm := "degraded"
	if groqKey != "" && !getFlags().ForceDegraded {
		llm = "groq"
	}
	writeJSON(w, map[string]any{"status": "ok", "db": dbOK, "llm": llm})
}

// ---------- утилиты ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token, X-Bot-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}
