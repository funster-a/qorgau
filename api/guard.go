// guard.go — этап «ВО ВРЕМЯ»: защита близкого («опекун ↔ подопечный»).
//   POST /guard/link      — опекун получает код привязки QG-XXXX (in-memory, TTL 15м)
//   POST /guard/confirm   — подопечный вводит код → связь в pii.guard_link
//   GET  /guard/links      — кого защищаю / кто защищает
//   POST /guard/alert      — (бот) создать алерт опекунам подопечного (X-Bot-Key)
//   GET  /guard/alerts     — (бот) недоставленные алерты (X-Bot-Key)
//   POST /guard/alerts/ack — (бот) отметить доставленными (X-Bot-Key)
// Идентификаторы (chat_id) — зона pii. В алерте НЕ передаётся текст сообщения
// подопечного: опекун видит только факт, тип угрозы и риск (приватность).
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/lib/pq"
)

// ---------- коды привязки в памяти (TTL 15 мин) ----------

type linkCode struct {
	guardian int64
	expires  time.Time
}

var (
	lcMu        sync.Mutex
	linkCodes   = map[string]linkCode{}
	lcJanitor   bool
)

func ensureLinkJanitor() {
	lcMu.Lock()
	if !lcJanitor {
		lcJanitor = true
		go func() {
			t := time.NewTicker(5 * time.Minute)
			for range t.C {
				lcMu.Lock()
				for c, v := range linkCodes {
					if time.Now().After(v.expires) {
						delete(linkCodes, c)
					}
				}
				lcMu.Unlock()
			}
		}()
	}
	lcMu.Unlock()
}

func genLinkCode() string {
	return fmt.Sprintf("QG-%04d", rand.Intn(10000))
}

// ---------- POST /guard/link ----------

func handleGuardLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ensureLinkJanitor()
	var req struct {
		GuardianChatID int64  `json:"guardian_chat_id"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.GuardianChatID == 0 {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	const ttl = 15 * time.Minute
	code := genLinkCode()
	lcMu.Lock()
	// избегаем коллизии кода
	for _, ok := linkCodes[code]; ok; _, ok = linkCodes[code] {
		code = genLinkCode()
	}
	linkCodes[code] = linkCode{guardian: req.GuardianChatID, expires: time.Now().Add(ttl)}
	lcMu.Unlock()

	writeJSON(w, map[string]any{"code": code, "expires_in_sec": int(ttl.Seconds())})
}

// ---------- POST /guard/confirm ----------

func handleGuardConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code       string `json:"code"`
		WardChatID int64  `json:"ward_chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.WardChatID == 0 {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	lcMu.Lock()
	lc, ok := linkCodes[req.Code]
	if ok && time.Now().After(lc.expires) {
		delete(linkCodes, req.Code)
		ok = false
	}
	lcMu.Unlock()
	if !ok {
		writeJSON(w, map[string]any{"ok": false, "error": "invalid_or_expired_code"})
		return
	}
	if lc.guardian == req.WardChatID {
		writeJSON(w, map[string]any{"ok": false, "error": "cannot_link_self"})
		return
	}
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := db.Exec(`INSERT INTO pii.guard_link (guardian_chat_id, ward_chat_id)
		VALUES ($1,$2) ON CONFLICT DO NOTHING`, lc.guardian, req.WardChatID); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "guardian_chat_id": lc.guardian})
}

// ---------- GET /guard/links?chat_id=123 ----------

func handleGuardLinks(w http.ResponseWriter, r *http.Request) {
	chatID, _ := strconv.ParseInt(r.URL.Query().Get("chat_id"), 10, 64)
	wards := []map[string]any{}
	guardians := []map[string]any{}
	if chatID != 0 && db != nil {
		if rows, err := db.Query(`SELECT ward_chat_id, linked_at FROM pii.guard_link WHERE guardian_chat_id=$1 ORDER BY linked_at`, chatID); err == nil {
			for rows.Next() {
				var id int64
				var at time.Time
				rows.Scan(&id, &at)
				wards = append(wards, map[string]any{"ward_chat_id": id, "linked_at": at.UTC()})
			}
			rows.Close()
		}
		if rows, err := db.Query(`SELECT guardian_chat_id, linked_at FROM pii.guard_link WHERE ward_chat_id=$1 ORDER BY linked_at`, chatID); err == nil {
			for rows.Next() {
				var id int64
				var at time.Time
				rows.Scan(&id, &at)
				guardians = append(guardians, map[string]any{"guardian_chat_id": id, "linked_at": at.UTC()})
			}
			rows.Close()
		}
	}
	writeJSON(w, map[string]any{"wards": wards, "guardians": guardians})
}

// ---------- POST /guard/alert (X-Bot-Key) — создаёт алерты опекунам ----------

func handleGuardAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		WardChatID  int64  `json:"ward_chat_id"`
		SchemeTitle string `json:"scheme_title"`
		RiskScore   int    `json:"risk_score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.WardChatID == 0 {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if db == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	if req.SchemeTitle == "" {
		req.SchemeTitle = "Подозрение на мошенничество"
	}
	// Один алерт на каждого опекуна подопечного. Текст сообщения НЕ сохраняется.
	rows, err := db.Query(`SELECT guardian_chat_id FROM pii.guard_link WHERE ward_chat_id=$1`, req.WardChatID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	guardians := []int64{}
	for rows.Next() {
		var g int64
		rows.Scan(&g)
		guardians = append(guardians, g)
	}
	rows.Close()
	created := 0
	for _, g := range guardians {
		if _, err := db.Exec(`INSERT INTO pii.guard_alert (guardian_chat_id, scheme_title, risk_score)
			VALUES ($1,$2,$3)`, g, req.SchemeTitle, req.RiskScore); err == nil {
			created++
		}
	}
	writeJSON(w, map[string]any{"ok": true, "alerts_created": created})
}

// ---------- GET /guard/alerts (X-Bot-Key) — недоставленные ----------

func handleGuardAlerts(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if db != nil {
		rows, err := db.Query(`SELECT id, guardian_chat_id, scheme_title, risk_score, created_at
			FROM pii.guard_alert WHERE delivered=false ORDER BY created_at LIMIT 200`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, title string
				var g int64
				var score int
				var at time.Time
				rows.Scan(&id, &g, &title, &score, &at)
				out = append(out, map[string]any{
					"id": id, "guardian_chat_id": g, "scheme_title": title,
					"risk_score": score, "created_at": at.UTC(),
				})
			}
		}
	}
	writeJSON(w, out)
}

// ---------- POST /guard/alerts/ack (X-Bot-Key) ----------

func handleGuardAlertsAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if db == nil || len(req.IDs) == 0 {
		writeJSON(w, map[string]any{"ok": true, "acked": 0})
		return
	}
	res, err := db.Exec(`UPDATE pii.guard_alert SET delivered=true WHERE id = ANY($1)`, pq.Array(req.IDs))
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	writeJSON(w, map[string]any{"ok": true, "acked": n})
}
