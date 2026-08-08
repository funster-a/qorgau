// check.go — этап «ДО»: POST /check/phone и POST /check/card.
// Проверка номера — по накопленным жалобам (analytics.ioc, type='phone').
// Проверка карты — Luhn (свой) + BIN по локальной таблице db/bins_kz.json.
// Полный номер карты НЕ хранится и НЕ логируется — только маска.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

var reNonDigit = regexp.MustCompile(`\D`)

// ---------- POST /check/phone ----------

func handleCheckPhone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	digits := reNonDigit.ReplaceAllString(req.Phone, "")
	if len(digits) < 6 {
		http.Error(w, "bad phone", http.StatusBadRequest)
		return
	}
	masked := maskPhone(req.Phone)
	last2 := digits[len(digits)-2:]

	reports := 0
	schemes := []map[string]any{}
	var firstSeen, lastSeen any = nil, nil

	if db != nil {
		// value_hash для type='phone' хранит маску (BR-2). Матчим по точной маске
		// либо по последним двум цифрам — этого достаточно для сигнала «встречался».
		var fs, ls *time.Time
		db.QueryRow(`SELECT count(*), min(s.created_at), max(s.created_at)
			FROM analytics.ioc i JOIN analytics.signal s ON s.id = i.signal_id
			WHERE i.type='phone' AND (i.value_hash=$1 OR right(i.value_hash,2)=$2)`,
			masked, last2).Scan(&reports, &fs, &ls)
		if fs != nil {
			firstSeen = fs.UTC()
		}
		if ls != nil {
			lastSeen = ls.UTC()
		}
		rows, err := db.Query(`SELECT s.scheme_code, sc.title_ru, count(*) c
			FROM analytics.ioc i
			JOIN analytics.signal s ON s.id = i.signal_id
			JOIN analytics.scheme sc ON sc.code = s.scheme_code
			WHERE i.type='phone' AND (i.value_hash=$1 OR right(i.value_hash,2)=$2)
			GROUP BY 1,2 ORDER BY c DESC LIMIT 8`, masked, last2)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var code, title string
				var c int
				rows.Scan(&code, &title, &c)
				schemes = append(schemes, map[string]any{"scheme": code, "title": title, "count": c})
			}
		}
	}

	level := "low"
	switch {
	case reports >= 5:
		level = "high"
	case reports >= 1:
		level = "medium"
	}

	verdict, actions := phoneVerdict(level, reports)
	writeJSON(w, map[string]any{
		"phone_masked":        masked,
		"reports":             reports,
		"risk_level":          level,
		"first_seen":          firstSeen,
		"last_seen":           lastSeen,
		"schemes":             schemes,
		"verdict":             verdict,
		"recommended_actions": actions,
	})
}

func phoneVerdict(level string, reports int) (string, []string) {
	switch level {
	case "high":
		return "Номер многократно встречался в жалобах на мошенничество. Высокий риск — не отвечайте и не перезванивайте.",
			[]string{
				"Не берите трубку и не перезванивайте на этот номер",
				"Не называйте коды из СМС и данные карты",
				"Внесите номер в чёрный список",
			}
	case "medium":
		return "Номер уже упоминался в жалобах. Будьте осторожны — возможен мошеннический звонок.",
			[]string{
				"Не сообщайте личные данные и коды из СМС",
				"Если «звонят из банка» — положите трубку и перезвоните на номер с карты",
			}
	default:
		return "В базе жалоб Qorǵau этот номер не встречался. Это не гарантия безопасности — оценивайте по содержанию разговора.",
			[]string{
				"Никому не называйте коды из СМС — банк их не спрашивает",
				"При давлении и спешке положите трубку и перезвоните в организацию сами",
			}
	}
}

// ---------- POST /check/card ----------

type binEntry struct {
	Bin   string `json:"bin"`
	Bank  string `json:"bank"`
	Brand string `json:"brand"`
	Known bool   `json:"known"`
}

var (
	binsOnce sync.Once
	binsMap  = map[string]binEntry{}
)

func loadBins() {
	binsOnce.Do(func() {
		for _, p := range []string{binsPathEnv(), "db/bins_kz.json", "../db/bins_kz.json"} {
			if p == "" {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var doc struct {
				Bins []binEntry `json:"bins"`
			}
			if json.Unmarshal(b, &doc) == nil {
				for _, e := range doc.Bins {
					binsMap[e.Bin] = e
				}
				return
			}
		}
	})
}

func binsPathEnv() string {
	if p := os.Getenv("BINS_PATH"); p != "" {
		return p
	}
	return ""
}

// brandByFirstDigit — грубое определение платёжной системы, когда BIN не в таблице.
func brandByFirstDigit(d string) string {
	if d == "" {
		return ""
	}
	switch d[0] {
	case '4':
		return "VISA"
	case '5', '2':
		return "MASTERCARD"
	case '6':
		return "VISA/UnionPay"
	}
	return ""
}

func luhnValid(d string) bool {
	if len(d) < 12 {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// maskCard: "4400430212345678" → "4400 **** **** 5678" (видны БИН-начало и хвост).
func maskCard(d string) string {
	if len(d) < 8 {
		return "****"
	}
	return d[:4] + " **** **** " + d[len(d)-4:]
}

func handleCheckCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Card string `json:"card"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	digits := reNonDigit.ReplaceAllString(req.Card, "")
	if len(digits) < 12 || len(digits) > 19 {
		http.Error(w, "bad card", http.StatusBadRequest)
		return
	}
	loadBins()

	masked := maskCard(digits)
	valid := luhnValid(digits)
	bin6 := digits[:6]

	binInfo := map[string]any{"bank": "", "country": "KZ", "brand": brandByFirstDigit(digits), "known": false}
	if e, ok := binsMap[bin6]; ok {
		binInfo = map[string]any{"bank": e.Bank, "country": "KZ", "brand": e.Brand, "known": e.Known}
	}

	// Полный номер НЕ пишем и НЕ логируем. reports по маске (type='card') — обычно 0,
	// т.к. карты в analytics не накапливаются; поле честно отражает базу жалоб.
	reports := 0
	if db != nil {
		db.QueryRow(`SELECT count(*) FROM analytics.ioc WHERE type='card' AND value_hash=$1`, masked).Scan(&reports)
	}

	level := "low"
	verdict := "Карта прошла проверку контрольной суммы (Luhn) — номер корректен. Это не проверка баланса или владельца."
	if !valid {
		level = "medium"
		verdict = "Номер не проходит проверку контрольной суммы (Luhn). Возможна опечатка или недействительный номер."
	}
	switch {
	case reports >= 5:
		level = "high"
		verdict = "Эта карта многократно фигурировала в жалобах как счёт для приёма мошеннических переводов."
	case reports >= 1:
		if level != "high" {
			level = "medium"
		}
		verdict = "Эта карта уже упоминалась в жалобах. Не переводите на неё деньги."
	}

	writeJSON(w, map[string]any{
		"card_masked": masked,
		"luhn_valid":  valid,
		"bin":         binInfo,
		"reports":     reports,
		"risk_level":  level,
		"verdict":     verdict,
		"recommended_actions": []string{
			"Никогда и никому не сообщайте полный номер карты, срок и CVV/CVC (три цифры на обороте)",
			"Код из СМS-подтверждения — это подпись под операцией, не диктуйте его никому",
			"Для перевода незнакомцу «за возврат/бонус» — это почти всегда мошенничество",
		},
	})
}
