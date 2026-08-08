// shield.go — Qorǵau Shield: DoH-резолвер (RFC 8484) с блок-листом фишинговых
// доменов. Домен из блок-листа → NXDOMAIN, остальное проксируется в Cloudflare DoH.
//
// ПРИВАТНОСТЬ (принципиально, фишка на защите): клиентские IP-адреса НЕ
// логируются и НЕ сохраняются нигде — ни в логах, ни в БД, ни в памяти.
// Ведём только агрегированные счётчики: сколько блокировок за сегодня и
// какие домены блокировались (domain → count). По ним невозможно понять,
// КТО ходил на домен — только ЧТО блокировалось.
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	dohUpstream    = "https://cloudflare-dns.com/dns-query"
	dohContentType = "application/dns-message"
	dohMaxMsgSize  = 65535 // максимум DNS-сообщения (RFC 8484 рекомендует лимитировать тело)
)

var dohClient = &http.Client{Timeout: 4 * time.Second}

// ---------- блок-лист: map в памяти, обновляется тикером раз в 60с ----------

var (
	blMu        sync.RWMutex
	blDomains   = map[string]struct{}{}
	blUpdatedAt time.Time
)

// blocklistRefresher собирает блок-лист при старте и пересобирает раз в 60с
// из двух источников: сид-файла и analytics.ioc (домены из жалоб).
func blocklistRefresher() {
	refreshBlocklist()
	t := time.NewTicker(60 * time.Second)
	for range t.C {
		refreshBlocklist()
	}
}

func refreshBlocklist() {
	next := map[string]struct{}{}

	// Источник 1: сид-файл (по домену на строку, # — комментарий).
	if path := findBlocklistPath(); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if d := normalizeDomain(line); d != "" {
					next[d] = struct{}{}
				}
			}
		} else {
			log.Printf("shield: не прочитал сид блок-листа %s: %v", path, err)
		}
	}

	// Источник 2: домены из жалоб (analytics.ioc; домены там в открытом виде —
	// это не ПДн, см. CLAUDE.md). value_hash для type='domain' содержит хост.
	if db != nil {
		if rows, err := db.Query(`SELECT DISTINCT value_hash FROM analytics.ioc WHERE type='domain'`); err == nil {
			for rows.Next() {
				var v string
				if rows.Scan(&v) == nil {
					if d := normalizeDomain(v); d != "" {
						next[d] = struct{}{}
					}
				}
			}
			rows.Close()
		}
	}

	blMu.Lock()
	blDomains = next
	blUpdatedAt = time.Now().UTC()
	blMu.Unlock()
}

func findBlocklistPath() string {
	paths := []string{}
	if p := os.Getenv("BLOCKLIST_PATH"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, "db/blocklist_seed.txt", "../db/blocklist_seed.txt")
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// normalizeDomain: lower, без финальной точки, без пробелов.
func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// isBlocked: точное совпадение или совпадение родителя (блок поддоменов):
// "login.kaspi-secure.xyz" блокируется записью "kaspi-secure.xyz".
func isBlocked(name string) bool {
	blMu.RLock()
	defer blMu.RUnlock()
	for name != "" {
		if _, ok := blDomains[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
	return false
}

// ---------- счётчики блокировок (без каких-либо данных о клиенте) ----------

var (
	shieldMu        sync.Mutex
	blockedToday    int64
	blockedDay      string // "2006-01-02" UTC — для сброса в полночь
	blockedByDomain = map[string]int64{}
)

func recordBlock(domain string) {
	shieldMu.Lock()
	defer shieldMu.Unlock()
	day := time.Now().UTC().Format("2006-01-02")
	if day != blockedDay {
		blockedDay = day
		blockedToday = 0
	}
	blockedToday++
	blockedByDomain[domain]++
}

// ---------- GET|POST /dns-query (RFC 8484) ----------

func handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		// base64url без паддинга по RFC 8484; паддинг, если клиент прислал, срезаем.
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(q, "="))
		if err != nil {
			http.Error(w, "bad dns parameter", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		raw, err = io.ReadAll(io.LimitReader(r.Body, dohMaxMsgSize))
		if err != nil || len(raw) == 0 {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil || len(msg.Question) == 0 {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	qname := normalizeDomain(msg.Question[0].Name)

	if isBlocked(qname) {
		recordBlock(qname)
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeNameError) // NXDOMAIN; ID и вопрос копируются из запроса
		resp.RecursionAvailable = true
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", dohContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(out)
		return
	}

	// Не в блок-листе — пересылаем сырые байты запроса в вышестоящий DoH как есть.
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, dohUpstream, bytes.NewReader(raw))
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", dohContentType)
	upReq.Header.Set("Accept", dohContentType)
	upResp, err := dohClient.Do(upReq)
	if err != nil {
		http.Error(w, "upstream dns unavailable", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(upResp.Body, dohMaxMsgSize))
	if err != nil {
		http.Error(w, "upstream read error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", dohContentType)
	w.WriteHeader(upResp.StatusCode)
	w.Write(body)
}

// ---------- GET /shield/blocklist ----------

func handleShieldBlocklist(w http.ResponseWriter, r *http.Request) {
	blMu.RLock()
	domains := make([]string, 0, len(blDomains))
	for d := range blDomains {
		domains = append(domains, d)
	}
	updated := blUpdatedAt
	blMu.RUnlock()
	sort.Strings(domains)
	writeJSON(w, map[string]any{
		"updated_at": updated,
		"count":      len(domains),
		"domains":    domains,
	})
}

// ---------- GET /shield/stats ----------

func handleShieldStats(w http.ResponseWriter, r *http.Request) {
	blMu.RLock()
	blCount := len(blDomains)
	blMu.RUnlock()

	shieldMu.Lock()
	today := blockedToday
	if time.Now().UTC().Format("2006-01-02") != blockedDay {
		today = 0 // полночь UTC прошла, а блокировок с тех пор не было
	}
	type dc struct {
		Domain string `json:"domain"`
		Count  int64  `json:"count"`
	}
	top := make([]dc, 0, len(blockedByDomain))
	for d, c := range blockedByDomain {
		top = append(top, dc{d, c})
	}
	shieldMu.Unlock()

	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Domain < top[j].Domain
	})
	if len(top) > 10 {
		top = top[:10]
	}
	writeJSON(w, map[string]any{
		"blocked_today":   today,
		"blocklist_count": blCount,
		"top_blocked":     top,
	})
}

// ---------- GET /shield/apple.mobileconfig ----------

// Детерминированные UUID профиля: одинаковые между перезапусками, чтобы iOS
// видел повторную установку как обновление того же профиля.
const (
	shieldPayloadUUID = "7f3c2a9e-5b1d-4e8a-9c6f-2d4b8e1a7c35"
	shieldProfileUUID = "c1a4e7d2-8f36-4b9a-a5e0-6d2c9b8f4e13"
)

func handleShieldMobileconfig(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	scheme := "https"
	if r.Header.Get("X-Forwarded-Proto") != "https" &&
		(strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1")) {
		scheme = "http"
	}
	serverURL := fmt.Sprintf("%s://%s/dns-query", scheme, host)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>%s</string>
			</dict>
			<key>PayloadDescription</key>
			<string>DNS-защита от фишинговых доменов (Qorǵau Shield)</string>
			<key>PayloadDisplayName</key>
			<string>Qorǵau Shield DNS</string>
			<key>PayloadIdentifier</key>
			<string>kz.qorgau.shield.dns</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Блокирует известные фишинговые домены Казахстана на уровне DNS</string>
	<key>PayloadDisplayName</key>
	<string>Qorǵau Shield</string>
	<key>PayloadIdentifier</key>
	<string>kz.qorgau.shield</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, serverURL, shieldPayloadUUID, shieldProfileUUID)

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename=qorgau-shield.mobileconfig`)
	w.Write([]byte(plist))
}
