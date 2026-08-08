// leaks.go — проверка пароля по утечкам: прокси к HIBP range API (k-anonymity).
// Браузер считает SHA-1 пароля сам и шлёт только первые 5 hex-символов —
// сам пароль (и даже полный хэш) на наш сервер не попадает.
package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	hibpBase     = "https://api.pwnedpasswords.com/range/"
	hibpCacheTTL = time.Hour
	hibpCacheMax = 10000
)

var hibpClient = &http.Client{Timeout: 6 * time.Second}

type hibpEntry struct {
	body    []byte
	expires time.Time
}

var (
	hibpMu    sync.Mutex
	hibpCache = map[string]hibpEntry{}
)

func isHex5(s string) bool {
	if len(s) != 5 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// GET /leaks/password/{prefix5}
func handleLeaksPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/leaks/password/"))
	if !isHex5(prefix) {
		http.Error(w, "prefix must be 5 hex chars", http.StatusBadRequest)
		return
	}

	hibpMu.Lock()
	if e, ok := hibpCache[prefix]; ok && time.Now().Before(e.expires) {
		hibpMu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(e.body)
		return
	}
	hibpMu.Unlock()

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, hibpBase+prefix, nil)
	if err != nil {
		writeUpstreamError(w)
		return
	}
	req.Header.Set("User-Agent", "qorgau-hackathon")
	resp, err := hibpClient.Do(req)
	if err != nil {
		writeUpstreamError(w)
		return
	}
	defer resp.Body.Close()

	var body []byte
	switch {
	case resp.StatusCode == http.StatusOK:
		body, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			writeUpstreamError(w)
			return
		}
	case resp.StatusCode == http.StatusNotFound:
		body = []byte{} // по контракту: 404 от HIBP → пустое тело 200
	default:
		writeUpstreamError(w)
		return
	}

	hibpMu.Lock()
	if len(hibpCache) >= hibpCacheMax {
		hibpCache = map[string]hibpEntry{} // простая защита от роста: сброс кэша
	}
	hibpCache[prefix] = hibpEntry{body: body, expires: time.Now().Add(hibpCacheTTL)}
	hibpMu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(body)
}

func writeUpstreamError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(`{"error":"upstream"}`))
}
