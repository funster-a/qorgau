// Qorǵau API — единый Go-сервис: движок анализа + запись сигналов + статистика.
//
// Файлы пакета:
//
//	main.go     — запуск, роуты, graceful shutdown
//	config.go   — .env и переменные окружения
//	engine.go   — Groq + эвристический фолбэк + маскирование индикаторов
//	store.go    — Postgres: bootstrap схемы, запись, TTL-чистка PII
//	anomaly.go  — фоновый детектор кампаний (z-score)
//	admin.go    — пульт демо (/admin/*) и эндпоинты бота (/bot/*)
//	handlers.go — публичные хендлеры и rate limit
//
// БД опциональна: если DATABASE_URL пуст, анализ работает, запись пропускается.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	loadConfig()
	loadPrompt()
	if groqKey == "" {
		log.Println("GROQ_API_KEY пуст — работаю на эвристическом фолбэке (degraded)")
	}
	openDB()
	if db != nil {
		go ttlCleaner()
		go anomalyTicker()
	}
	go rlCleaner()
	go blocklistRefresher()

	mux := http.NewServeMux()
	// публичные
	mux.HandleFunc("/healthz", withCORS(handleHealthz))
	mux.HandleFunc("/analyze", withCORS(handleAnalyze))
	// киллер-анализаторы: ссылка (пассивно) / скриншот (vision) / голос (whisper)
	mux.HandleFunc("/analyze/link", withCORS(handleAnalyzeLink))
	mux.HandleFunc("/analyze/image", withCORS(handleAnalyzeImage))
	mux.HandleFunc("/analyze/audio", withCORS(handleAnalyzeAudio))
	mux.HandleFunc("/stats/summary", withCORS(handleSummary))
	mux.HandleFunc("/stats/regions", withCORS(handleStatsRegions))
	mux.HandleFunc("/stats/timeseries", withCORS(handleTimeseries))
	mux.HandleFunc("/campaigns/active", withCORS(handleCampaigns))
	mux.HandleFunc("/threat-feed", withCORS(handleThreatFeed))
	mux.HandleFunc("/privacy/proof", withCORS(handlePrivacyProof))
	// Qorǵau Shield: DoH-резолвер + блок-лист + профиль iOS
	mux.HandleFunc("/dns-query", withCORS(handleDNSQuery))
	mux.HandleFunc("/shield/blocklist", withCORS(handleShieldBlocklist))
	mux.HandleFunc("/shield/stats", withCORS(handleShieldStats))
	mux.HandleFunc("/shield/apple.mobileconfig", withCORS(handleShieldMobileconfig))
	// проверка пароля по утечкам (HIBP k-anonymity)
	mux.HandleFunc("/leaks/password/", withCORS(handleLeaksPassword))
	// этап «ДО»: проверка номера/карты + тренажёр
	mux.HandleFunc("/check/phone", withCORS(handleCheckPhone))
	mux.HandleFunc("/check/card", withCORS(handleCheckCard))
	mux.HandleFunc("/trainer/start", withCORS(handleTrainerStart))
	mux.HandleFunc("/trainer/reply", withCORS(handleTrainerReply))
	// этап «ВО ВРЕМЯ»: живой суфлёр + защита близкого
	mux.HandleFunc("/live/hint", withCORS(handleLiveHint))
	mux.HandleFunc("/guard/link", withCORS(handleGuardLink))
	mux.HandleFunc("/guard/confirm", withCORS(handleGuardConfirm))
	mux.HandleFunc("/guard/links", withCORS(handleGuardLinks))
	// алерты опекунам — только бот (X-Bot-Key, если задан BOT_API_KEY)
	mux.HandleFunc("/guard/alert", withCORS(requireKey("X-Bot-Key", &botAPIKey, handleGuardAlert)))
	mux.HandleFunc("/guard/alerts", withCORS(requireKey("X-Bot-Key", &botAPIKey, handleGuardAlerts)))
	mux.HandleFunc("/guard/alerts/ack", withCORS(requireKey("X-Bot-Key", &botAPIKey, handleGuardAlertsAck)))
	// этап «ПОСЛЕ»: ИИ-юрист первой помощи + ближайшие точки
	mux.HandleFunc("/help/chat", withCORS(handleHelpChat))
	mux.HandleFunc("/help/places", withCORS(handleHelpPlaces))
	// служебные для бота (X-Bot-Key, если задан BOT_API_KEY)
	mux.HandleFunc("/bot/subscribe", withCORS(requireKey("X-Bot-Key", &botAPIKey, handleBotSubscribe)))
	mux.HandleFunc("/bot/unsubscribe", withCORS(requireKey("X-Bot-Key", &botAPIKey, handleBotUnsubscribe)))
	mux.HandleFunc("/bot/subscribers", withCORS(requireKey("X-Bot-Key", &botAPIKey, handleBotSubscribers)))
	// админ (X-Admin-Token, если задан ADMIN_TOKEN)
	mux.HandleFunc("/admin/seed", withCORS(requireKey("X-Admin-Token", &adminToken, handleSeed)))
	mux.HandleFunc("/admin/spike", withCORS(requireKey("X-Admin-Token", &adminToken, handleSpike)))
	mux.HandleFunc("/admin/clear", withCORS(requireKey("X-Admin-Token", &adminToken, handleClear)))
	mux.HandleFunc("/admin/flags", withCORS(requireKey("X-Admin-Token", &adminToken, handleFlags)))
	mux.HandleFunc("/admin/recent", withCORS(requireKey("X-Admin-Token", &adminToken, handleRecent)))

	// Отдаём веб-чекер с того же адреса: на демо одна ссылка и никаких CORS.
	if dir := webDir(); dir != "" {
		mux.Handle("/", http.FileServer(http.Dir(dir)))
		log.Printf("веб-чекер: http://localhost%s/ (из %s)", apiAddr, dir)
	}

	srv := &http.Server{Addr: apiAddr, Handler: mux}
	go func() {
		log.Printf("Qorǵau API на %s (model=%s)", apiAddr, groqModel)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Graceful shutdown: даём начатым /analyze дописаться в БД.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("останавливаюсь...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	if db != nil {
		db.Close()
	}
	log.Println("остановлен")
}

// webDir ищет каталог веб-чекера: сервер запускают и из корня, и из api/.
func webDir() string {
	for _, p := range []string{env("WEB_DIR", ""), "web", filepath.Join("..", "web")} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(p, "index.html")); err == nil {
			return p
		}
	}
	return ""
}
