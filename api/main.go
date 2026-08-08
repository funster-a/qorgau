// Qorǵau API — единый Go-сервис: движок анализа + запись сигналов + статистика.
// Эндпоинты:
//
//	POST /analyze          — анализ сообщения (Groq + эвристический фолбэк)
//	GET  /stats/summary    — сводка для дашборда
//	GET  /stats/timeseries — ряд по схемам
//	GET  /campaigns/active — активные кампании (аномалии)
//	GET  /healthz
//
// БД опциональна: если DATABASE_URL пуст, анализ работает, запись пропускается.
package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// ---------- конфиг ----------
// Заполняется в main() уже ПОСЛЕ чтения .env, поэтому не инициализируем здесь.
var (
	groqKey   string
	groqBase  string
	groqModel string
	apiAddr   string
	dbURL     string
	piiTTL    time.Duration
)

func loadConfig() {
	loadDotEnv()
	groqKey = env("GROQ_API_KEY", "")
	groqBase = env("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
	groqModel = env("GROQ_MODEL", "llama-3.3-70b-versatile")
	apiAddr = env("API_ADDR", ":8080")
	dbURL = env("DATABASE_URL", "")
	hours, err := strconv.Atoi(env("PII_TTL_HOURS", "24"))
	if err != nil || hours <= 0 {
		hours = 24
	}
	piiTTL = time.Duration(hours) * time.Hour
}

// loadDotEnv читает .env из рабочей директории или на уровень выше (запуск из api/).
// Уже заданные переменные окружения имеют приоритет — .env их не перетирает.
func loadDotEnv() {
	for _, p := range []string{".env", filepath.Join("..", ".env")} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			if _, exists := os.LookupEnv(k); !exists {
				os.Setenv(k, v)
			}
		}
		f.Close()
		log.Printf("конфиг подхвачен из %s", p)
		return
	}
}

var db *sql.DB

// ---------- типы контракта (см. TZ.md §5.2) ----------
type AnalyzeRequest struct {
	Text    string `json:"text"`
	Channel string `json:"channel"`
	Region  string `json:"region"`
}

type IOC struct {
	Type        string `json:"type"`
	Value       string `json:"value,omitempty"`
	ValueMasked string `json:"value_masked,omitempty"`
}

type AnalyzeResponse struct {
	RiskScore          int      `json:"risk_score"`
	RiskLevel          string   `json:"risk_level"`
	SchemeCode         string   `json:"scheme_code"`
	SchemeTitle        string   `json:"scheme_title,omitempty"`
	ImpersonatedBrand  string   `json:"impersonated_brand"`
	Flags              []string `json:"flags"`
	Explanation        string   `json:"explanation"`
	RecommendedActions []string `json:"recommended_actions"`
	IOCs               []IOC    `json:"iocs"`
	Lang               string   `json:"lang"`
	Degraded           bool     `json:"degraded"`
}

const systemPrompt = `Ты — Qorǵau, эксперт по распознаванию мошенничества в Казахстане.
Проанализируй сообщение и верни ТОЛЬКО валидный JSON:
{"risk_score":0-100,"risk_level":"low|medium|high","scheme_code":"bank_security|card_block|prize_payout|relative_help|phishing_link|investment|gov_payout|remote_install|other|not_scam","impersonated_brand":"строка или null","flags":["признаки"],"explanation":"почему, простым языком","recommended_actions":["что делать"],"iocs":[{"type":"phone|domain|url|iban","value":"как в тексте"}],"lang":"ru|kz"}
Оценивай: срочность/давление, запрос кода из СМС/CVV, маскировку под банк/госорган/полицию,
просьбу перевести деньги или установить AnyDesk/TeamViewer, «выигрыш/компенсация»,
«родственник в беде», подозрительные ссылки. Банки и госорганы НИКОГДА не просят код из СМС.
Если сообщение безобидное — scheme_code="not_scam" и низкий risk_score. Отвечай кратко, без воды.`

func main() {
	loadConfig()
	if groqKey == "" {
		log.Println("GROQ_API_KEY пуст — работаю на эвристическом фолбэке (degraded)")
	}
	if dbURL != "" {
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Printf("db open error: %v (продолжаю без БД)", err)
			db = nil
		} else if err = db.Ping(); err != nil {
			log.Printf("db ping error: %v (продолжаю без БД)", err)
			db = nil
		} else {
			log.Println("db connected")
			go ttlCleaner()
		}
	} else {
		log.Println("DATABASE_URL пуст — работаю без записи в БД")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/analyze", withCORS(handleAnalyze))
	mux.HandleFunc("/stats/summary", withCORS(handleSummary))
	mux.HandleFunc("/stats/timeseries", withCORS(handleTimeseries))
	mux.HandleFunc("/campaigns/active", withCORS(handleCampaigns))

	// Отдаём веб-чекер с того же адреса: на демо одна ссылка и никаких CORS.
	if dir := webDir(); dir != "" {
		mux.Handle("/", http.FileServer(http.Dir(dir)))
		log.Printf("веб-чекер: http://localhost%s/ (из %s)", apiAddr, dir)
	}

	log.Printf("Qorǵau API на %s (model=%s)", apiAddr, groqModel)
	log.Fatal(http.ListenAndServe(apiAddr, mux))
}

// ---------- /analyze ----------
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" || len(req.Text) > 4000 {
		http.Error(w, "empty or too long text", http.StatusBadRequest)
		return
	}

	res := classify(req.Text)
	res.SchemeTitle = schemeTitle(res.SchemeCode)

	// Маскируем индикаторы перед отдачей и записью (BR-2).
	for i := range res.IOCs {
		res.IOCs[i].ValueMasked = mask(res.IOCs[i].Type, res.IOCs[i].Value)
		res.IOCs[i].Value = ""
	}
	res.IOCs = dedupeIOCs(res.IOCs)

	if db != nil {
		if err := store(req, res); err != nil {
			log.Printf("store error: %v", err)
		}
	}
	writeJSON(w, res)
}

// classify: пробуем Groq, при ошибке — эвристический фолбэк.
func classify(text string) AnalyzeResponse {
	if groqKey != "" {
		if res, err := classifyGroq(text); err == nil {
			return res
		} else {
			log.Printf("groq error: %v → фолбэк", err)
		}
	}
	res := classifyHeuristic(text)
	res.Degraded = true
	normalize(&res)
	return res
}

// ---------- Groq (OpenAI-совместимый) ----------
func classifyGroq(text string) (AnalyzeResponse, error) {
	body := map[string]any{
		"model":       groqModel,
		"temperature": 0.1,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": text},
		},
		"response_format": map[string]string{"type": "json_object"},
	}
	b, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, groqBase+"/chat/completions", bytes.NewReader(b))
	httpReq.Header.Set("Authorization", "Bearer "+groqKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return AnalyzeResponse{}, err
	}
	defer resp.Body.Close()

	// Ошибку от Groq (401/429/5xx) читаем как текст: в теле нет choices, и разбор ниже
	// иначе упал бы на пустом срезе вместо честного перехода в фолбэк.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return AnalyzeResponse{}, fmt.Errorf("groq http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var wrap struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return AnalyzeResponse{}, err
	}
	if len(wrap.Choices) == 0 {
		return AnalyzeResponse{}, fmt.Errorf("groq вернул пустой choices")
	}
	var out AnalyzeResponse
	content := extractJSON(wrap.Choices[0].Message.Content)
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return AnalyzeResponse{}, err
	}
	normalize(&out)
	return out, nil
}

// normalize приводит ответ модели к контракту: модель может выдумать код схемы
// (это уронило бы вставку по внешнему ключу) или выйти за диапазон score.
func normalize(out *AnalyzeResponse) {
	if out.RiskScore < 0 {
		out.RiskScore = 0
	}
	if out.RiskScore > 100 {
		out.RiskScore = 100
	}
	if schemeTitle(out.SchemeCode) == "" {
		out.SchemeCode = "other"
	}
	switch out.RiskLevel {
	case "low", "medium", "high":
	default:
		out.RiskLevel = levelFor(out.RiskScore)
	}
	if out.Lang != "kz" {
		out.Lang = "ru"
	}
	if out.Flags == nil {
		out.Flags = []string{}
	}
	if out.RecommendedActions == nil {
		out.RecommendedActions = []string{}
	}
	if out.IOCs == nil {
		out.IOCs = []IOC{}
	}
}

func levelFor(score int) string {
	switch {
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	}
	return "low"
}

// ---------- эвристический фолбэк (работает без интернета) ----------
type rule struct {
	re     *regexp.Regexp
	weight int
	scheme string
	flag   string
}

var rules = []rule{
	{regexp.MustCompile(`(?i)код из смс|одноразов|никому не сообщайте`), 40, "bank_security", "запрос кода из СМС"},
	{regexp.MustCompile(`(?i)служба безопасн|банк|kaspi|каспи|halyk|халык`), 20, "bank_security", "маскировка под банк"},
	{regexp.MustCompile(`(?i)срочно|немедленно|в течение|истека|заблокир`), 20, "card_block", "давление срочностью"},
	{regexp.MustCompile(`(?i)выигр|приз|поздравля|компенсац|выплат`), 25, "prize_payout", "обещание лёгких денег"},
	{regexp.MustCompile(`(?i)перевед|реквизит|номер карты|cvv`), 30, "bank_security", "запрос данных карты/перевода"},
	{regexp.MustCompile(`(?i)полиц|кнб|прокурат|финпол|дело`), 20, "bank_security", "маскировка под органы"},
	{regexp.MustCompile(`(?i)сын|дочь|авари|залог|помоги|беда`), 25, "relative_help", "родственник в беде"},
	{regexp.MustCompile(`(?i)инвест|доход|крипт|заработок|процент`), 20, "investment", "лёгкий заработок"},
	{regexp.MustCompile(`(?i)anydesk|teamviewer|установите приложение`), 30, "remote_install", "удалённый доступ"},
	{regexp.MustCompile(`(?i)http://|bit\.ly|tinyurl|\.xyz|\.top`), 25, "phishing_link", "подозрительная ссылка"},
}

func classifyHeuristic(text string) AnalyzeResponse {
	score := 0
	flags := []string{}
	schemeVotes := map[string]int{}
	for _, r := range rules {
		if r.re.MatchString(text) {
			score += r.weight
			flags = append(flags, r.flag)
			schemeVotes[r.scheme] += r.weight
		}
	}
	if score > 100 {
		score = 100
	}
	scheme := "not_scam"
	best := 0
	for s, v := range schemeVotes {
		if v > best {
			best, scheme = v, s
		}
	}
	level := levelFor(score)
	if score < 15 {
		scheme = "not_scam"
	}
	expl := "Базовый режим: обнаружены типичные признаки мошенничества — будьте осторожны."
	actions := []string{"Не сообщайте коды и данные карты", "Не переходите по ссылкам", "Свяжитесь с банком по официальному номеру"}
	if scheme == "not_scam" {
		expl = "Базовый режим: явных признаков мошенничества не обнаружено."
		actions = []string{}
		flags = []string{}
	}
	return AnalyzeResponse{
		RiskScore: score, RiskLevel: level, SchemeCode: scheme,
		Flags: flags, Explanation: expl, RecommendedActions: actions,
		IOCs: extractIOCs(text), Lang: "ru",
	}
}

// ---------- индикаторы и маскирование ----------
var (
	rePhone = regexp.MustCompile(`(?:\+?7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}`)
	reURL   = regexp.MustCompile(`https?://[^\s]+`)
	reIBAN  = regexp.MustCompile(`KZ\d{18}`)
)

func extractIOCs(text string) []IOC {
	out := []IOC{}
	for _, m := range rePhone.FindAllString(text, -1) {
		out = append(out, IOC{Type: "phone", Value: m})
	}
	for _, m := range reURL.FindAllString(text, -1) {
		out = append(out, IOC{Type: "domain", Value: m})
	}
	for _, m := range reIBAN.FindAllString(text, -1) {
		out = append(out, IOC{Type: "iban", Value: m})
	}
	return out
}

// mask обезличивает индикатор ПЕРЕД отдачей и записью (BR-2).
// Домен — не персональные данные и главный признак кампании, поэтому его
// оставляем целиком: без этого радар не связал бы обращения в одну волну.
func mask(typ, v string) string {
	v = strings.TrimSpace(v)
	switch typ {
	case "domain", "url":
		return host(v)
	case "phone":
		return maskPhone(v)
	}
	return maskTail(v)
}

// maskPhone: "+7 701 234 56 78" → "+7 7** *** ** 78" (видны код страны и хвост).
func maskPhone(v string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(v, "")
	if len(digits) < 6 {
		return "****"
	}
	if len(digits) == 11 && (digits[0] == '8' || digits[0] == '7') {
		return fmt.Sprintf("+7 %c** *** ** %s", digits[1], digits[len(digits)-2:])
	}
	return maskTail(digits)
}

func maskTail(v string) string {
	r := []rune(v)
	if len(r) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(r)-4) + string(r[len(r)-4:])
}

// host вытаскивает домен из URL, отбрасывая путь и параметры (там бывают токены).
func host(raw string) string {
	raw = strings.TrimRight(raw, ".,);!?»\"'")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return maskTail(raw)
	}
	return strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
}

// dedupeIOCs: одна ссылка, упомянутая трижды, не должна утроить вес индикатора.
func dedupeIOCs(in []IOC) []IOC {
	seen := map[string]bool{}
	out := []IOC{}
	for _, ioc := range in {
		key := ioc.Type + "|" + ioc.ValueMasked
		if ioc.ValueMasked == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ioc)
	}
	return out
}

// ---------- хранение ----------
func store(req AnalyzeRequest, res AnalyzeResponse) error {
	if _, err := db.Exec(
		`INSERT INTO pii.raw_submission (raw_text, channel, expires_at) VALUES ($1,$2,$3)`,
		req.Text, orDefault(req.Channel, "web"), time.Now().Add(piiTTL),
	); err != nil {
		return err
	}
	flagsJSON, _ := json.Marshal(res.Flags)
	var signalID string
	if err := db.QueryRow(
		`INSERT INTO analytics.signal
		 (scheme_code, risk_score, risk_level, flags, impersonated_brand, region, lang, degraded)
		 VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8) RETURNING id`,
		res.SchemeCode, res.RiskScore, res.RiskLevel, flagsJSON,
		res.ImpersonatedBrand, req.Region, orDefault(res.Lang, "ru"), res.Degraded,
	).Scan(&signalID); err != nil {
		return err
	}
	for _, ioc := range res.IOCs {
		db.Exec(`INSERT INTO analytics.ioc (signal_id, type, value_hash) VALUES ($1,$2,$3)`,
			signalID, ioc.Type, ioc.ValueMasked)
	}
	go detectAnomaly(res.SchemeCode)
	return nil
}

// detectAnomaly: очень простая версия (BR-3). За окно 1ч сравниваем с суточным средним.
func detectAnomaly(scheme string) {
	if db == nil || scheme == "not_scam" {
		return
	}
	var lastHour, avgHour float64
	db.QueryRow(`SELECT count(*) FROM analytics.signal
		WHERE scheme_code=$1 AND created_at > now() - interval '1 hour'`, scheme).Scan(&lastHour)
	db.QueryRow(`SELECT COALESCE(count(*)/24.0,0) FROM analytics.signal
		WHERE scheme_code=$1 AND created_at > now() - interval '24 hour'`, scheme).Scan(&avgHour)
	if lastHour >= 5 && (avgHour == 0 || lastHour >= 3*avgHour) {
		db.Exec(`INSERT INTO analytics.campaign (scheme_code, peak_value)
			SELECT $1,$2 WHERE NOT EXISTS (
			  SELECT 1 FROM analytics.campaign WHERE scheme_code=$1 AND status='active')`,
			scheme, int(lastHour))
		log.Printf("АНОМАЛИЯ: кампания по схеме %s (за час=%v)", scheme, lastHour)
	}
}

// ---------- статистика для дашборда ----------
func handleSummary(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		writeJSON(w, map[string]any{"total": 0, "top": []any{}})
		return
	}
	var total int
	db.QueryRow(`SELECT count(*) FROM analytics.signal`).Scan(&total)
	rows, _ := db.Query(`SELECT scheme_code, title_ru, cnt FROM analytics.v_top_schemes LIMIT 8`)
	top := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var code, title string
			var cnt int
			rows.Scan(&code, &title, &cnt)
			top = append(top, map[string]any{"scheme": code, "title": title, "count": cnt})
		}
	}
	writeJSON(w, map[string]any{"total": total, "top": top})
}

func handleTimeseries(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		writeJSON(w, []any{})
		return
	}
	rows, _ := db.Query(`SELECT bucket, scheme_code, cnt FROM analytics.v_signals_hourly ORDER BY bucket`)
	out := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var bucket time.Time
			var scheme string
			var cnt int
			rows.Scan(&bucket, &scheme, &cnt)
			out = append(out, map[string]any{"t": bucket, "scheme": scheme, "count": cnt})
		}
	}
	writeJSON(w, out)
}

func handleCampaigns(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		writeJSON(w, []any{})
		return
	}
	rows, _ := db.Query(`SELECT c.scheme_code, s.title_ru, c.started_at, c.peak_value
		FROM analytics.campaign c JOIN analytics.scheme s ON s.code=c.scheme_code
		WHERE c.status='active' ORDER BY c.started_at DESC`)
	out := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var code, title string
			var started time.Time
			var peak int
			rows.Scan(&code, &title, &started, &peak)
			out = append(out, map[string]any{"scheme": code, "title": title, "started_at": started, "peak": peak})
		}
	}
	writeJSON(w, out)
}

// ---------- утилиты ----------
func ttlCleaner() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		db.Exec(`DELETE FROM pii.raw_submission WHERE expires_at < now()`)
	}
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

func schemeTitle(code string) string {
	m := map[string]string{
		"bank_security": "Фейковая служба безопасности банка", "card_block": "Блокировка карты / счёта",
		"prize_payout": "Выигрыш / компенсация / выплата", "relative_help": "Родственник в беде",
		"phishing_link": "Фишинговая ссылка", "investment": "Инвестиции / лёгкий заработок",
		"gov_payout": "Госвыплата / пособие", "remote_install": "Удалённый доступ",
		"other": "Другое", "not_scam": "Похоже, не мошенничество",
	}
	return m[code]
}

func extractJSON(s string) string {
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
