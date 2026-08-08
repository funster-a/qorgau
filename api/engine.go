// engine.go — AI-ядро: Groq (таймаут 5с + 1 ретрай 3с), эвристический фолбэк,
// нормализация ответа, извлечение и маскирование индикаторов.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ---------- типы контракта (docs/API.md) ----------

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
	SchemeTitle        string   `json:"scheme_title"`
	ImpersonatedBrand  string   `json:"impersonated_brand"`
	Flags              []string `json:"flags"`
	Explanation        string   `json:"explanation"`
	RecommendedActions []string `json:"recommended_actions"`
	IOCs               []IOC    `json:"iocs"`
	Lang               string   `json:"lang"`
	Degraded           bool     `json:"degraded"`
}

// ---------- системный промпт ----------

// Компактный встроенный фолбэк на случай, если engine/prompt.md не найден.
const fallbackPrompt = `Ты — Qorǵau, эксперт по распознаванию мошенничества в Казахстане.
Проанализируй сообщение и верни ТОЛЬКО валидный JSON:
{"risk_score":0-100,"risk_level":"low|medium|high","scheme_code":"bank_security|card_block|prize_payout|relative_help|phishing_link|investment|gov_payout|remote_install|other|not_scam","impersonated_brand":"строка или \"\"","flags":["признаки"],"explanation":"почему, простым языком","recommended_actions":["что делать"],"iocs":[{"type":"phone|domain|url|iban","value":"как в тексте"}],"lang":"ru|kz"}
Оценивай: срочность/давление, просьбу НАЗВАТЬ код из СМС/CVV, маскировку под банк/госорган/полицию,
перевод «на безопасный счёт», установку AnyDesk/TeamViewer, «выигрыш/компенсацию»,
«родственника в беде», подозрительные ссылки. Настоящая СМС банка с кодом и припиской
«никому не сообщайте» — НЕ мошенничество. Банки и госорганы никогда не просят назвать код.
Если сообщение безобидное — scheme_code="not_scam" и низкий risk_score. Кратко, без воды.`

var systemPrompt = fallbackPrompt

// loadPrompt загружает системный промпт: ENGINE_PROMPT_PATH → engine/prompt.md →
// ../engine/prompt.md → встроенный фолбэк. Логирует источник.
func loadPrompt() {
	paths := []string{}
	if p := os.Getenv("ENGINE_PROMPT_PATH"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, filepath.Join("engine", "prompt.md"), filepath.Join("..", "engine", "prompt.md"))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		systemPrompt = string(b)
		log.Printf("системный промпт загружен из %s (%d байт)", p, len(b))
		return
	}
	log.Println("engine/prompt.md не найден — использую встроенный фолбэк-промпт")
}

// ---------- классификация ----------

// classify: Groq (если не force_degraded), при ошибке — эвристический фолбэк.
func classify(text string) AnalyzeResponse {
	if groqKey != "" && !getFlags().ForceDegraded {
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

// classifyGroq: первая попытка с таймаутом 5с (KPI-1), при ошибке один ретрай с 3с.
func classifyGroq(text string) (AnalyzeResponse, error) {
	res, err := groqOnce(text, 5*time.Second)
	if err == nil {
		return res, nil
	}
	log.Printf("groq попытка 1: %v → ретрай", err)
	return groqOnce(text, 3*time.Second)
}

func groqOnce(text string, timeout time.Duration) (AnalyzeResponse, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return AnalyzeResponse{}, fmt.Errorf("groq http %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
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
	// Тип "url" сводим к "domain" (контракт docs/API.md): маскирование всё равно
	// оставляет от URL только хост, а блок-лист Shield собирается по type='domain' —
	// без этого домены из LLM-ответов не попадали бы под блокировку.
	for i := range out.IOCs {
		if out.IOCs[i].Type == "url" {
			out.IOCs[i].Type = "domain"
		}
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
	weight int // отрицательный — легитимный паттерн, снижает риск
	scheme string
	flag   string
}

var rules = []rule{
	// сильные скам-сигналы
	{regexp.MustCompile(`(?i)назовите код|продиктуйте код|сообщите код|скажите код|отправьте код|введите код из`), 45, "bank_security", "просят назвать код из СМС"},
	{regexp.MustCompile(`(?i)безопасн(ый|ом) сч[её]т|защищ[её]нный сч[её]т|сохранности (денег|средств)`), 45, "bank_security", "перевод на «безопасный счёт»"},
	{regexp.MustCompile(`(?i)служба безопасност`), 35, "bank_security", "звонок «службы безопасности»"},
	{regexp.MustCompile(`(?i)cvv|три цифры на обороте|номер карты|полные данные карты`), 35, "bank_security", "запрос данных карты"},
	{regexp.MustCompile(`(?i)полици|кнб|прокуратур|следовател|уголовн(ое|ым)`), 30, "bank_security", "маскировка под органы"},
	{regexp.MustCompile(`(?i)спишутся|списание средств|для отмены операции|отменить операцию|отмены операции`), 25, "bank_security", "угроза списания денег"},
	{regexp.MustCompile(`(?i)заблокирован|заблокируйте|разблокир|блокировк`), 35, "card_block", "угроза блокировки"},
	{regexp.MustCompile(`(?i)выигр|приз|лотере|джекпот|начислен[аоы]?\s`), 25, "prize_payout", "обещание выигрыша"},
	{regexp.MustCompile(`(?i)компенсаци|возврат средств`), 30, "prize_payout", "обещание компенсации"},
	{regexp.MustCompile(`(?i)соцвыплат|госвыплат|пособи[ея]|положена выплата|полагается выплата|выплата от государства|госпрограмм`), 35, "gov_payout", "фейковая госвыплата"},
	{regexp.MustCompile(`(?i)попал[а]? в (аварию|дтп|беду|полицию)|я в беде|кинь на карту|срочно переведи|переведи на карту|с чужого номера|ақша аудар|теңге аудар`), 40, "relative_help", "сценарий «родственник в беде»"},
	{regexp.MustCompile(`(?i)инвест|акци(и|ях) (казмунайгаз|kaspi|halyk|тенгри)|гарантированн\S+ (доход|прибыл)|пассивный доход|заработок от|доход от \d|криптовалют|биткоин`), 35, "investment", "нереалистичный доход"},
	{regexp.MustCompile(`(?i)anydesk|teamviewer|rustdesk|удал[её]нн(ый|ого) доступ|установите приложение`), 40, "remote_install", "удалённый доступ к устройству"},
	{regexp.MustCompile(`(?i)bit\.ly|tinyurl|goo\.gl|clck\.ru|\.xyz|\.top|\.site|\.icu|\.click|\.online|\.buzz`), 30, "phishing_link", "подозрительный домен"},
	{regexp.MustCompile(`(?i)http://`), 15, "phishing_link", "незащищённая ссылка"},
	{regexp.MustCompile(`(?i)проголосуй|голосовани`), 30, "phishing_link", "просьба проголосовать по ссылке"},
	{regexp.MustCompile(`(?i)получите деньги по ссылке|заберите (перевод|деньги)`), 35, "phishing_link", "деньги «по ссылке»"},
	{regexp.MustCompile(`(?i)оплатите (пошлину|комиссию|штраф|взнос)|страховой взнос|регистрационный взнос|предоплат`), 30, "other", "просят предоплату"},
	{regexp.MustCompile(`(?i)фото удостоверени|фото документов|иин и номер`), 30, "other", "запрос документов"},
	{regexp.MustCompile(`(?i)срочно|немедленно|прямо сейчас|в течение часа|иначе`), 15, "", "давление срочностью"},
	// легитимные паттерны — снижают риск (типовые фразы настоящих уведомлений)
	{regexp.MustCompile(`(?i)никому не сообщайте|не сообщайте (его|код) никому|не говорите код`), -35, "", ""},
	{regexp.MustCompile(`(?i)заказ №|ваш заказ|трек-номер|курьер|доставк|посылка прибыла|передан в доставку`), -15, "", ""},
	{regexp.MustCompile(`(?i)скидк|распродаж|промокод|кэшбэк|жума`), -10, "", ""},
	{regexp.MustCompile(`(?i)egov\.kz|gov\.kz|личн(ый|ом) кабинет|мобильном приложении`), -15, "", ""},
}

var reBrand = regexp.MustCompile(`(?i)(kaspi|каспи|halyk|халык|jusan|forte|egov|егов|кнб|wildberries|olx|kazpost|казпочта|whatsapp|telegram|казмунайгаз)`)

func classifyHeuristic(text string) AnalyzeResponse {
	score := 0
	flags := []string{}
	schemeVotes := map[string]int{}
	for _, r := range rules {
		if r.re.MatchString(text) {
			score += r.weight
			if r.flag != "" && r.weight > 0 {
				flags = append(flags, r.flag)
			}
			if r.scheme != "" && r.weight > 0 {
				schemeVotes[r.scheme] += r.weight
			}
		}
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	scheme := "not_scam"
	best := 0
	for s, v := range schemeVotes {
		if v > best {
			best, scheme = v, s
		}
	}
	if score < 25 {
		scheme = "not_scam"
	}
	level := levelFor(score)
	expl := "Базовый режим: обнаружены типичные признаки мошенничества — будьте осторожны."
	actions := []string{"Не сообщайте коды и данные карты", "Не переходите по ссылкам", "Свяжитесь с банком по официальному номеру"}
	brand := ""
	if scheme == "not_scam" {
		expl = "Базовый режим: явных признаков мошенничества не обнаружено."
		actions = []string{}
		flags = []string{}
	} else if m := reBrand.FindString(text); m != "" {
		brand = m
	}
	return AnalyzeResponse{
		RiskScore: score, RiskLevel: level, SchemeCode: scheme,
		ImpersonatedBrand: brand,
		Flags:             flags, Explanation: expl, RecommendedActions: actions,
		IOCs: extractIOCs(text), Lang: langOf(text),
	}
}

// langOf: грубая эвристика языка по специфичным казахским буквам.
func langOf(text string) string {
	if strings.ContainsAny(text, "әғқңөұүіӘҒҚҢӨҰҮІ") {
		return "kz"
	}
	return "ru"
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
