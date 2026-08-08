// link.go — POST /analyze/link: пассивный разбор ссылки БЕЗ перехода на сайт.
// Три независимых сигнала (whois-возраст домена, TLS-сертификат, похожесть на
// бренд КЗ) + блок-лист Shield сводятся в детерминированный вердикт. Ни один
// источник не обязателен: при неудаче поле пустое/-1, эвристика работает по
// тому, что удалось узнать. Никаких HTTP-запросов К САМОМУ сайту — только
// whois и TLS-хендшейк на :443.
package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// ---------- контракт (docs/API.md §Киллер-анализаторы) ----------

type LinkRequest struct {
	URL    string `json:"url"`
	Region string `json:"region"`
}

type SSLInfo struct {
	Present    bool   `json:"present"`
	SelfSigned bool   `json:"self_signed"`
	Issuer     string `json:"issuer"`
	AgeDays    int    `json:"age_days"`
	Valid      bool   `json:"valid"`
}

type BrandMatch struct {
	Brand    string `json:"brand"`
	Distance int    `json:"distance"`
}

type LinkResponse struct {
	AnalyzeResponse
	Domain          string       `json:"domain"`
	DomainAgeDays   int          `json:"domain_age_days"`
	Registrar       string       `json:"registrar"`
	SSL             SSLInfo      `json:"ssl"`
	BrandSimilarity []BrandMatch `json:"brand_similarity"`
	InBlocklist     bool         `json:"in_blocklist"`
}

// Бренды КЗ, под которые чаще всего маскируются фишинговые домены.
// label — второй уровень домена (для сравнения), brand — как показать пользователю.
var kzBrands = []struct{ label, brand string }{
	{"kaspi", "kaspi.kz"}, {"halykbank", "halykbank.kz"}, {"egov", "egov.kz"},
	{"forte", "forte.kz"}, {"jusan", "jusan.kz"}, {"bcc", "bcc.kz"},
	{"kazpost", "kazpost.kz"}, {"enpf", "enpf.kz"}, {"otbasy", "otbasy.kz"},
}

var riskyTLDs = map[string]bool{"xyz": true, "top": true, "site": true}

// ---------- расстояние Левенштейна (свой, без зависимостей) ----------

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// brandSimilarity: минимальное расстояние между брендом и вторым уровнем домена
// ИЛИ его токенами (по дефису). Токены ловят комбосквоттинг («kaspi-bonus» →
// токен «kaspi» distance 0), одиночная метка — тайпсквоттинг («kaspii» → 1).
// Порог dist < len(brand) отсекает мусор для коротких брендов (bcc и т.п.).
func brandSimilarity(sld string) []BrandMatch {
	candidates := []string{sld}
	for _, tok := range strings.FieldsFunc(sld, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(tok) >= 3 {
			candidates = append(candidates, tok)
		}
	}
	out := []BrandMatch{}
	for _, b := range kzBrands {
		best := 1 << 30
		for _, c := range candidates {
			if d := levenshtein(c, b.label); d < best {
				best = d
			}
		}
		if best <= 3 && best < len(b.label) {
			out = append(out, BrandMatch{Brand: b.brand, Distance: best})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distance != out[j].Distance {
			return out[i].Distance < out[j].Distance
		}
		return out[i].Brand < out[j].Brand
	})
	return out
}

// ---------- whois: возраст домена + регистратор (таймаут 5с) ----------

func lookupWhois(registrable string) (ageDays int, registrar string) {
	ageDays, registrar = -1, ""
	type res struct {
		age int
		reg string
	}
	ch := make(chan res, 1)
	go func() {
		out := res{age: -1}
		client := whois.NewClient()
		client.SetTimeout(5 * time.Second)
		raw, err := client.Whois(registrable)
		if err != nil {
			ch <- out
			return
		}
		parsed, err := whoisparser.Parse(raw)
		if err != nil {
			ch <- out
			return
		}
		if parsed.Registrar != nil {
			out.reg = parsed.Registrar.Name
		}
		if parsed.Domain != nil && parsed.Domain.CreatedDateInTime != nil {
			out.age = int(time.Since(*parsed.Domain.CreatedDateInTime).Hours() / 24)
			if out.age < 0 {
				out.age = 0
			}
		}
		ch <- out
	}()
	select {
	case r := <-ch:
		return r.age, r.reg
	case <-time.After(6 * time.Second):
		return -1, ""
	}
}

// ---------- TLS: сертификат на :443 (таймаут 4с) ----------

func inspectSSL(registrable string) SSLInfo {
	info := SSLInfo{}
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	addr := registrable + ":443"

	// 1) читаем серт без верификации — чтобы достать issuer/NotBefore даже у битого.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, ServerName: registrable,
	})
	if err != nil {
		return info // present=false → «нет SSL»
	}
	certs := conn.ConnectionState().PeerCertificates
	conn.Close()
	if len(certs) == 0 {
		return info
	}
	info.Present = true
	leaf := certs[0]
	info.Issuer = issuerName(leaf.Issuer)
	info.AgeDays = int(time.Since(leaf.NotBefore).Hours() / 24)
	if info.AgeDays < 0 {
		info.AgeDays = 0
	}
	selfSigned := leaf.Issuer.String() == leaf.Subject.String()

	// 2) отдельная обычная верификация → valid (цепочка + имя + срок).
	conn2, err2 := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: registrable})
	if err2 == nil {
		info.Valid = true
		conn2.Close()
	} else {
		selfSigned = true // verify failed (см. контракт: self_signed при провале верификации)
	}
	info.SelfSigned = selfSigned
	return info
}

func issuerName(n pkix.Name) string {
	if len(n.Organization) > 0 && n.Organization[0] != "" {
		return n.Organization[0]
	}
	return n.CommonName
}

// ---------- POST /analyze/link ----------

func handleAnalyzeLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(req.URL)
	if raw == "" {
		http.Error(w, "empty url", http.StatusBadRequest)
		return
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		http.Error(w, "bad url", http.StatusBadRequest)
		return
	}
	host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
	labels := strings.Split(host, ".")
	tld, sld, registrable := "", host, host
	if len(labels) >= 2 {
		tld = labels[len(labels)-1]
		sld = labels[len(labels)-2]
		registrable = labels[len(labels)-2] + "." + labels[len(labels)-1]
	}

	// Три пассивных источника (можно было бы параллелить, но 5с+4с приемлемо для MVP).
	ageDays, registrar := lookupWhois(registrable)
	ssl := inspectSSL(registrable)
	brands := brandSimilarity(sld)
	inBlock := isBlocked(host)

	// ---- эвристический риск-скор ----
	score := 0
	flags := []string{}
	if ageDays >= 0 && ageDays < 7 {
		score += 50
		flags = append(flags, plural(ageDays, "домену %d день", "домену %d дня", "домену %d дней"))
	} else if ageDays >= 0 && ageDays < 30 {
		score += 30
		flags = append(flags, plural(ageDays, "домену %d день", "домену %d дня", "домену %d дней"))
	}
	if ssl.SelfSigned {
		score += 25
		flags = append(flags, "самоподписанный/невалидный сертификат")
	}
	if !ssl.Present {
		score += 20
		flags = append(flags, "нет действующего HTTPS-сертификата")
	}
	brand := ""
	genuine := false
	if len(brands) > 0 {
		top := brands[0]
		if registrable == top.Brand {
			// Точное совпадение с официальным доменом бренда — это сам бренд, не подделка.
			genuine = true
		} else {
			brand = top.Brand
			if top.Distance <= 2 {
				score += 35
			} else {
				score += 20
			}
			flags = append(flags, "маскировка под "+top.Brand)
		}
	}
	if inBlock {
		score += 60
		flags = append(flags, "домен уже в блок-листе Qorǵau Shield")
	}
	if riskyTLDs[tld] {
		score += 15
		flags = append(flags, "рискованная зона ."+tld)
	}
	if score > 100 {
		score = 100
	}

	scheme := "phishing_link"
	expl := "Пассивный разбор ссылки: явных признаков фишинга не обнаружено, но переходить по незнакомым ссылкам всё равно не стоит."
	actions := []string{"Не вводите на этом сайте логины, пароли и данные карты",
		"Открывайте банк и госуслуги только через официальное приложение или egov.kz"}
	if score >= 30 {
		expl = "Пассивный разбор ссылки выявил признаки фишингового домена — не переходите и не вводите данные."
	}
	if brand != "" {
		expl = "Домен маскируется под " + brand + " и имеет признаки фишинга. Настоящий " + brand + " не использует такие адреса — не вводите на нём данные."
	}
	if genuine {
		// Официальный домен известного бренда с валидным сертификатом — не подделка.
		scheme = "not_scam"
		expl = "Это официальный домен " + registrable + " — известный легитимный сайт. Всё равно проверяйте адрес в строке браузера перед вводом данных."
		actions = []string{"Убедитесь, что адрес в браузере точно совпадает с официальным"}
	}

	resp := LinkResponse{
		AnalyzeResponse: AnalyzeResponse{
			RiskScore:          score,
			RiskLevel:          levelFor(score),
			SchemeCode:         scheme,
			ImpersonatedBrand:  brand,
			Flags:              flags,
			Explanation:        expl,
			RecommendedActions: actions,
			IOCs:               []IOC{{Type: "domain", Value: host}},
			Lang:               "ru",
			Degraded:           false,
		},
		Domain:          registrable,
		DomainAgeDays:   ageDays,
		Registrar:       registrar,
		SSL:             ssl,
		BrandSimilarity: brands,
		InBlocklist:     inBlock,
	}

	// Запись сигнала тем же путём, что /analyze (channel="link"); маскирует домен.
	storeReq := AnalyzeRequest{Text: raw, Channel: "link", Region: req.Region}
	maskAndStore(storeReq, &resp.AnalyzeResponse)
	writeJSON(w, resp)
}

// plural подбирает русскую форму по числу (1 день / 2 дня / 5 дней).
func plural(n int, one, few, many string) string {
	mod10, mod100 := n%10, n%100
	switch {
	case mod10 == 1 && mod100 != 11:
		return fmt.Sprintf(one, n)
	case mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20):
		return fmt.Sprintf(few, n)
	default:
		return fmt.Sprintf(many, n)
	}
}
