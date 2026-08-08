// Qorǵau Telegram-бот. Тонкий клиент: шлёт текст в API /analyze и красиво выводит вердикт.
// Плюс подписка на оповещения: горутина поллит /campaigns/active и рассылает
// предупреждение подписчикам при новой волне мошенничества.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var (
	apiURL    string
	botAPIKey string // если задан BOT_API_KEY — шлём X-Bot-Key на /bot/*
)

type analyzeResp struct {
	RiskScore          int      `json:"risk_score"`
	RiskLevel          string   `json:"risk_level"`
	SchemeTitle        string   `json:"scheme_title"`
	Flags              []string `json:"flags"`
	Explanation        string   `json:"explanation"`
	RecommendedActions []string `json:"recommended_actions"`
	IOCs               []struct {
		Type        string `json:"type"`
		ValueMasked string `json:"value_masked"`
	} `json:"iocs"`
	Degraded bool `json:"degraded"`
}

type campaign struct {
	ID     string `json:"id"`
	Scheme string `json:"scheme"`
	Title  string `json:"title"`
	Peak   int    `json:"peak"`
	Status string `json:"status"`
}

const helpText = `🛡️ <b>Qorǵau</b> — проверка сообщений на мошенничество.

Просто пришлите подозрительную СМС или скопированную переписку — я разберу её за пару секунд и объясню, что не так.

Команды:
/help — эта справка
/campaigns — какие схемы мошенничества сейчас на подъёме
/subscribe — получать предупреждения о новых волнах мошенничества
/unsubscribe — отключить предупреждения

⚠️ Помните: банк и госорганы <b>никогда</b> не просят код из СМС.`

func main() {
	loadDotEnv()
	apiURL = env("API_URL", "http://localhost:8080")
	botAPIKey = os.Getenv("BOT_API_KEY")

	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN не задан (см. .env.example)")
	}
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Бот @%s запущен, API=%s", bot.Self.UserName, apiURL)

	go broadcastLoop(bot)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	for update := range bot.GetUpdatesChan(u) {
		if update.Message == nil {
			continue
		}
		go handle(bot, update.Message)
	}
}

func handle(bot *tgbotapi.BotAPI, m *tgbotapi.Message) {
	chatID := m.Chat.ID
	text := strings.TrimSpace(m.Text)

	// Пересланное фото/голосовое без подписи разобрать нечем — подсказываем, что делать.
	if text == "" {
		send(bot, chatID, "Пришлите <b>текст</b> сообщения — скриншоты я пока не читаю. Скопируйте СМС и отправьте сюда.")
		return
	}

	switch {
	case text == "/start":
		send(bot, chatID, helpText+"\n\nСовет: подпишитесь на /subscribe — предупрежу, когда по стране пойдёт новая волна мошенничества.")
		return
	case text == "/help":
		send(bot, chatID, helpText)
		return
	case text == "/campaigns":
		send(bot, chatID, campaignsText())
		return
	case text == "/subscribe":
		if err := botAPICall("/bot/subscribe", chatID); err != nil {
			log.Printf("subscribe error: %v", err)
			send(bot, chatID, "⚠️ Не получилось оформить подписку, попробуйте позже.")
			return
		}
		send(bot, chatID, "🔔 Готово! Пришлю предупреждение, когда зафиксируем новую волну мошенничества. Отключить: /unsubscribe")
		return
	case text == "/unsubscribe":
		if err := botAPICall("/bot/unsubscribe", chatID); err != nil {
			log.Printf("unsubscribe error: %v", err)
			send(bot, chatID, "⚠️ Не получилось отписаться, попробуйте позже.")
			return
		}
		send(bot, chatID, "🔕 Подписка отключена. Вернуть предупреждения: /subscribe")
		return
	case strings.HasPrefix(text, "/"):
		send(bot, chatID, "Не знаю такой команды. /help — что я умею.")
		return
	}

	if len([]rune(text)) > 4000 {
		send(bot, chatID, "Сообщение слишком длинное. Пришлите ключевой фрагмент (до 4000 символов).")
		return
	}

	bot.Send(tgbotapi.NewChatAction(chatID, tgbotapi.ChatTyping))

	res, err := analyze(text)
	if err != nil {
		log.Printf("analyze error: %v", err)
		send(bot, chatID, "⚠️ Не удалось проверить сообщение — сервис недоступен. Попробуйте через минуту.")
		return
	}
	send(bot, chatID, format(res))
}

// ---------- вызовы API ----------

func analyze(text string) (analyzeResp, error) {
	body, _ := json.Marshal(map[string]string{"text": text, "channel": "tg"})
	client := http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(apiURL+"/analyze", "application/json", bytes.NewReader(body))
	if err != nil {
		return analyzeResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return analyzeResp{}, fmt.Errorf("api http %d", resp.StatusCode)
	}
	var out analyzeResp
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// botAPICall — POST на /bot/subscribe|unsubscribe с X-Bot-Key (если задан).
func botAPICall(path string, chatID int64) error {
	body, _ := json.Marshal(map[string]int64{"chat_id": chatID})
	req, _ := http.NewRequest(http.MethodPost, apiURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if botAPIKey != "" {
		req.Header.Set("X-Bot-Key", botAPIKey)
	}
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("api http %d", resp.StatusCode)
	}
	return nil
}

func fetchCampaigns() ([]campaign, error) {
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(apiURL + "/campaigns/active")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var list []campaign
	return list, json.NewDecoder(resp.Body).Decode(&list)
}

func fetchSubscribers() ([]int64, error) {
	req, _ := http.NewRequest(http.MethodGet, apiURL+"/bot/subscribers", nil)
	if botAPIKey != "" {
		req.Header.Set("X-Bot-Key", botAPIKey)
	}
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		ChatIDs []int64 `json:"chat_ids"`
	}
	return out.ChatIDs, json.NewDecoder(resp.Body).Decode(&out)
}

// broadcastEnabled спрашивает флаг у API; при любой ошибке считаем true (fail-open).
func broadcastEnabled() bool {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL + "/admin/flags")
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return true
	}
	var f struct {
		BroadcastEnabled *bool `json:"broadcast_enabled"`
	}
	if json.NewDecoder(resp.Body).Decode(&f) != nil || f.BroadcastEnabled == nil {
		return true
	}
	return *f.BroadcastEnabled
}

// ---------- broadcast новых кампаний ----------

// broadcastLoop поллит активные кампании раз в 30с и рассылает предупреждение
// подписчикам по каждой ещё не виденной кампании.
func broadcastLoop(bot *tgbotapi.BotAPI) {
	seen := map[string]bool{}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		list, err := fetchCampaigns()
		if err != nil {
			log.Printf("broadcast: campaigns error: %v", err)
		}
		for _, c := range list {
			if c.ID == "" || seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			if !broadcastEnabled() {
				log.Printf("broadcast: кампания %s (%s) — рассылка выключена флагом", c.ID, c.Scheme)
				continue
			}
			broadcast(bot, c)
		}
		<-t.C
	}
}

func broadcast(bot *tgbotapi.BotAPI, c campaign) {
	subs, err := fetchSubscribers()
	if err != nil {
		log.Printf("broadcast: subscribers error: %v", err)
		return
	}
	msg := fmt.Sprintf(`⚠️ <b>Новая волна мошенничества:</b> %s.
За последний час %d обращений.

Будьте осторожны:
• Не называйте коды из СМС — даже «сотруднику банка»
• Не переходите по подозрительным ссылкам
• Перезванивайте в банк только по официальному номеру

Проверить подозрительное сообщение — просто пришлите его мне.
/unsubscribe — отключить предупреждения`, esc(c.Title), c.Peak)

	sent := 0
	for _, chatID := range subs {
		m := tgbotapi.NewMessage(chatID, msg)
		m.ParseMode = tgbotapi.ModeHTML
		m.DisableWebPagePreview = true
		if _, err := bot.Send(m); err != nil {
			log.Printf("broadcast → %d: %v", chatID, err)
			// Пользователь заблокировал бота — отписываем, чтобы не долбиться впустую.
			if strings.Contains(err.Error(), "Forbidden") || strings.Contains(err.Error(), "blocked") {
				botAPICall("/bot/unsubscribe", chatID)
			}
		} else {
			sent++
		}
		time.Sleep(50 * time.Millisecond) // лимиты Telegram (~30 msg/сек)
	}
	log.Printf("broadcast: кампания «%s» — отправлено %d/%d подписчикам", c.Title, sent, len(subs))
}

// ---------- вывод вердикта ----------

func campaignsText() string {
	list, err := fetchCampaigns()
	if err != nil {
		return "⚠️ Не удалось получить сводку. Попробуйте позже."
	}
	if len(list) == 0 {
		return "✅ Сейчас активных всплесков мошенничества не зафиксировано."
	}
	var b bytes.Buffer
	b.WriteString("🚨 <b>Сейчас на подъёме:</b>\n\n")
	for _, c := range list {
		fmt.Fprintf(&b, "• %s — %d обращений за час\n", esc(c.Title), c.Peak)
	}
	b.WriteString("\nБудьте особенно внимательны к таким сообщениям.")
	return b.String()
}

func format(r analyzeResp) string {
	emoji, word := "🟢", "низкий"
	switch r.RiskLevel {
	case "high":
		emoji, word = "🔴", "высокий"
	case "medium":
		emoji, word = "🟡", "средний"
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s <b>Риск %s — %d/100</b>\n", emoji, word, r.RiskScore)
	if r.SchemeTitle != "" {
		fmt.Fprintf(&b, "Схема: %s\n", esc(r.SchemeTitle))
	}
	b.WriteString("\n" + progressBar(r.RiskScore) + "\n")

	if len(r.Flags) > 0 {
		b.WriteString("\n🚩 <b>Признаки:</b>\n")
		for _, f := range r.Flags {
			fmt.Fprintf(&b, "• %s\n", esc(f))
		}
	}
	if r.Explanation != "" {
		fmt.Fprintf(&b, "\n%s\n", esc(r.Explanation))
	}
	if len(r.RecommendedActions) > 0 {
		b.WriteString("\n✅ <b>Что делать:</b>\n")
		for _, a := range r.RecommendedActions {
			fmt.Fprintf(&b, "• %s\n", esc(a))
		}
	}
	if len(r.IOCs) > 0 {
		b.WriteString("\n🔎 <b>Найденные индикаторы:</b>\n")
		for _, i := range r.IOCs {
			fmt.Fprintf(&b, "• %s: <code>%s</code>\n", esc(i.Type), esc(i.ValueMasked))
		}
	}
	if r.Degraded {
		b.WriteString("\n<i>Базовый режим: ИИ временно недоступен, вердикт по правилам.</i>")
	}
	return b.String()
}

// progressBar — риск-метр «на глаз», чтобы вердикт читался мгновенно.
func progressBar(score int) string {
	const width = 10
	filled := score * width / 100
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func send(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeHTML
	msg.DisableWebPagePreview = true
	if _, err := bot.Send(msg); err != nil {
		log.Printf("send error: %v", err)
	}
}

// esc экранирует то, что пришло из LLM: без этого угловая скобка в тексте
// сломала бы HTML-разметку и Telegram отклонил бы сообщение целиком.
func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// loadDotEnv читает .env из рабочей директории или на уровень выше (запуск из bot/).
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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
