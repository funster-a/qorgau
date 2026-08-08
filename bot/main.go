// Qorǵau Telegram-бот. Тонкий клиент: шлёт текст в API /analyze и красиво выводит вердикт.
// Плюс подписка на оповещения: горутина поллит /campaigns/active и рассылает
// предупреждение подписчикам при новой волне мошенничества.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
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
	// Доп. поля киллер-анализаторов (image/audio) — см. docs/API.md.
	ExtractedText string `json:"extracted_text"` // текст, распознанный на скриншоте
	UISpoofing    bool   `json:"ui_spoofing"`    // похоже на поддельный интерфейс
	Transcript    string `json:"transcript"`     // расшифровка голосового
}

type campaign struct {
	ID     string `json:"id"`
	Scheme string `json:"scheme"`
	Title  string `json:"title"`
	Peak   int    `json:"peak"`
	Status string `json:"status"`
}

const helpText = `🛡️ <b>Qorǵau</b> — проверка сообщений на мошенничество.

Пришлите мне что угодно подозрительное — я разберу за пару секунд и объясню, что не так:
• 💬 <b>текст</b> — СМС или скопированную переписку
• 📸 <b>скриншот</b> переписки или сайта
• 🎙 <b>голосовое</b> или запись звонка

Команды:
/help — эта справка
/campaigns — какие схемы мошенничества сейчас на подъёме
/subscribe — получать предупреждения о новых волнах мошенничества
/unsubscribe — отключить предупреждения

👨‍👩‍👧 <b>Защита близкого</b> (для пожилых родителей и др.):
/guardian — я опекун: получить код привязки
/protect QG-XXXX — я подопечный: ввести код опекуна
/myprotection — кого я защищаю и кто защищает меня

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
	go guardAlertLoop(bot)

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

	// Скриншот переписки/сайта → vision-анализ. Берём фото макс. размера.
	if len(m.Photo) > 0 {
		handlePhoto(bot, m)
		return
	}
	// Голосовое или аудио-запись звонка → расшифровка + анализ текста.
	if m.Voice != nil || m.Audio != nil {
		handleVoice(bot, m)
		return
	}

	// Прочие вложения без текста разобрать нечем — подсказываем, что делать.
	if text == "" {
		send(bot, chatID, "Пришлите <b>текст</b>, <b>скриншот</b> переписки или <b>голосовое</b> — я всё разберу.")
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
	case text == "/guardian":
		handleGuardian(bot, chatID)
		return
	case text == "/protect" || strings.HasPrefix(text, "/protect "):
		handleProtect(bot, chatID, strings.TrimSpace(strings.TrimPrefix(text, "/protect")))
		return
	case text == "/myprotection":
		handleMyProtection(bot, chatID)
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
	maybeAlertGuardians(chatID, res)
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

// ---------- медиа: фото и голос ----------

// mediaTimeout больше текстового (15с): vision и whisper считаются дольше.
const mediaTimeout = 30 * time.Second

// handlePhoto: скачивает фото макс. размера из Telegram и гонит его в /analyze/image.
func handlePhoto(bot *tgbotapi.BotAPI, m *tgbotapi.Message) {
	chatID := m.Chat.ID
	bot.Send(tgbotapi.NewChatAction(chatID, tgbotapi.ChatUploadPhoto))
	send(bot, chatID, "🔎 Анализирую изображение…")

	// Последний элемент m.Photo — версия максимального разрешения.
	photo := m.Photo[len(m.Photo)-1]
	url, err := bot.GetFileDirectURL(photo.FileID)
	if err != nil {
		log.Printf("photo file url error: %v", err)
		send(bot, chatID, "⚠️ Не удалось получить изображение из Telegram. Попробуйте ещё раз.")
		return
	}
	data, err := downloadFile(url, 5*1024*1024)
	if err != nil {
		log.Printf("photo download error: %v", err)
		send(bot, chatID, "⚠️ Не удалось загрузить изображение (слишком большое или сервис недоступен).")
		return
	}
	dataURI := "data:" + mimeFromURL(url) + ";base64," + base64.StdEncoding.EncodeToString(data)

	res, err := analyzeImage(dataURI)
	if err != nil {
		log.Printf("analyze image error: %v", err)
		send(bot, chatID, "⚠️ Не удалось распознать изображение — сервис недоступен. Попробуйте позже.")
		return
	}
	send(bot, chatID, format(res))
	maybeAlertGuardians(chatID, res)
}

// handleVoice: скачивает голосовое/аудио и отправляет в /analyze/audio (multipart).
func handleVoice(bot *tgbotapi.BotAPI, m *tgbotapi.Message) {
	chatID := m.Chat.ID
	bot.Send(tgbotapi.NewChatAction(chatID, tgbotapi.ChatTyping))
	send(bot, chatID, "🎙 Слушаю запись…")

	var fileID string
	switch {
	case m.Voice != nil:
		fileID = m.Voice.FileID
	case m.Audio != nil:
		fileID = m.Audio.FileID
	}
	url, err := bot.GetFileDirectURL(fileID)
	if err != nil {
		log.Printf("voice file url error: %v", err)
		send(bot, chatID, "⚠️ Не удалось получить запись из Telegram. Попробуйте ещё раз.")
		return
	}
	data, err := downloadFile(url, 10*1024*1024)
	if err != nil {
		log.Printf("voice download error: %v", err)
		send(bot, chatID, "⚠️ Не удалось загрузить запись (слишком большая или сервис недоступен).")
		return
	}

	res, err := analyzeAudio(data, "voice.ogg")
	if err != nil {
		log.Printf("analyze audio error: %v", err)
		send(bot, chatID, "⚠️ Не удалось распознать запись — сервис недоступен. Попробуйте позже.")
		return
	}
	// Сначала показываем расшифровку — пользователь видит, что именно услышала модель.
	if t := strings.TrimSpace(res.Transcript); t != "" {
		send(bot, chatID, "🎙 Распознал: «"+esc(clip(t, 3500))+"»")
	}
	send(bot, chatID, format(res))
	maybeAlertGuardians(chatID, res)
}

// analyzeImage — POST base64-картинки в /analyze/image (таймаут mediaTimeout).
func analyzeImage(imageBase64 string) (analyzeResp, error) {
	body, _ := json.Marshal(map[string]string{"image_base64": imageBase64, "channel": "tg"})
	client := http.Client{Timeout: mediaTimeout}
	resp, err := client.Post(apiURL+"/analyze/image", "application/json", bytes.NewReader(body))
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

// analyzeAudio — POST аудио в /analyze/audio как multipart/form-data (поле "audio").
func analyzeAudio(data []byte, filename string) (analyzeResp, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("audio", filename)
	if err != nil {
		return analyzeResp{}, err
	}
	if _, err := part.Write(data); err != nil {
		return analyzeResp{}, err
	}
	w.WriteField("channel", "tg")
	if err := w.Close(); err != nil {
		return analyzeResp{}, err
	}
	client := http.Client{Timeout: mediaTimeout}
	resp, err := client.Post(apiURL+"/analyze/audio", w.FormDataContentType(), &buf)
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

// downloadFile качает файл по URL с жёстким лимитом размера (защита от OOM).
func downloadFile(url string, limit int64) ([]byte, error) {
	client := http.Client{Timeout: mediaTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download http %d", resp.StatusCode)
	}
	// Читаем на 1 байт больше лимита, чтобы поймать превышение.
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

// mimeFromURL угадывает MIME по расширению файла из Telegram-URL.
// Для Telegram фото по умолчанию — image/jpeg.
func mimeFromURL(u string) string {
	ext := strings.ToLower(filepath.Ext(u))
	if i := strings.IndexAny(ext, "?#"); i >= 0 { // отрезаем query/fragment, если есть
		ext = ext[:i]
	}
	switch ext {
	case ".png":
		return "image/png"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	default:
		return "image/jpeg"
	}
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
	if r.UISpoofing {
		b.WriteString("⚠️ <b>Похоже на поддельный интерфейс</b> банка/госоргана.\n")
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

// clip обрезает длинную строку по рунам (расшифровка/распознанный текст могут
// не влезть в лимит Telegram 4096 симв.), добавляя многоточие.
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// ---------- защита близкого (опекун ↔ подопечный) ----------

// handleGuardian: пользователь-опекун получает код привязки, который показывает
// подопечному. Тот вводит его командой /protect QG-XXXX.
func handleGuardian(bot *tgbotapi.BotAPI, chatID int64) {
	code, ttl, err := guardLink(chatID)
	if err != nil {
		log.Printf("guard link error: %v", err)
		send(bot, chatID, "⚠️ Не удалось создать код привязки. Попробуйте позже.")
		return
	}
	send(bot, chatID, fmt.Sprintf(`🔗 <b>Код привязки: <code>%s</code></b>

Передайте его близкому, которого хотите защитить. Пусть он отправит мне команду:
<code>/protect %s</code>

Код действует %d минут. После привязки я предупрежу вас, если на близкого пойдёт атака мошенников.`, esc(code), esc(code), ttl/60))
}

// handleProtect: подопечный вводит код опекуна → создаётся связь.
func handleProtect(bot *tgbotapi.BotAPI, chatID int64, code string) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		send(bot, chatID, "Укажите код опекуна: <code>/protect QG-1234</code>\nКод даёт человек, который будет вас защищать (см. /guardian).")
		return
	}
	ok, errMsg, err := guardConfirm(code, chatID)
	if err != nil {
		log.Printf("guard confirm error: %v", err)
		send(bot, chatID, "⚠️ Не удалось привязать. Попробуйте позже.")
		return
	}
	if !ok {
		msg := "Код неверный или истёк. Попросите опекуна создать новый через /guardian."
		if errMsg == "cannot_link_self" {
			msg = "Нельзя привязать самого себя. Код должен создать другой человек (опекун)."
		}
		send(bot, chatID, "❌ "+msg)
		return
	}
	send(bot, chatID, "✅ Готово! Теперь ваш опекун получит предупреждение, если я замечу атаку мошенников на вас. Ваши сообщения при этом опекуну <b>не</b> пересылаются — только факт угрозы.")
}

// handleMyProtection: кого защищаю / кто защищает меня.
func handleMyProtection(bot *tgbotapi.BotAPI, chatID int64) {
	wards, guardians, err := guardLinks(chatID)
	if err != nil {
		send(bot, chatID, "⚠️ Не удалось получить данные. Попробуйте позже.")
		return
	}
	var b bytes.Buffer
	b.WriteString("👨‍👩‍👧 <b>Ваша защита</b>\n\n")
	if len(wards) > 0 {
		fmt.Fprintf(&b, "Вы защищаете (%d): я предупрежу вас об атаке на этих людей.\n", len(wards))
	} else {
		b.WriteString("Вы пока никого не защищаете. Станьте опекуном: /guardian\n")
	}
	if len(guardians) > 0 {
		fmt.Fprintf(&b, "\nВас защищают (%d): им придёт сигнал, если на вас пойдёт атака.\n", len(guardians))
	} else {
		b.WriteString("\nВас пока никто не защищает. Попросите близкого дать код (/guardian) и введите /protect КОД.\n")
	}
	send(bot, chatID, b.String())
}

// maybeAlertGuardians: при высоком риске просим API создать алерт опекунам
// подопечного. API сам находит опекунов; если их нет — ничего не создаётся.
func maybeAlertGuardians(chatID int64, res analyzeResp) {
	if res.RiskLevel != "high" {
		return
	}
	if err := guardAlert(chatID, res.SchemeTitle, res.RiskScore); err != nil {
		log.Printf("guard alert error: %v", err)
	}
}

// guardAlertLoop поллит недоставленные алерты и рассылает опекунам, затем ack.
func guardAlertLoop(bot *tgbotapi.BotAPI) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		alerts, err := fetchGuardAlerts()
		if err != nil {
			log.Printf("guard alerts poll error: %v", err)
		}
		delivered := []string{}
		for _, a := range alerts {
			msg := fmt.Sprintf(`⚠️ <b>Ваш близкий под атакой мошенников</b>

Тип угрозы: %s
Оценка риска: %d/100

Позвоните ему прямо сейчас и попросите ничего не переводить и не называть коды из СМС. Ради приватности содержание его переписки мы не показываем.`, esc(a.SchemeTitle), a.RiskScore)
			m := tgbotapi.NewMessage(a.GuardianChatID, msg)
			m.ParseMode = tgbotapi.ModeHTML
			m.DisableWebPagePreview = true
			if _, err := bot.Send(m); err != nil {
				log.Printf("guard alert → %d: %v", a.GuardianChatID, err)
			}
			delivered = append(delivered, a.ID)
			time.Sleep(50 * time.Millisecond)
		}
		if len(delivered) > 0 {
			if err := ackGuardAlerts(delivered); err != nil {
				log.Printf("guard alerts ack error: %v", err)
			}
		}
		<-t.C
	}
}

// ---------- HTTP-обёртки для /guard/* ----------

type guardAlertItem struct {
	ID             string `json:"id"`
	GuardianChatID int64  `json:"guardian_chat_id"`
	SchemeTitle    string `json:"scheme_title"`
	RiskScore      int    `json:"risk_score"`
}

func guardLink(chatID int64) (string, int, error) {
	var out struct {
		Code         string `json:"code"`
		ExpiresInSec int    `json:"expires_in_sec"`
	}
	if err := postJSON("/guard/link", map[string]any{"guardian_chat_id": chatID}, false, &out); err != nil {
		return "", 0, err
	}
	return out.Code, out.ExpiresInSec, nil
}

func guardConfirm(code string, wardChatID int64) (bool, string, error) {
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := postJSON("/guard/confirm", map[string]any{"code": code, "ward_chat_id": wardChatID}, false, &out); err != nil {
		return false, "", err
	}
	return out.OK, out.Error, nil
}

func guardLinks(chatID int64) (wards, guardians []map[string]any, err error) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/guard/links?chat_id=%d", apiURL, chatID), nil)
	client := http.Client{Timeout: 8 * time.Second}
	resp, e := client.Do(req)
	if e != nil {
		return nil, nil, e
	}
	defer resp.Body.Close()
	var out struct {
		Wards     []map[string]any `json:"wards"`
		Guardians []map[string]any `json:"guardians"`
	}
	if e := json.NewDecoder(resp.Body).Decode(&out); e != nil {
		return nil, nil, e
	}
	return out.Wards, out.Guardians, nil
}

func guardAlert(wardChatID int64, schemeTitle string, riskScore int) error {
	return postJSON("/guard/alert", map[string]any{
		"ward_chat_id": wardChatID, "scheme_title": schemeTitle, "risk_score": riskScore,
	}, true, nil)
}

func fetchGuardAlerts() ([]guardAlertItem, error) {
	req, _ := http.NewRequest(http.MethodGet, apiURL+"/guard/alerts", nil)
	if botAPIKey != "" {
		req.Header.Set("X-Bot-Key", botAPIKey)
	}
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api http %d", resp.StatusCode)
	}
	var out []guardAlertItem
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func ackGuardAlerts(ids []string) error {
	return postJSON("/guard/alerts/ack", map[string]any{"ids": ids}, true, nil)
}

// postJSON — POST JSON на API; botKey добавляет X-Bot-Key; out (если не nil) декодит ответ.
func postJSON(path string, payload any, botKey bool, out any) error {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, apiURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if botKey && botAPIKey != "" {
		req.Header.Set("X-Bot-Key", botAPIKey)
	}
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("api http %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
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
