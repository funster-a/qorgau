// live.go — этап «ВО ВРЕМЯ»: POST /live/hint. Живой суфлёр во время звонка.
// Приоритет — скорость (≤1.5с, «реальное время»): СНАЧАЛА мгновенная эвристика
// по маркерам без сети. LLM-уточнение опционально и включается только флагом
// LIVE_LLM=1 с жёстким таймаутом 1.1с — чтобы гарантированно укладываться в
// бюджет и не жечь квоту. Накопительный риск копится по сессии.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

type liveMarker struct {
	re     *regexp.Regexp
	level  string // danger | warn
	weight int
	title  string
	hint   string
	manip  string
}

var liveMarkers = []liveMarker{
	{regexp.MustCompile(`(?i)код из смс|код из смс|назовите код|продиктуйте код|сообщите код|скажите код|одноразов\w* код|otp|код подтвержд`), "danger", 45,
		"Просят код из СМС", "Немедленно кладите трубку. Код из СМС — это подпись под операцией, банк его НИКОГДА не спрашивает.", "запрос OTP/кода из СМС"},
	{regexp.MustCompile(`(?i)cvv|cvc|три цифры|номер карты|данные карты|срок действия карты`), "danger", 40,
		"Просят данные карты", "Не называйте номер карты, срок и CVV. Эти данные не сообщают никому.", "запрос данных карты"},
	{regexp.MustCompile(`(?i)безопасн\w* сч[её]т|защищ[её]нн\w* сч[её]т|резервн\w* сч[её]т|переведите деньги|переведите средства|перевести на счет`), "danger", 40,
		"Просят перевести деньги", "«Безопасного счёта» не существует. Никаких переводов — это увод денег.", "перевод на «безопасный счёт»"},
	{regexp.MustCompile(`(?i)anydesk|teamviewer|rustdesk|установите приложение|удал[её]нн\w* доступ|скачайте программу`), "danger", 40,
		"Просят установить приложение", "Не устанавливайте никаких программ. Это даст мошеннику доступ к вашему телефону и банку.", "запрос удалённого доступа"},
	{regexp.MustCompile(`(?i)служба безопасност|сотрудник банка|из банка|финмониторинг`), "warn", 20,
		"Представляются банком", "Положите трубку и перезвоните в банк сами — по номеру с обратной стороны карты.", "маскировка под сотрудника банка"},
	{regexp.MustCompile(`(?i)полици|прокуратур|следовател|кнб|уголовн\w*|росфинмониторинг|афм`), "warn", 25,
		"Представляются органами", "Настоящие органы не решают вопросы по телефону и не просят переводов. Это запугивание.", "маскировка под правоохранителей"},
	{regexp.MustCompile(`(?i)срочно|немедленно|прямо сейчас|в течение|поспеши|быстрее|иначе|последн\w* шанс`), "warn", 15,
		"Давят срочностью", "Спешка — главный приём мошенника. Возьмите паузу, положите трубку.", "давление срочностью"},
	{regexp.MustCompile(`(?i)не кладите трубку|оставайтесь на связи|не отключайтесь|никому не говорите|это секрет`), "warn", 25,
		"Просят не прерывать разговор", "Именно поэтому и нужно положить трубку. Мошенник боится, что вы перепроверите.", "изоляция жертвы"},
	{regexp.MustCompile(`(?i)заблокир|блокировк|спишут|списани|подозрительн\w* операци|попытка вход`), "warn", 20,
		"Пугают блокировкой/списанием", "Это провокация страха. Проверьте счёт только через официальное приложение.", "запугивание блокировкой"},
}

// ---------- накопительный риск по сессии ----------

var (
	liveMu       sync.Mutex
	liveSessions = map[string]int{}
	liveJanitor  bool
	liveTouch    = map[string]time.Time{}
)

func ensureLiveJanitor() {
	liveMu.Lock()
	if !liveJanitor {
		liveJanitor = true
		go func() {
			t := time.NewTicker(15 * time.Minute)
			for range t.C {
				liveMu.Lock()
				for id, ts := range liveTouch {
					if time.Since(ts) > time.Hour {
						delete(liveSessions, id)
						delete(liveTouch, id)
					}
				}
				liveMu.Unlock()
			}
		}()
	}
	liveMu.Unlock()
}

// scorePhrase прогоняет фразу по маркерам: возвращает уровень, заголовок, подсказку,
// список манипуляций и вес для накопления.
func scorePhrase(phrase string) (level, title, hint string, manips []string, weight int) {
	level = "ok"
	manips = []string{}
	best := -1
	for _, m := range liveMarkers {
		if !m.re.MatchString(phrase) {
			continue
		}
		manips = append(manips, m.manip)
		weight += m.weight
		// приоритет: danger важнее warn; при равном — больший вес.
		rank := m.weight
		if m.level == "danger" {
			rank += 100
		}
		if rank > best {
			best = rank
			level = m.level
			title = m.title
			hint = m.hint
		}
	}
	if title == "" {
		title = "Пока явных угроз нет"
		hint = "Держите ухо востро: не называйте коды и данные карты, не переводите деньги по просьбе звонящего."
	}
	return
}

func handleLiveHint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ensureLiveJanitor()
	var req struct {
		SessionID string   `json:"session_id"`
		Phrase    string   `json:"phrase"`
		History   []string `json:"history"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	level, title, hint, manips, weight := scorePhrase(req.Phrase)

	// Накопительный риск. Если есть session_id — копим по сессии. Иначе — считаем
	// по переданной истории + текущей фразе (stateless-режим).
	cumulative := weight
	if req.SessionID != "" {
		liveMu.Lock()
		prev := liveSessions[req.SessionID]
		cumulative = prev + weight
		if cumulative > 100 {
			cumulative = 100
		}
		liveSessions[req.SessionID] = cumulative
		liveTouch[req.SessionID] = time.Now()
		liveMu.Unlock()
	} else {
		for _, h := range req.History {
			_, _, _, _, wq := scorePhrase(h)
			cumulative += wq
		}
		if cumulative > 100 {
			cumulative = 100
		}
	}

	// Опциональное LLM-уточнение — только по флагу и с жёстким бюджетом 1.1с.
	if os.Getenv("LIVE_LLM") == "1" && llmAvailable() {
		if extra := liveLLMRefine(req.Phrase, 1100*time.Millisecond); extra != "" {
			hint = hint + " " + extra
		}
	}

	writeJSON(w, map[string]any{
		"level":           level,
		"title":           title,
		"hint":            hint,
		"manipulations":   manips,
		"cumulative_risk": cumulative,
	})
}

// liveLLMRefine возвращает короткое доп. предупреждение или "" (по таймауту/ошибке).
func liveLLMRefine(phrase string, budget time.Duration) string {
	ch := make(chan string, 1)
	go func() {
		out, err := groqChat([]map[string]any{
			msg("system", "Ты — суфлёр во время звонка. По фразе звонящего дай ОДНО короткое (до 12 слов) предупреждение пользователю, что делать. Без вступлений."),
			msg("user", phrase),
		}, budget, false)
		if err != nil {
			ch <- ""
			return
		}
		ch <- out
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(budget + 100*time.Millisecond):
		return ""
	}
}
