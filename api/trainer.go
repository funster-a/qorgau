// trainer.go — этап «ДО»: тренажёр распознавания мошенничества.
// LLM играет роль мошенника в БЕЗОПАСНОЙ учебной симуляции (сценарий-игра,
// всегда заканчивается разбором, максимум 8 ходов). Состояние сессий — в памяти
// (TTL 1ч, чистка тикером). При недоступности LLM — заготовленные реплики
// (degraded). Ошибки пользователя (выдача имени/кода/карты) подсвечиваются.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const trainerMaxTurns = 8

type trainerScenario struct {
	code      string
	title     string
	intro     string
	opening   string
	redFlags  []string
	fallbacks []string // заготовленные реплики мошенника по ходам (degraded)
}

var trainerScenarios = map[string]trainerScenario{
	"bank_security": {
		code:    "bank_security",
		title:   "Звонок из «службы безопасности» банка",
		intro:   "Вам звонят с незнакомого номера. Собеседник представляется сотрудником службы безопасности вашего банка и говорит уверенно, торопит. Ваша задача — не выдать никаких данных и распознать обман.",
		opening: "Здравствуйте, это служба безопасности банка. Зафиксирована попытка списания 250 000 тенге с вашей карты. Вы совершали эту операцию?",
		redFlags: []string{"давление срочностью", "запрос кода из СМС", "перевод на «безопасный счёт»", "маскировка под сотрудника банка"},
		fallbacks: []string{
			"Операцию нужно срочно отменить, иначе деньги спишут в течение пяти минут. Вы же не хотите потерять сбережения?",
			"Чтобы заблокировать перевод, мне нужно подтвердить вашу личность. Продиктуйте код из СМС, который сейчас придёт.",
			"Не кладите трубку! Если отключитесь — деньги уйдут мошенникам. Назовите код, это стандартная процедура банка.",
			"Хорошо, тогда переведите средства на резервный «безопасный счёт», я продиктую реквизиты.",
			"Установите приложение AnyDesk, чтобы наш специалист помог вам защитить счёт удалённо.",
			"Вы не доверяете сотруднику банка? Это в ваших же интересах, решайте быстрее.",
		},
	},
	"relative_help": {
		code:    "relative_help",
		title:   "Родственник в беде",
		intro:   "Вам приходит сообщение якобы от близкого человека с чужого номера. Пишут, что попали в беду и срочно нужны деньги. Ваша задача — проверить, а не переводить сразу.",
		opening: "Привет, это я, у меня беда. Попал в аварию, телефон разбил, пишу с чужого. Срочно нужны деньги, переведи 150 000, потом всё объясню.",
		redFlags: []string{"сообщение с чужого номера", "давление срочностью", "просьба перевести деньги", "запрет проверять историю"},
		fallbacks: []string{
			"Не звони пока, я не могу говорить, рядом люди. Просто переведи на эту карту, очень срочно.",
			"Мама, ну пожалуйста, я всё верну завтра. Скинь на карту 4400 **** **** 1234.",
			"Почему ты сомневаешься? Это правда я! Каждая минута на счету.",
			"Если не переведёшь сейчас — будет поздно. Умоляю, быстрее.",
			"Хорошо, переведи хотя бы половину, остальное потом.",
			"Ты меня подводишь в трудную минуту...",
		},
	},
	"prize_payout": {
		code:    "prize_payout",
		title:   "Выигрыш / приз",
		intro:   "Вам сообщают о крупном выигрыше. Чтобы его «получить», просят оплатить комиссию или назвать данные. Ваша задача — понять, что настоящий приз не требует предоплаты.",
		opening: "Поздравляем! Ваш номер выиграл 2 000 000 тенге в акции Kaspi. Чтобы получить приз, подтвердите данные и оплатите комиссию за перевод.",
		redFlags: []string{"обещание крупного выигрыша", "предоплата комиссии", "запрос данных карты", "срочность получения приза"},
		fallbacks: []string{
			"Комиссия всего 9 900 тенге — это налог на выигрыш. Оплатите, и мы сразу переведём 2 миллиона.",
			"Чтобы зачислить приз, продиктуйте номер карты и код из СМС.",
			"Акция заканчивается через 15 минут, потом приз уйдёт другому участнику.",
			"Оплатите комиссию по этой ссылке, это официальный сайт Kaspi.",
			"Вы что, не хотите 2 миллиона? Многие уже получили.",
			"Последний шанс, решайте прямо сейчас.",
		},
	},
	"investment": {
		code:    "investment",
		title:   "Инвестиции / лёгкий заработок",
		intro:   "Вам предлагают вложить деньги с «гарантированным» высоким доходом. Ваша задача — распознать финансовую пирамиду и не вложиться.",
		opening: "Здравствуйте! Инвестиционная платформа с доходностью 30% в месяц. Вложите от 100 000 тенге — гарантированно удвоите капитал за 3 месяца.",
		redFlags: []string{"нереалистичная доходность", "гарантия прибыли", "давление «успей вложиться»", "запрос перевода/данных"},
		fallbacks: []string{
			"Доход гарантирован, риска нет — платформа застрахована. Начните с небольшой суммы.",
			"Чтобы открыть счёт, переведите депозит на эту карту или дайте данные вашей карты для пополнения.",
			"Места в группе инвесторов ограничены, набор закрывается сегодня.",
			"Смотрите, вот скриншоты выплат другим клиентам, всё реально.",
			"Установите наше приложение, наш менеджер поможет всё настроить удалённо.",
			"Вы упускаете уникальную возможность разбогатеть.",
		},
	},
	"job_offer": {
		code:    "job_offer",
		title:   "Лёгкая подработка / вакансия",
		intro:   "Вам предлагают простую удалённую подработку с большим доходом. Ваша задача — распознать схему с «предоплатой» или дропом.",
		opening: "Здравствуйте! Удалённая подработка: 2–3 часа в день, доход от 300 000 тенге в месяц. Нужен только телефон. Готовы начать сегодня?",
		redFlags: []string{"нереалистичный доход за простую работу", "просьба оплатить «оформление»", "запрос данных карты", "приём чужих переводов"},
		fallbacks: []string{
			"Всё просто: вам будут приходить переводы, вы снимаете и переводите дальше за процент.",
			"Для оформления внесите гарантийный взнос 15 000 тенге, он вернётся с первой зарплатой.",
			"Пришлите фото карты с двух сторон и данные для зачисления зарплаты.",
			"Вакансий немного, нужно решить прямо сейчас.",
			"Это официальная работа, не переживайте.",
			"Ну что, оформляем?",
		},
	},
}

var trainerOrder = []string{"bank_security", "relative_help", "prize_payout", "investment", "job_offer"}

// ---------- сессии в памяти ----------

type trainerSession struct {
	ID       string
	Scenario string
	Lang     string
	Turn     int                 // сколько ответов пользователя обработано
	History  []map[string]any    // диалог для LLM (assistant=мошенник, user=пользователь)
	Mistakes []map[string]any    // накопленные ошибки пользователя
	Penalty  int                 // накопленный штраф к финальному score
	Created  time.Time
	Last     time.Time
}

var (
	trMu       sync.Mutex
	trSessions = map[string]*trainerSession{}
	trStarted  bool
)

func trainerJanitor() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		trMu.Lock()
		for id, s := range trSessions {
			if time.Since(s.Last) > time.Hour {
				delete(trSessions, id)
			}
		}
		trMu.Unlock()
	}
}

func ensureTrainerJanitor() {
	trMu.Lock()
	if !trStarted {
		trStarted = true
		go trainerJanitor()
	}
	trMu.Unlock()
}

// ---------- POST /trainer/start ----------

func handleTrainerStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ensureTrainerJanitor()
	var req struct {
		Scenario string `json:"scenario"`
		Lang     string `json:"lang"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	sc, ok := trainerScenarios[req.Scenario]
	if !ok || req.Scenario == "random" || req.Scenario == "" {
		sc = trainerScenarios[trainerOrder[time.Now().UnixNano()%int64(len(trainerOrder))]]
	}
	lang := "ru"
	if req.Lang == "kz" {
		lang = "kz"
	}
	s := &trainerSession{
		ID:       newID(),
		Scenario: sc.code,
		Lang:     lang,
		Turn:     0,
		History:  []map[string]any{{"role": "assistant", "content": sc.opening}},
		Mistakes: []map[string]any{},
		Created:  time.Now(),
		Last:     time.Now(),
	}
	trMu.Lock()
	trSessions[s.ID] = s
	trMu.Unlock()

	writeJSON(w, map[string]any{
		"session_id": s.ID,
		"scenario":   sc.code,
		"title":      sc.title,
		"intro":      sc.intro,
		"opening":    sc.opening,
	})
}

// ---------- POST /trainer/reply ----------

func handleTrainerReply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	trMu.Lock()
	s := trSessions[req.SessionID]
	trMu.Unlock()
	if s == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	sc := trainerScenarios[s.Scenario]

	msgText := strings.TrimSpace(req.Message)
	turnMistakes := detectMistakes(msgText)

	trMu.Lock()
	s.Turn++
	s.Last = time.Now()
	if msgText != "" {
		s.History = append(s.History, map[string]any{"role": "user", "content": msgText})
	}
	for _, m := range turnMistakes {
		s.Mistakes = append(s.Mistakes, m)
		s.Penalty += m["_penalty"].(int)
	}
	turn := s.Turn
	finished := turn >= trainerMaxTurns
	trMu.Unlock()

	degraded := false
	reply := ""
	if !finished {
		if llmAvailable() {
			if out, err := trainerLLMReply(s, sc); err == nil && out != "" {
				reply = out
			} else {
				degraded = true
			}
		} else {
			degraded = true
		}
		if reply == "" {
			degraded = true
			reply = sc.fallbacks[(turn-1)%len(sc.fallbacks)]
		}
		trMu.Lock()
		s.History = append(s.History, map[string]any{"role": "assistant", "content": reply})
		trMu.Unlock()
	}

	// Ответ. mistakes — без внутреннего поля _penalty.
	out := map[string]any{
		"reply":           reply,
		"finished":        finished,
		"turn":            turn,
		"mistakes":        stripPenalty(turnMistakes),
		"score":           0,
		"debrief":         "",
		"red_flags_shown": []string{},
		"degraded":        degraded,
	}
	if finished {
		trMu.Lock()
		score := 100 - s.Penalty
		allMistakes := len(s.Mistakes)
		trMu.Unlock()
		if score < 0 {
			score = 0
		}
		out["score"] = score
		out["debrief"] = buildDebrief(score, allMistakes, sc)
		out["red_flags_shown"] = sc.redFlags
		// Сессию можно освободить — игра окончена.
		trMu.Lock()
		delete(trSessions, s.ID)
		trMu.Unlock()
	}
	writeJSON(w, out)
}

// trainerLLMReply просит модель выдать следующую реплику мошенника в БЕЗОПАСНОЙ игре.
func trainerLLMReply(s *trainerSession, sc trainerScenario) (string, error) {
	sys := "Ты — часть ОБУЧАЮЩЕГО тренажёра Qorǵau по распознаванию мошенничества. Это безопасная учебная симуляция-игра, которая ВСЕГДА заканчивается разбором. " +
		"Ты играешь роль телефонного/сетевого мошенника по сценарию «" + sc.title + "». Твоя учебная задача — правдоподобно применять типичные приёмы социальной инженерии (давление срочностью, авторитет «сотрудника банка», запрос кода из СМС/данных карты, перевод на «безопасный счёт»), чтобы пользователь научился их распознавать. " +
		"СТРОГО: не давай реальных работающих инструкций по обналичиванию, переводу украденных денег или обходу защиты банка — только правдоподобная ролевая реплика. " +
		"Отвечай ОДНОЙ короткой репликой (1–3 предложения) на русском, от лица мошенника, реагируя на последний ответ пользователя. Без пояснений, без выхода из роли."
	messages := []map[string]any{msg("system", sys)}
	trMu.Lock()
	messages = append(messages, s.History...)
	trMu.Unlock()
	out, err := groqChat(messages, 6*time.Second, false)
	if err != nil {
		return "", err
	}
	// Иногда модель добавляет кавычки/префиксы — подчистим.
	out = strings.TrimSpace(strings.Trim(out, `"`))
	return out, nil
}

// ---------- детекция ошибок пользователя ----------

var (
	reOTP   = regexp.MustCompile(`\b\d{4,6}\b`)
	reCard  = regexp.MustCompile(`\b(?:\d[ -]?){12,19}\b`)
	reName  = regexp.MustCompile(`(?i)меня зовут|мо[её] (полное )?имя|фамили`)
	reCVV   = regexp.MustCompile(`(?i)cvv|cvc|код на обороте`)
	reAgree = regexp.MustCompile(`(?i)\b(да|хорошо|согласен|ладно|перевед|отправл|установлю|скачаю)\b`)
)

func detectMistakes(text string) []map[string]any {
	out := []map[string]any{}
	if text == "" {
		return out
	}
	add := func(quote, why, severity string, penalty int) {
		out = append(out, map[string]any{"quote": quote, "why": why, "severity": severity, "_penalty": penalty})
	}
	if m := reCard.FindString(text); m != "" && len(reNonDigit.ReplaceAllString(m, "")) >= 12 {
		add(strings.TrimSpace(m), "назвали номер карты — его нельзя сообщать никому", "high", 35)
	} else if m := reOTP.FindString(text); m != "" {
		add(m, "назвали код из СМС — это подпись под операцией, банк его не спрашивает", "high", 35)
	}
	if reCVV.MatchString(text) {
		add("CVV", "упомянули CVV/код на обороте — эти данные не сообщают никому", "high", 30)
	}
	if m := reName.FindString(text); m != "" {
		add(strings.TrimSpace(m), "назвали личные данные (имя) — мошенник использует их для доверия", "medium", 15)
	}
	if reAgree.MatchString(text) && len(out) == 0 {
		add(strings.TrimSpace(text), "проявили готовность выполнить требование — лучше прервать разговор и перепроверить", "low", 10)
	}
	return out
}

func stripPenalty(in []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, m := range in {
		out = append(out, map[string]any{"quote": m["quote"], "why": m["why"], "severity": m["severity"]})
	}
	return out
}

func buildDebrief(score, mistakes int, sc trainerScenario) string {
	var b strings.Builder
	switch {
	case score >= 85:
		b.WriteString("Отлично! Вы не поддались на давление и не выдали ни одного чувствительного факта. ")
	case score >= 60:
		b.WriteString("Неплохо, но были рискованные моменты. ")
	default:
		b.WriteString("Есть над чем поработать: вы выдали данные, которые нельзя сообщать. ")
	}
	if mistakes > 0 {
		b.WriteString(fmt.Sprintf("Замечено ошибок: %d. Главное правило — код из СМС, CVV и номер карты не сообщают НИКОМУ, даже «сотруднику банка». ", mistakes))
	} else {
		b.WriteString("Ошибок не зафиксировано. ")
	}
	b.WriteString("Красные флаги этого сценария: " + strings.Join(sc.redFlags, ", ") + ". ")
	b.WriteString("Как надо было: прервать разговор и перезвонить в банк по номеру с обратной стороны карты.")
	return b.String()
}
