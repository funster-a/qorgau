// help.go — этап «ПОСЛЕ»: юридическая первая помощь.
//   POST /help/chat   — ИИ-юрист простым языком (Groq) + чёткие шаги + контакты
//   GET  /help/places — ближайшие отделения полиции/ЦОН/юрпомощь (гаверсинус)
// Контакты — из db/contacts_kz.json (только общеизвестные номера). Точки — из
// db/places_kz.json. Сессии чата — в памяти (TTL 1ч). При недоступности LLM —
// шаги строятся детерминированно по ситуации (degraded).
package main

import (
	"encoding/json"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- локальные данные ----------

type contact struct {
	Name  string `json:"name"`
	Phone string `json:"phone"`
	Kind  string `json:"kind"`
	Note  string `json:"note,omitempty"`
}

type place struct {
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	Address string  `json:"address"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Phone   string  `json:"phone"`
}

var (
	helpDataOnce sync.Once
	contactsAll  []contact
	placesAll    []place
)

func loadHelpData() {
	helpDataOnce.Do(func() {
		if b := readFirst(os.Getenv("CONTACTS_PATH"), "db/contacts_kz.json", "../db/contacts_kz.json"); b != nil {
			var doc struct {
				Contacts []contact `json:"contacts"`
			}
			json.Unmarshal(b, &doc)
			contactsAll = doc.Contacts
		}
		if b := readFirst(os.Getenv("PLACES_PATH"), "db/places_kz.json", "../db/places_kz.json"); b != nil {
			var doc struct {
				Places []place `json:"places"`
			}
			json.Unmarshal(b, &doc)
			placesAll = doc.Places
		}
	})
}

func readFirst(paths ...string) []byte {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	return nil
}

// ---------- сессии чата (память, TTL 1ч) ----------

type helpSession struct {
	History []map[string]any
	Last    time.Time
}

var (
	helpMu       sync.Mutex
	helpSessions = map[string]*helpSession{}
	helpJanitor  bool
)

func ensureHelpJanitor() {
	helpMu.Lock()
	if !helpJanitor {
		helpJanitor = true
		go func() {
			t := time.NewTicker(10 * time.Minute)
			for range t.C {
				helpMu.Lock()
				for id, s := range helpSessions {
					if time.Since(s.Last) > time.Hour {
						delete(helpSessions, id)
					}
				}
				helpMu.Unlock()
			}
		}()
	}
	helpMu.Unlock()
}

// ---------- POST /help/chat ----------

type helpSituation struct {
	LostMoney    bool `json:"lost_money"`
	GaveOTP      bool `json:"gave_otp"`
	GaveCard     bool `json:"gave_card"`
	InstalledApp bool `json:"installed_app"`
}

func handleHelpChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	loadHelpData()
	ensureHelpJanitor()
	var req struct {
		SessionID string        `json:"session_id"`
		Message   string        `json:"message"`
		Situation helpSituation `json:"situation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// Сессия
	sid := req.SessionID
	if sid == "" {
		sid = newID()
	}
	helpMu.Lock()
	s := helpSessions[sid]
	if s == nil {
		s = &helpSession{}
		helpSessions[sid] = s
	}
	if strings.TrimSpace(req.Message) != "" {
		s.History = append(s.History, msg("user", req.Message))
	}
	s.Last = time.Now()
	histSnapshot := append([]map[string]any(nil), s.History...)
	helpMu.Unlock()

	steps := buildHelpSteps(req.Situation)
	contacts := relevantContacts(req.Situation)

	reply := ""
	degraded := false
	if llmAvailable() {
		if out, err := helpLLM(histSnapshot); err == nil && out != "" {
			reply = out
		} else {
			degraded = true
		}
	} else {
		degraded = true
	}
	if reply == "" {
		degraded = true
		reply = scriptedHelpReply(req.Situation)
	}
	helpMu.Lock()
	if s2 := helpSessions[sid]; s2 != nil {
		s2.History = append(s2.History, msg("assistant", reply))
	}
	helpMu.Unlock()

	writeJSON(w, map[string]any{
		"session_id": sid,
		"reply":      reply,
		"steps":      steps,
		"contacts":   contacts,
		"degraded":   degraded,
	})
}

func helpLLM(history []map[string]any) (string, error) {
	sys := "Ты — ИИ-юрист первой помощи Qorǵau для жертв мошенничества в Казахстане. Отвечай простым, спокойным, человечным языком, коротко (3–6 предложений). " +
		"Приоритеты по КЗ: 1) немедленно заблокировать карту через официальное приложение банка или звонок на номер с обратной стороны карты; 2) позвонить в полицию 102 и подать заявление; 3) обратиться в банк письменно (чарджбэк/спор по операции); 4) при финансовом мошенничестве — обращение в АФМ (Агентство по финмониторингу) через egov.kz. " +
		"Не давай ложных гарантий возврата денег. Не выдумывай номера телефонов и названия. Не проси у пользователя коды, пароли и данные карты."
	messages := []map[string]any{msg("system", sys)}
	messages = append(messages, history...)
	return groqChat(messages, 8*time.Second, false)
}

// buildHelpSteps — детерминированные шаги по ситуации (надёжнее, чем структура от LLM).
func buildHelpSteps(sit helpSituation) []map[string]any {
	order := 0
	steps := []map[string]any{}
	add := func(title, detail, urgency, done string) {
		order++
		steps = append(steps, map[string]any{
			"order": order, "title": title, "detail": detail,
			"urgency": urgency, "done_hint": done,
		})
	}
	if sit.GaveCard || sit.GaveOTP || sit.LostMoney {
		add("Заблокируйте карту", "Немедленно заблокируйте карту в официальном приложении банка или позвоните на номер с обратной стороны карты.", "now", "Карта заблокирована, новые операции невозможны")
	}
	if sit.LostMoney {
		add("Сообщите в банк о мошеннической операции", "Потребуйте зафиксировать обращение и открыть спор по операции (чарджбэк). Запишите номер обращения.", "now", "Есть номер обращения в банке")
	}
	if sit.InstalledApp {
		add("Удалите приложение удалённого доступа", "Удалите AnyDesk/TeamViewer и подобное, включите авиарежим, а лучше выключите телефон до проверки. Смените пароли с другого устройства.", "now", "Приложение удалено, доступ закрыт")
	}
	if sit.GaveOTP || sit.GaveCard {
		add("Смените пароли и отзовите доступы", "Смените пароль интернет-банка и почты с чистого устройства. Проверьте активные сессии и подключённые приложения.", "today", "Пароли сменены")
	}
	add("Подайте заявление в полицию", "Позвоните 102 или обратитесь в ближайшее отделение полиции/ЦОН. Возьмите с собой все скриншоты, СМС и реквизиты.", "today", "Заявление зарегистрировано, есть талон/номер")
	add("Соберите доказательства", "Сохраните переписку, скриншоты, номера, чеки о переводах. Ничего не удаляйте — это понадобится для разбирательства.", "today", "Доказательства собраны")
	if sit.LostMoney {
		add("Обратитесь в АФМ", "При финансовом мошенничестве подайте обращение в Агентство по финмониторингу через egov.kz.", "week", "Обращение в АФМ отправлено")
	}
	return steps
}

func relevantContacts(sit helpSituation) []contact {
	if len(contactsAll) == 0 {
		return []contact{}
	}
	return contactsAll // набор невелик и весь релевантен; фильтровать нет смысла
}

func scriptedHelpReply(sit helpSituation) string {
	var b strings.Builder
	b.WriteString("Главное — действуйте спокойно и по шагам. ")
	if sit.GaveCard || sit.GaveOTP || sit.LostMoney {
		b.WriteString("Сейчас же заблокируйте карту через приложение банка или звонок на номер с обратной стороны карты. ")
	}
	if sit.LostMoney {
		b.WriteString("Сообщите в банк о мошеннической операции и потребуйте открыть спор (чарджбэк), запишите номер обращения. ")
	}
	if sit.InstalledApp {
		b.WriteString("Удалите приложение удалённого доступа и смените пароли с другого устройства. ")
	}
	b.WriteString("Затем позвоните 102 и подайте заявление, сохранив все доказательства. Возврат денег не гарантирован, но быстрые действия повышают шансы.")
	return b.String()
}

// ---------- GET /help/places ----------

func handleHelpPlaces(w http.ResponseWriter, r *http.Request) {
	loadHelpData()
	q := r.URL.Query()
	lat := parseFloat(q.Get("lat"))
	lon := parseFloat(q.Get("lon"))
	kind := strings.TrimSpace(q.Get("kind"))

	type placeOut struct {
		Name       string  `json:"name"`
		Kind       string  `json:"kind"`
		Address    string  `json:"address"`
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
		DistanceKM float64 `json:"distance_km"`
		Phone      string  `json:"phone"`
	}
	out := []placeOut{}
	for _, p := range placesAll {
		if kind != "" && p.Kind != kind {
			continue
		}
		dist := -1.0
		if lat != 0 || lon != 0 {
			dist = math.Round(haversine(lat, lon, p.Lat, p.Lon)*10) / 10
		}
		out = append(out, placeOut{
			Name: p.Name, Kind: p.Kind, Address: p.Address,
			Lat: p.Lat, Lon: p.Lon, DistanceKM: dist, Phone: p.Phone,
		})
	}
	// сортировка по расстоянию, если координаты заданы
	if lat != 0 || lon != 0 {
		for i := 1; i < len(out); i++ {
			for j := i; j > 0 && out[j].DistanceKM < out[j-1].DistanceKM; j-- {
				out[j], out[j-1] = out[j-1], out[j]
			}
		}
	}
	writeJSON(w, out)
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// haversine — расстояние между двумя точками на Земле в километрах.
func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return R * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}
