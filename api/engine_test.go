// engine_test.go — замер точности классификации на engine/testset.json (KPI-2).
//
//	go test -v -run TestHeuristicAccuracy          — фолбэк-эвристика (порог 0.70)
//	GROQ_EVAL=1 go test -v -run TestGroqAccuracy   — Groq с реальным ключом (порог 0.85)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type tsItem struct {
	Text   string `json:"text"`
	IsScam bool   `json:"is_scam"`
	Scheme string `json:"scheme"`
}

func loadTestset(t *testing.T) []tsItem {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "engine", "testset.json"),
		filepath.Join("engine", "testset.json"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var items []tsItem
		if err := json.Unmarshal(b, &items); err != nil {
			t.Fatalf("testset.json битый: %v", err)
		}
		return items
	}
	t.Fatal("engine/testset.json не найден")
	return nil
}

// evalMetrics печатает accuracy, precision/recall по классу «скам» и confusion по схемам.
func evalMetrics(t *testing.T, name string, items []tsItem, predict func(string) (AnalyzeResponse, error)) float64 {
	t.Helper()
	var tp, fp, fn, tn, correct int
	confusion := map[string]int{} // "ожидалось→получено" для ошибок по схемам
	for i, it := range items {
		res, err := predict(it.Text)
		if err != nil {
			t.Logf("[%d] ошибка классификации (%v) — засчитываю как промах", i, err)
			res = AnalyzeResponse{SchemeCode: "other"}
		}
		predScam := res.SchemeCode != "not_scam"
		if predScam == it.IsScam {
			correct++
		}
		switch {
		case it.IsScam && predScam:
			tp++
		case !it.IsScam && predScam:
			fp++
			t.Logf("[%d] FP: %.60q → %s (score %d)", i, it.Text, res.SchemeCode, res.RiskScore)
		case it.IsScam && !predScam:
			fn++
			t.Logf("[%d] FN: %.60q (score %d)", i, it.Text, res.RiskScore)
		default:
			tn++
		}
		if res.SchemeCode != it.Scheme {
			confusion[it.Scheme+" → "+res.SchemeCode]++
		}
	}
	n := len(items)
	acc := float64(correct) / float64(n)
	prec, rec := 0.0, 0.0
	if tp+fp > 0 {
		prec = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		rec = float64(tp) / float64(tp+fn)
	}
	t.Logf("=== %s: n=%d accuracy=%.2f precision(scam)=%.2f recall(scam)=%.2f (TP=%d FP=%d FN=%d TN=%d)",
		name, n, acc, prec, rec, tp, fp, fn, tn)
	if len(confusion) > 0 {
		keys := make([]string, 0, len(confusion))
		for k := range confusion {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Logf("--- расхождения по схемам (%s):", name)
		for _, k := range keys {
			t.Logf("    %s: %d", k, confusion[k])
		}
	}
	return acc
}

func TestHeuristicAccuracy(t *testing.T) {
	items := loadTestset(t)
	acc := evalMetrics(t, "heuristic", items, func(text string) (AnalyzeResponse, error) {
		return classifyHeuristic(text), nil
	})
	if acc < 0.70 {
		t.Errorf("эвристика ниже порога: accuracy=%.2f < 0.70", acc)
	}
}

func TestGroqAccuracy(t *testing.T) {
	if os.Getenv("GROQ_EVAL") != "1" {
		t.Skip("прогон Groq только при GROQ_EVAL=1 (тратит free tier)")
	}
	loadConfig()
	loadPrompt()
	if groqKey == "" {
		t.Skip("GROQ_API_KEY не задан")
	}
	// Пауза между запросами: free tier лимитирует токены в минуту.
	// По умолчанию 2.5с; при жёстких лимитах задайте GROQ_EVAL_PAUSE_MS=20000.
	pause := 2500 * time.Millisecond
	if ms, err := strconv.Atoi(os.Getenv("GROQ_EVAL_PAUSE_MS")); err == nil && ms > 0 {
		pause = time.Duration(ms) * time.Millisecond
	}
	items := loadTestset(t)
	first := true
	acc := evalMetrics(t, fmt.Sprintf("groq (%s)", groqModel), items, func(text string) (AnalyzeResponse, error) {
		if !first {
			time.Sleep(pause)
		}
		first = false
		var res AnalyzeResponse
		var err error
		for attempt, backoff := 0, 10*time.Second; attempt < 4; attempt, backoff = attempt+1, backoff*2 {
			res, err = classifyGroq(text)
			if err == nil || !strings.Contains(err.Error(), "429") {
				break
			}
			time.Sleep(backoff) // rate limit — ждём и пробуем ещё
		}
		return res, err
	})
	if acc < 0.85 {
		t.Errorf("Groq ниже KPI-2: accuracy=%.2f < 0.85", acc)
	}
}
