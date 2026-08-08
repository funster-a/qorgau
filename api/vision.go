// vision.go — POST /analyze/image: скриншот чата/сайта → Groq vision.
// Модель извлекает текст со скриншота, оценивает подделку интерфейса банка/
// госоргана и возвращает тот же контракт, что /analyze, плюс extracted_text и
// ui_spoofing. При недоступности vision — degraded и эвристика по тексту, если он
// хоть как-то извлёкся.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type ImageRequest struct {
	ImageBase64 string `json:"image_base64"`
	Region      string `json:"region"`
}

type ImageResponse struct {
	AnalyzeResponse
	ExtractedText string `json:"extracted_text"`
	UISpoofing    bool   `json:"ui_spoofing"`
}

const maxImageBytes = 5 << 20 // 5 МБ после декодирования

const visionInstruction = `Тебе прислали СКРИНШОТ (переписка, СМС, пуш или веб-страница).
1) Извлеки ВЕСЬ видимый на изображении текст дословно.
2) Оцени, не является ли это ПОДДЕЛКОЙ интерфейса банка/госоргана/Kaspi/Halyk/eGov
   (фальшивая страница входа, поддельный чат «поддержки», фейковый пуш о блокировке).
3) Проанализируй извлечённый текст на признаки мошенничества по своим правилам.
Верни ТОЛЬКО валидный JSON того же формата, что обычный анализ:
{"risk_score":0-100,"risk_level":"low|medium|high","scheme_code":"...","impersonated_brand":"строка или \"\"","flags":["..."],"explanation":"...","recommended_actions":["..."],"iocs":[{"type":"phone|domain|iban","value":"как в тексте"}],"lang":"ru|kz"}
И ДОПОЛНИТЕЛЬНО два поля: "extracted_text" (string — весь распознанный текст) и "ui_spoofing" (bool — похоже ли на подделку интерфейса банка/госоргана).`

// ---------- POST /analyze/image ----------

func handleAnalyzeImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	b64 := strings.TrimSpace(req.ImageBase64)
	if b64 == "" {
		http.Error(w, "empty image_base64", http.StatusBadRequest)
		return
	}
	// data:image/png;base64,XXXX → отрезаем префикс, mime запоминаем для data-URL.
	mime := "image/png"
	if strings.HasPrefix(b64, "data:") {
		if comma := strings.IndexByte(b64, ','); comma > 0 {
			if semi := strings.IndexByte(b64, ';'); semi > 5 && semi < comma {
				mime = b64[5:semi]
			}
			b64 = b64[comma+1:]
		}
	}
	b64 = strings.TrimSpace(b64)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		http.Error(w, "bad base64", http.StatusBadRequest)
		return
	}
	if len(decoded) == 0 {
		http.Error(w, "empty image", http.StatusBadRequest)
		return
	}
	if len(decoded) > maxImageBytes {
		http.Error(w, "image too large (>5MB)", http.StatusBadRequest)
		return
	}
	dataURL := "data:" + mime + ";base64," + b64

	var resp ImageResponse
	if groqKey != "" && !getFlags().ForceDegraded {
		if r2, err := classifyVision(dataURL); err == nil {
			resp = r2
		} else {
			log.Printf("vision error: %v → degraded", err)
			resp = visionDegraded("")
		}
	} else {
		resp = visionDegraded("")
	}

	storeReq := AnalyzeRequest{Text: orDefault(resp.ExtractedText, "[image]"), Channel: "image", Region: req.Region}
	maskAndStore(storeReq, &resp.AnalyzeResponse)
	writeJSON(w, resp)
}

// classifyVision вызывает Groq vision. Пробуем со строгим JSON-режимом; если
// модель его не поддерживает вместе с картинкой — повторяем без него и парсим
// JSON из тела ответа.
func classifyVision(dataURL string) (ImageResponse, error) {
	if r, err := visionOnce(dataURL, true); err == nil {
		return r, nil
	}
	return visionOnce(dataURL, false)
}

func visionOnce(dataURL string, jsonMode bool) (ImageResponse, error) {
	body := map[string]any{
		"model":       groqVisionModel,
		"temperature": 0.1,
		"messages": []map[string]any{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": []map[string]any{
				{"type": "text", "text": visionInstruction},
				{"type": "image_url", "image_url": map[string]string{"url": dataURL}},
			}},
		},
	}
	if jsonMode {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	b, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, groqBase+"/chat/completions", bytes.NewReader(b))
	httpReq.Header.Set("Authorization", "Bearer "+groqKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return ImageResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return ImageResponse{}, fmt.Errorf("groq vision http %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var wrap struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return ImageResponse{}, err
	}
	if len(wrap.Choices) == 0 {
		return ImageResponse{}, fmt.Errorf("groq vision вернул пустой choices")
	}
	var out ImageResponse
	if err := json.Unmarshal([]byte(extractJSON(wrap.Choices[0].Message.Content)), &out); err != nil {
		return ImageResponse{}, err
	}
	normalize(&out.AnalyzeResponse)
	out.Degraded = false
	return out, nil
}

// visionDegraded строит ответ, когда vision недоступен. Если удалось хоть как-то
// получить текст со скриншота — прогоняем его через эвристику (контракт).
func visionDegraded(extracted string) ImageResponse {
	var base AnalyzeResponse
	if strings.TrimSpace(extracted) != "" {
		base = classifyHeuristic(extracted)
	} else {
		base = AnalyzeResponse{
			SchemeCode:         "other",
			Explanation:        "Не удалось распознать изображение (сервис зрения недоступен). Опишите текст сообщения — проверю его.",
			RecommendedActions: []string{"Пришлите текст сообщения обычным сообщением"},
		}
	}
	base.Degraded = true
	normalize(&base)
	return ImageResponse{AnalyzeResponse: base, ExtractedText: extracted, UISpoofing: false}
}
