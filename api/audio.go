// audio.go — POST /analyze/audio: голосовое/запись звонка → Whisper-транскрипция
// (Groq) → анализ текста тем же движком, что /analyze. «Интонация давления»
// оценивается по словам-маркерам в расшифровке (движок), а не по звуку.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

type AudioResponse struct {
	AnalyzeResponse
	Transcript string `json:"transcript"`
}

const maxAudioBytes = 10 << 20 // 10 МБ

// ---------- POST /analyze/audio (multipart, поле "audio") ----------

func handleAnalyzeAudio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(maxAudioBytes + 1<<20); err != nil {
		http.Error(w, "bad multipart form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("audio")
	if err != nil {
		http.Error(w, "missing audio file (field 'audio')", http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAudioBytes+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(data) == 0 {
		http.Error(w, "empty audio file", http.StatusBadRequest)
		return
	}
	if len(data) > maxAudioBytes {
		http.Error(w, "audio too large (>10MB)", http.StatusBadRequest)
		return
	}
	region := r.FormValue("region")
	filename := header.Filename
	if filename == "" {
		filename = "audio.ogg"
	}

	var resp AudioResponse
	transcript, err := transcribe(data, filename)
	switch {
	case err != nil:
		log.Printf("whisper error: %v → degraded", err)
		resp.AnalyzeResponse = AnalyzeResponse{
			SchemeCode:         "other",
			Explanation:        "Не удалось расшифровать аудио (сервис распознавания речи недоступен). Пришлите текст сообщения — проверю его.",
			RecommendedActions: []string{"Пришлите текст обычным сообщением"},
			Degraded:           true,
		}
		normalize(&resp.AnalyzeResponse)
	case strings.TrimSpace(transcript) == "":
		resp.AnalyzeResponse = AnalyzeResponse{
			SchemeCode:  "not_scam",
			Explanation: "В аудио не распознано речи для анализа.",
		}
		normalize(&resp.AnalyzeResponse)
	default:
		resp.AnalyzeResponse = classify(transcript)
	}
	resp.Transcript = transcript

	storeReq := AnalyzeRequest{Text: orDefault(transcript, "[audio]"), Channel: "voice", Region: region}
	maskAndStore(storeReq, &resp.AnalyzeResponse)
	writeJSON(w, resp)
}

// transcribe отправляет аудио в Groq audio/transcriptions (Whisper) и возвращает
// распознанный текст.
func transcribe(data []byte, filename string) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(data); err != nil {
		return "", err
	}
	mw.WriteField("model", groqSTTModel)
	mw.WriteField("response_format", "json")
	mw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, groqBase+"/audio/transcriptions", &buf)
	httpReq.Header.Set("Authorization", "Bearer "+groqKey)
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("groq whisper http %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.Text), nil
}
