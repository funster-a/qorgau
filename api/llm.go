// llm.go — универсальный вызов Groq chat/completions для фич, которым нужен
// свободный текст, а не строгий контракт /analyze (тренажёр, живой суфлёр,
// ИИ-юрист). Тот же транспорт и стиль, что engine.go/vision.go.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// newID генерирует UUIDv4-подобный идентификатор без внешних зависимостей
// (для in-memory сессий тренажёра/суфлёра/юриста).
func newID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// llmAvailable: есть ключ и не включён форс-degraded (пульт демо).
func llmAvailable() bool {
	return groqKey != "" && !getFlags().ForceDegraded
}

// groqChat вызывает chat/completions и возвращает content первого choice.
// jsonMode включает строгий JSON-режим. temperature повыше — реплики живее.
func groqChat(messages []map[string]any, timeout time.Duration, jsonMode bool) (string, error) {
	body := map[string]any{
		"model":       groqModel,
		"temperature": 0.5,
		"messages":    messages,
	}
	if jsonMode {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	b, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, groqBase+"/chat/completions", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+groqKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("groq http %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var wrap struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return "", err
	}
	if len(wrap.Choices) == 0 {
		return "", fmt.Errorf("groq пустой choices")
	}
	return strings.TrimSpace(wrap.Choices[0].Message.Content), nil
}

// msg — короткий конструктор сообщения для groqChat.
func msg(role, content string) map[string]any {
	return map[string]any{"role": role, "content": content}
}
