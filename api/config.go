// config.go — конфигурация: .env, переменные окружения, дефолты.
package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	groqKey    string
	groqBase   string
	groqModel  string
	apiAddr    string
	dbURL      string
	piiTTL     time.Duration
	piiEncKey  string
	botAPIKey  string
	adminToken string
)

const defaultPIIKey = "qorgau-demo-key"

func loadConfig() {
	loadDotEnv()
	groqKey = env("GROQ_API_KEY", "")
	groqBase = env("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
	groqModel = env("GROQ_MODEL", "llama-3.3-70b-versatile")
	apiAddr = env("API_ADDR", ":8080")
	dbURL = env("DATABASE_URL", "")
	botAPIKey = env("BOT_API_KEY", "")
	adminToken = env("ADMIN_TOKEN", "")
	piiEncKey = env("PII_ENC_KEY", "")
	if piiEncKey == "" {
		piiEncKey = defaultPIIKey
		log.Println("WARNING: PII_ENC_KEY не задан — использую демо-ключ шифрования (для прода задайте свой)")
	}
	hours, err := strconv.Atoi(env("PII_TTL_HOURS", "24"))
	if err != nil || hours <= 0 {
		hours = 24
	}
	piiTTL = time.Duration(hours) * time.Hour
}

// loadDotEnv читает .env из рабочей директории или на уровень выше (запуск из api/).
// Уже заданные переменные окружения имеют приоритет — .env их не перетирает.
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

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
