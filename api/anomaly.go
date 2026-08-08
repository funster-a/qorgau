// anomaly.go — детектор кампаний: фоновый тикер раз в 60с сравнивает текущий час
// с почасовыми бакетами за предыдущие 24ч (z-score + кратность среднего).
package main

import (
	"log"
	"math"
	"time"
)

const (
	anomalyMinCount = 5.0 // минимум обращений за час, ниже — не всплеск
	anomalyZScore   = 3.0
	anomalyFactor   = 3.0 // во сколько раз выше среднего
)

func anomalyTicker() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		runAnomalyCheck()
	}
}

func runAnomalyCheck() {
	if db == nil {
		return
	}
	// Текущий (неполный) час по каждой схеме.
	cur := map[string]int{}
	rows, err := db.Query(`SELECT scheme_code, count(*) FROM analytics.signal
		WHERE created_at >= date_trunc('hour', now()) AND scheme_code <> 'not_scam'
		GROUP BY 1`)
	if err != nil {
		log.Printf("anomaly: %v", err)
		return
	}
	for rows.Next() {
		var s string
		var c int
		rows.Scan(&s, &c)
		cur[s] = c
	}
	rows.Close()

	// База: почасовые бакеты за предыдущие 24 часа (текущий час исключён).
	base := map[string][]float64{}
	rows, err = db.Query(`SELECT scheme_code, count(*) FROM analytics.signal
		WHERE created_at >= date_trunc('hour', now()) - interval '24 hours'
		  AND created_at <  date_trunc('hour', now())
		  AND scheme_code <> 'not_scam'
		GROUP BY scheme_code, date_trunc('hour', created_at)`)
	if err != nil {
		log.Printf("anomaly: %v", err)
		return
	}
	for rows.Next() {
		var s string
		var c float64
		rows.Scan(&s, &c)
		base[s] = append(base[s], c)
	}
	rows.Close()

	// Объединяем схемы: и те, где есть активность сейчас, и те, где есть активная кампания.
	schemes := map[string]bool{}
	for s := range cur {
		schemes[s] = true
	}
	rows, err = db.Query(`SELECT DISTINCT scheme_code FROM analytics.campaign WHERE status='active'`)
	if err == nil {
		for rows.Next() {
			var s string
			rows.Scan(&s)
			schemes[s] = true
		}
		rows.Close()
	}

	for scheme := range schemes {
		mean, sd := meanStd(pad24(base[scheme]))
		c := float64(cur[scheme])
		spike := c >= anomalyMinCount &&
			((sd > 0 && (c-mean)/sd >= anomalyZScore) || c >= anomalyFactor*mean)
		threshold := math.Max(anomalyMinCount, anomalyFactor*mean)

		var campID string
		var peak int
		active := db.QueryRow(`SELECT id, peak_value FROM analytics.campaign
			WHERE scheme_code=$1 AND status='active' ORDER BY started_at DESC LIMIT 1`,
			scheme).Scan(&campID, &peak) == nil

		switch {
		case spike && !active:
			db.Exec(`INSERT INTO analytics.campaign (scheme_code, peak_value) VALUES ($1,$2)`, scheme, int(c))
			log.Printf("КАМПАНИЯ ОТКРЫТА: схема %s, за час %d (среднее за 24ч %.1f)", scheme, int(c), mean)
		case active && c > float64(peak):
			db.Exec(`UPDATE analytics.campaign SET peak_value=$1 WHERE id=$2`, int(c), campID)
		case active && c < threshold/2:
			db.Exec(`UPDATE analytics.campaign SET status='closed', closed_at=now() WHERE id=$1`, campID)
			log.Printf("КАМПАНИЯ ЗАКРЫТА: схема %s (за час %d < порога %.1f)", scheme, int(c), threshold/2)
		}
	}
}

// pad24 дополняет ряд нулями до 24 значений: часы без сигналов — тоже данные.
func pad24(v []float64) []float64 {
	for len(v) < 24 {
		v = append(v, 0)
	}
	return v
}

func meanStd(v []float64) (mean, sd float64) {
	if len(v) == 0 {
		return 0, 0
	}
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	for _, x := range v {
		sd += (x - mean) * (x - mean)
	}
	sd = math.Sqrt(sd / float64(len(v)))
	return mean, sd
}
