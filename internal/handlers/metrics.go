package handlers

import (
	"encoding/json"
	"net/http"
)

type MetricPoint struct {
	CPU       int    `json:"cpu"`
	RAM       int    `json:"ram"`
	Storage   int    `json:"storage"`
	Timestamp string `json:"ts"`
}

func (h *Handler) HandleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	var intervalValue int
	var intervalUnit string
	switch period {
	case "1h":
		intervalValue, intervalUnit = 1, "HOUR"
	case "6h":
		intervalValue, intervalUnit = 6, "HOUR"
	case "24h":
		intervalValue, intervalUnit = 24, "HOUR"
	case "7d":
		intervalValue, intervalUnit = 7, "DAY"
	default:
		intervalValue, intervalUnit = 24, "HOUR"
	}

	var query string
	switch intervalUnit {
	case "DAY":
		query = "SELECT cpu, ram, storage, recorded_at FROM metrics_history WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY recorded_at ASC"
	default:
		query = "SELECT cpu, ram, storage, recorded_at FROM metrics_history WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) ORDER BY recorded_at ASC"
	}
	rows, err := h.DB.Query(query, intervalValue)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]MetricPoint{})
		return
	}
	defer rows.Close()

	var points []MetricPoint
	for rows.Next() {
		var p MetricPoint
		if rows.Scan(&p.CPU, &p.RAM, &p.Storage, &p.Timestamp) == nil {
			points = append(points, p)
		}
	}
	_ = rows.Err()
	if points == nil {
		points = []MetricPoint{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(points)
}
