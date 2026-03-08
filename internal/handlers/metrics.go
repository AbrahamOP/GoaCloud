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

	var interval string
	switch period {
	case "1h":
		interval = "1 HOUR"
	case "6h":
		interval = "6 HOUR"
	case "24h":
		interval = "24 HOUR"
	case "7d":
		interval = "7 DAY"
	default:
		interval = "24 HOUR"
	}

	rows, err := h.DB.Query(
		"SELECT cpu, ram, storage, recorded_at FROM metrics_history WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL " + interval + ") ORDER BY recorded_at ASC")
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
	if points == nil {
		points = []MetricPoint{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(points)
}
