package workers

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log/slog"
	"net/http"
	"time"
)

func StartHealthWorker(ctx context.Context, db *sql.DB) {
	slog.Info("Starting Health Check Worker...")
	runHealthChecks(db)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Health Worker stopped")
			return
		case <-ticker.C:
			runHealthChecks(db)
		}
	}
}

func runHealthChecks(db *sql.DB) {
	rows, err := db.Query("SELECT id, external_url FROM apps")
	if err != nil {
		slog.Error("Health worker: DB error", "error", err)
		return
	}
	defer rows.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	for rows.Next() {
		var id int
		var url string
		if err := rows.Scan(&id, &url); err != nil {
			continue
		}

		start := time.Now()
		status := "down"
		respMs := 0

		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			respMs = int(time.Since(start).Milliseconds())
			if resp.StatusCode < 500 {
				status = "up"
			}
		} else {
			respMs = int(time.Since(start).Milliseconds())
		}

		if _, err := db.Exec("UPDATE apps SET health_status = ?, health_response_ms = ?, health_last_check = NOW() WHERE id = ?",
			status, respMs, id); err != nil {
			slog.Error("Health worker: failed to update status", "id", id, "error", err)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("Health worker: row iteration error", "error", err)
	}
	slog.Debug("Health checks completed")
}
