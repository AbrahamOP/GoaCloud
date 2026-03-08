package services

import (
	"database/sql"
	"log/slog"
)

// LogAudit inserts an audit log entry into the database.
func LogAudit(db *sql.DB, userID int, username, action, details, ip string) {
	if userID == 0 && username != "" {
		db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	}

	_, err := db.Exec("INSERT INTO audit_logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
		userID, username, action, details, ip)
	if err != nil {
		slog.Error("Audit Log Error", "error", err)
	}
}
