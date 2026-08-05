package services

import (
	"database/sql"
	"log/slog"
)

// LogAudit inserts an audit log entry into the database.
//
// details is rendered as-is on /audit-logs: it must NEVER carry a secret (private
// key, password, TOTP code, API token, query string). Name WHAT was done and on
// WHICH resource — a key by its name or fingerprint, never by its material.
//
// A failed insert is reported instead of being swallowed: a trail that silently
// loses rows is worse than no trail, because it is trusted. The failing action is
// logged with it so the lost entry can still be reconstructed from the app logs.
func LogAudit(db *sql.DB, userID int, username, action, details, ip string) {
	if userID == 0 && username != "" {
		db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	}

	_, err := db.Exec("INSERT INTO audit_logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
		userID, username, action, details, ip)
	if err != nil {
		slog.Error("Audit Log Error", "error", err, "action", action, "username", username, "ip", ip)
	}
}
