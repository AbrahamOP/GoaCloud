package handlers

import (
	"log/slog"
	"net/http"

	"goacloud/internal/models"
)

// HandleAuditLogs renders the audit log viewer (Admin only).
func (h *Handler) HandleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := h.SessionStore.Get(r, "goacloud-session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var role string
	if err := h.DB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role); err != nil {
		slog.Error("Error fetching user role", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if role != "Admin" {
		h.renderError(w, "dashboard.html", "Accès refusé. Réservé aux administrateurs.")
		return
	}

	rows, err := h.DB.Query("SELECT id, username, action, details, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.Username, &l.Action, &l.Details, &l.IPAddress, &l.CreatedAt); err != nil {
			slog.Error("Error scanning audit log", "error", err)
			continue
		}
		logs = append(logs, l)
	}

	data := map[string]interface{}{
		"Username": username,
		"Role":     role,
		"Logs":     logs,
	}
	if err := h.Templates.ExecuteTemplate(w, "audit_logs.html", data); err != nil {
		slog.Error("Template execution error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}
