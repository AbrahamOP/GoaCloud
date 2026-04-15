package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"

	"goacloud/internal/models"
)

// HandleDashboard renders the main dashboard page.
func (h *Handler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)

	apps, err := h.getApps()
	if err != nil {
		slog.Error("Error fetching apps", "error", err)
	}

	data := map[string]interface{}{
		"Apps":     apps,
		"Username": username,
	}
	if err := h.Templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		slog.Error("Template execution error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}

func (h *Handler) getApps() ([]models.App, error) {
	rows, err := h.DB.Query("SELECT id, name, description, external_url, icon_url, category, health_status, health_response_ms, health_last_check, is_pinned, position FROM apps ORDER BY is_pinned DESC, position ASC, category, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []models.App
	for rows.Next() {
		var a models.App
		var icon sql.NullString
		var healthLastChk sql.NullString
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.ExternalURL, &icon, &a.Category, &a.HealthStatus, &a.HealthRespMs, &healthLastChk, &a.IsPinned, &a.Position); err != nil {
			continue
		}
		if icon.Valid {
			a.IconURL = icon.String
		}
		if healthLastChk.Valid {
			a.HealthLastChk = healthLastChk.String
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return apps, err
	}
	return apps, nil
}
