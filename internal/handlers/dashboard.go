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
	h.Templates.ExecuteTemplate(w, "dashboard.html", data)
}

func (h *Handler) getApps() ([]models.App, error) {
	rows, err := h.DB.Query("SELECT id, name, description, external_url, icon_url, category FROM apps ORDER BY category, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []models.App
	for rows.Next() {
		var a models.App
		var icon sql.NullString
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.ExternalURL, &icon, &a.Category); err != nil {
			continue
		}
		if icon.Valid {
			a.IconURL = icon.String
		}
		apps = append(apps, a)
	}
	return apps, nil
}
