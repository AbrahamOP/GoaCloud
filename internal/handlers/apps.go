package handlers

import (
	"log/slog"
	"net/http"
)

// HandleAddApp handles the add application form.
func (h *Handler) HandleAddApp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.Templates.ExecuteTemplate(w, "add_app.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		url := r.FormValue("url")
		desc := r.FormValue("description")
		cat := r.FormValue("category")
		icon := r.FormValue("icon_url")

		if name == "" || url == "" {
			http.Error(w, "Nom et URL requis", http.StatusBadRequest)
			return
		}

		if _, err := h.DB.Exec("INSERT INTO apps (name, description, external_url, icon_url, category) VALUES (?, ?, ?, ?, ?)",
			name, desc, url, icon, cat); err != nil {
			slog.Error("Error inserting app", "error", err)
			http.Error(w, "Erreur base de données", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
