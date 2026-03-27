package handlers

import (
	"encoding/json"
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

// HandleUpdateApp handles updating an existing application via JSON API.
func (h *Handler) HandleUpdateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		ExternalURL string `json:"url"`
		IconURL     string `json:"icon_url"`
		Category    string `json:"category"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.ID == 0 || req.Name == "" || req.ExternalURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id, name and url are required"})
		return
	}

	_, err := h.DB.Exec(
		"UPDATE apps SET name = ?, description = ?, external_url = ?, icon_url = ?, category = ? WHERE id = ?",
		req.Name, req.Description, req.ExternalURL, req.IconURL, req.Category, req.ID,
	)
	if err != nil {
		slog.Error("Error updating app", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "database error"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// HandleDeleteApp handles deleting an application via JSON API.
func (h *Handler) HandleDeleteApp(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("id")
	if appID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing id"})
		return
	}

	_, err := h.DB.Exec("DELETE FROM apps WHERE id = ?", appID)
	if err != nil {
		slog.Error("Error deleting app", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "database error"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}
