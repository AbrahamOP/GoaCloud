package handlers

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) HandleTogglePin(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("id")
	if appID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing id"})
		return
	}

	// Toggle is_pinned
	_, err := h.DB.Exec("UPDATE apps SET is_pinned = NOT is_pinned WHERE id = ?", appID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var pinned bool
	h.DB.QueryRow("SELECT is_pinned FROM apps WHERE id = ?", appID).Scan(&pinned)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "pinned": pinned})
}
