package handlers

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) HandleNotificationStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"supported": true})
}
