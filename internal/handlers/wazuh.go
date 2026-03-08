package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"goacloud/internal/models"
)

// HandleWazuh renders the Wazuh agents page.
func (h *Handler) HandleWazuh(w http.ResponseWriter, r *http.Request) {
	if h.WazuhClient == nil {
		http.Error(w, "Wazuh not configured", http.StatusInternalServerError)
		return
	}

	h.WazuhCache.Mutex.RLock()
	agents := h.WazuhCache.Agents
	h.WazuhCache.Mutex.RUnlock()

	if len(agents) == 0 {
		var err error
		agents, err = h.WazuhClient.GetAgents()
		if err != nil {
			http.Error(w, "Error fetching agents: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	currentUser, _ := session.Values["username"].(string)

	data := struct {
		User   string
		Agents []models.WazuhAgent
	}{
		User:   currentUser,
		Agents: agents,
	}

	if err := h.Templates.ExecuteTemplate(w, "wazuh.html", data); err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// HandleWazuhVulns returns vulnerability details for a specific agent as JSON.
func (h *Handler) HandleWazuhVulns(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	agentID := parts[4]

	if val, ok := h.VulnCache.Load(agentID); ok {
		cached := val.(models.CachedVulns)
		if time.Now().Before(cached.Expiry) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cached.Data)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]models.WazuhVuln{})
}

// HandleWazuhAgentsRefresh force-refreshes the Wazuh cache and returns updated agents as JSON.
func (h *Handler) HandleWazuhAgentsRefresh(w http.ResponseWriter, r *http.Request) {
	if h.WazuhClient == nil {
		http.Error(w, `{"error":"Wazuh not configured"}`, http.StatusInternalServerError)
		return
	}

	// Trigger a synchronous update
	agents, err := h.WazuhClient.GetAgents()
	if err == nil {
		h.WazuhCache.Mutex.Lock()
		h.WazuhCache.Agents = agents
		h.WazuhCache.UpdatedAt = time.Now()
		h.WazuhCache.Mutex.Unlock()
	}

	h.WazuhCache.Mutex.RLock()
	result := h.WazuhCache.Agents
	h.WazuhCache.Mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
