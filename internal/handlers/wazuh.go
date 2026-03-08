package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
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
	agentID := chi.URLParam(r, "agentID")

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

// HandleWazuhCVESummary returns aggregated CVE statistics across all agents.
func (h *Handler) HandleWazuhCVESummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	h.WazuhCache.Mutex.RLock()
	agents := h.WazuhCache.Agents
	h.WazuhCache.Mutex.RUnlock()

	summary := map[string]interface{}{
		"total_agents": len(agents),
		"critical":     0,
		"high":         0,
		"medium":       0,
		"low":          0,
		"total_vulns":  0,
		"top_agents":   []map[string]interface{}{},
	}

	type agentVulns struct {
		Name  string `json:"name"`
		Total int    `json:"total"`
		Crit  int    `json:"critical"`
		High  int    `json:"high"`
	}

	var topAgents []agentVulns
	for _, a := range agents {
		summary["critical"] = summary["critical"].(int) + a.VulnSummary.Critical
		summary["high"] = summary["high"].(int) + a.VulnSummary.High
		summary["medium"] = summary["medium"].(int) + a.VulnSummary.Medium
		summary["low"] = summary["low"].(int) + a.VulnSummary.Low
		summary["total_vulns"] = summary["total_vulns"].(int) + a.VulnSummary.Total
		if a.VulnSummary.Total > 0 {
			topAgents = append(topAgents, agentVulns{Name: a.Name, Total: a.VulnSummary.Total, Crit: a.VulnSummary.Critical, High: a.VulnSummary.High})
		}
	}

	// Sort top agents by total vulns descending, take top 5
	sort.Slice(topAgents, func(i, j int) bool { return topAgents[i].Total > topAgents[j].Total })
	if len(topAgents) > 5 {
		topAgents = topAgents[:5]
	}
	summary["top_agents"] = topAgents

	json.NewEncoder(w).Encode(summary)
}

// HandleWazuhGeoData returns geo/IP threat data from recent auth-related alerts.
func (h *Handler) HandleWazuhGeoData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.WazuhIndexer == nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}

	alerts, err := h.WazuhIndexer.GetRecentAlerts(24 * time.Hour)
	if err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}

	// Extract unique source IPs from auth-related alerts
	ipSet := make(map[string]int)
	for _, a := range alerts {
		if a.Data.SrcIP != "" && a.Data.SrcIP != "127.0.0.1" && a.Rule.Level >= 5 {
			ipSet[a.Data.SrcIP]++
		}
	}

	var result []map[string]interface{}
	for ip, count := range ipSet {
		result = append(result, map[string]interface{}{"ip": ip, "count": count})
	}

	json.NewEncoder(w).Encode(result)
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
