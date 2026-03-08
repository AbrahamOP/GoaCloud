package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

type SearchResult struct {
	Type string `json:"type"` // "app", "vm", "page"
	Name string `json:"name"`
	URL  string `json:"url"`
	Icon string `json:"icon"` // emoji or category
}

func (h *Handler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]SearchResult{})
		return
	}

	var results []SearchResult

	// Search apps
	rows, err := h.DB.Query("SELECT name, external_url, category FROM apps WHERE LOWER(name) LIKE ? OR LOWER(category) LIKE ? LIMIT 10", "%"+query+"%", "%"+query+"%")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, url, cat string
			if rows.Scan(&name, &url, &cat) == nil {
				results = append(results, SearchResult{Type: "app", Name: name, URL: url, Icon: cat})
			}
		}
	}

	// Search VMs from cache
	h.ProxmoxCache.Mutex.RLock()
	for _, vm := range h.ProxmoxCache.Stats.VMs {
		if strings.Contains(strings.ToLower(vm.Name), query) || strings.Contains(strings.ToLower(vm.IP), query) {
			results = append(results, SearchResult{Type: "vm", Name: vm.Name, URL: "/proxmox", Icon: vm.Type})
		}
	}
	h.ProxmoxCache.Mutex.RUnlock()

	// Static pages
	pages := []struct{ name, url string }{
		{"Applications", "/"}, {"Proxmox", "/proxmox"}, {"Securite (Wazuh)", "/wazuh"},
		{"SOAR", "/soar"}, {"Cles SSH", "/ssh"}, {"Ansible", "/ansible"},
		{"Console Web", "/console"}, {"Utilisateurs", "/users"}, {"Profil", "/profile"},
		{"Audit Logs", "/audit-logs"},
	}
	for _, p := range pages {
		if strings.Contains(strings.ToLower(p.name), query) {
			results = append(results, SearchResult{Type: "page", Name: p.name, URL: p.url, Icon: "page"})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
