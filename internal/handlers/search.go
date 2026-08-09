package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"goacore/internal/middleware"
)

type SearchResult struct {
	Type string `json:"type"` // "app", "vm", "page"
	Name string `json:"name"`
	URL  string `json:"url"`
	Icon string `json:"icon"` // emoji or category
}

// searchPage is one entry of the static page index. adminOnly marks the pages that
// live in the AdminOnly router group: they are already 403 for a Viewer, but listing
// them still hands one the map of the admin surface (which screens exist, at which
// URL) — a free reconnaissance step. The palette mirrors the router's boundary
// instead of advertising past it.
type searchPage struct {
	name      string
	url       string
	adminOnly bool
}

// searchPages must stay in sync with the router groups in internal/router/router.go.
var searchPages = []searchPage{
	{name: "Applications", url: "/"},
	{name: "Proxmox", url: "/proxmox"},
	{name: "Securite (Wazuh)", url: "/wazuh"},
	{name: "SOAR", url: "/soar"},
	{name: "Profil", url: "/profile"},
	{name: "Cles SSH", url: "/ssh", adminOnly: true},
	{name: "Ansible", url: "/ansible", adminOnly: true},
	{name: "Console Web", url: "/console", adminOnly: true},
	{name: "Utilisateurs", url: "/users", adminOnly: true},
	{name: "Audit Logs", url: "/audit-logs", adminOnly: true},
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

	// Static pages, filtered by role. AuthMiddleware re-syncs session.Values["role"]
	// with the DB on every request, so this read is as fresh as the DB lookup the
	// AdminOnly gate does — and it is only a display filter here: the gate, not the
	// palette, is what actually denies a Viewer.
	isAdmin := middleware.GetSessionRole(r, h.SessionStore) == "Admin"
	for _, p := range searchPages {
		if p.adminOnly && !isAdmin {
			continue
		}
		if strings.Contains(strings.ToLower(p.name), query) {
			results = append(results, SearchResult{Type: "page", Name: p.name, URL: p.url, Icon: "page"})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
