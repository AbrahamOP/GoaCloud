package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"goacloud/internal/models"
)

// HandleProxmox renders the Proxmox VM/CT overview page (served from in-memory cache).
func (h *Handler) HandleProxmox(w http.ResponseWriter, r *http.Request) {
	var stats models.ProxmoxStats

	if h.Config.ProxmoxURL != "" && h.Config.ProxmoxTokenID != "" {
		h.ProxmoxCache.Mutex.RLock()
		stats = h.ProxmoxCache.Stats
		h.ProxmoxCache.Mutex.RUnlock()

		// Cache vide au premier démarrage — fetch live et peuple le cache
		if len(stats.VMs) == 0 {
			realStats, err := h.Proxmox.GetStats(h.Config.ProxmoxURL, h.Config.ProxmoxNode, h.Config.ProxmoxTokenID, h.Config.ProxmoxTokenSecret, true, false)
			if err != nil {
				slog.Error("Proxmox API Error", "error", err)
				stats.VMs = []models.VM{{Name: fmt.Sprintf("Erreur: %v", err), Status: "error"}}
			} else {
				stats = realStats
				h.ProxmoxCache.Mutex.Lock()
				h.ProxmoxCache.Stats = stats
				h.ProxmoxCache.Mutex.Unlock()
			}
		}
	} else {
		stats = mockProxmoxStats()
	}

	if err := h.Templates.ExecuteTemplate(w, "proxmox.html", stats); err != nil {
		slog.Error("Template execution error", "error", err)
		http.Error(w, "Erreur de rendu", http.StatusInternalServerError)
	}
}

// HandleProxmoxAPI returns Proxmox stats as JSON (used by the dashboard live widget).
func (h *Handler) HandleProxmoxAPI(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	var stats models.ProxmoxStats

	if cfg.ProxmoxURL != "" && cfg.ProxmoxTokenID != "" {
		realStats, err := h.Proxmox.GetStats(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, false, false)
		if err != nil {
			stats.VMs = []models.VM{{Name: fmt.Sprintf("Erreur: %v", err), Status: "error"}}
		} else {
			stats = realStats
		}
	} else {
		stats = mockProxmoxStats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleProxmoxGuestDetail returns detailed information about a single VM/CT as JSON.
func (h *Handler) HandleProxmoxGuestDetail(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")

	if guestType == "" || guestID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type or id"})
		return
	}

	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}

	var detail models.GuestDetail
	var err error

	if cfg.ProxmoxURL != "" && cfg.ProxmoxTokenID != "" {
		detail, err = h.Proxmox.GetGuestDetail(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, pveType, guestID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Error fetching details: %v", err)})
			return
		}
	} else {
		detail = models.GuestDetail{
			ID: 100, Name: "Mock Guest", Status: "running", Uptime: "1d 2h",
			CPU: 15.5, Cores: 4, RAMUsed: "2.1 GB", RAMTotal: "4 GB", RAMPercent: 52,
			DiskUsed: "10 GB", DiskTotal: "32 GB", DiskPercent: 31,
			Note: "This is a mock note.", Type: guestType,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

// HandleProxmoxPowerAction sends a power command (start/stop/reboot/shutdown) to a VM/CT.
func (h *Handler) HandleProxmoxPowerAction(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")
	action := r.URL.Query().Get("action")

	w.Header().Set("Content-Type", "application/json")

	if guestType == "" || guestID == "" || action == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type, id or action"})
		return
	}

	validActions := map[string]bool{"start": true, "stop": true, "reboot": true, "shutdown": true}
	if !validActions[action] {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid action"})
		return
	}

	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}

	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		json.NewEncoder(w).Encode(map[string]string{"ok": "mock: action simulated"})
		return
	}

	if err := h.Proxmox.PowerAction(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, pveType, guestID, action); err != nil {
		slog.Error("Proxmox power action failed", "action", action, "id", guestID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"ok": "action queued"})
}

// HandleProxmoxIPs returns a VMID→IP map from the vm_cache table.
func (h *Handler) HandleProxmoxIPs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query("SELECT vmid, ip_address FROM vm_cache")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	ipMap := make(map[string]string)
	for rows.Next() {
		var vmid int
		var ip string
		if err := rows.Scan(&vmid, &ip); err == nil {
			ipMap[fmt.Sprintf("%d", vmid)] = ip
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ipMap)
}

func mockProxmoxStats() models.ProxmoxStats {
	return models.ProxmoxStats{
		CPU:      12,
		RAM:      45,
		RAMUsed:  14.2,
		RAMTotal: 32.0,
		Storage:  68,
		VMs: []models.VM{
			{ID: 0, Name: "Mock Data (Configurez ENV)", Status: "running", Uptime: "-", IP: "127.0.0.1"},
		},
	}
}
