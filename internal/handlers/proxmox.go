package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"goacloud/internal/models"
	"goacloud/internal/services"
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

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	services.LogAudit(h.DB, 0, username, "ProxmoxPower", fmt.Sprintf("%s %s #%s", action, guestType, guestID), r.RemoteAddr)
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
	if err := rows.Err(); err != nil {
		slog.Error("Error iterating vm_cache", "error", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ipMap)
}

// HandleProxmoxSnapshots returns the list of snapshots for a VM/CT as JSON.
func (h *Handler) HandleProxmoxSnapshots(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")

	w.Header().Set("Content-Type", "application/json")

	if guestType == "" || guestID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type or id"})
		return
	}

	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}

	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		json.NewEncoder(w).Encode([]models.Snapshot{})
		return
	}

	snapshots, err := h.Proxmox.ListSnapshots(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, pveType, guestID)
	if err != nil {
		slog.Error("Proxmox list snapshots failed", "id", guestID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if snapshots == nil {
		snapshots = []models.Snapshot{}
	}
	json.NewEncoder(w).Encode(snapshots)
}

// HandleProxmoxSnapshotCreate creates a new snapshot for a VM/CT.
func (h *Handler) HandleProxmoxSnapshotCreate(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")

	w.Header().Set("Content-Type", "application/json")

	if guestType == "" || guestID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type or id"})
		return
	}

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid name"})
		return
	}

	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}

	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		json.NewEncoder(w).Encode(map[string]string{"ok": "mock: snapshot created"})
		return
	}

	if err := h.Proxmox.CreateSnapshot(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, pveType, guestID, body.Name, body.Description); err != nil {
		slog.Error("Proxmox create snapshot failed", "id", guestID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"ok": "snapshot created"})
}

// HandleProxmoxSnapshotDelete deletes a snapshot from a VM/CT.
func (h *Handler) HandleProxmoxSnapshotDelete(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")
	snapName := r.URL.Query().Get("name")

	w.Header().Set("Content-Type", "application/json")

	if guestType == "" || guestID == "" || snapName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type, id or name"})
		return
	}

	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}

	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		json.NewEncoder(w).Encode(map[string]string{"ok": "mock: snapshot deleted"})
		return
	}

	if err := h.Proxmox.DeleteSnapshot(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, pveType, guestID, snapName); err != nil {
		slog.Error("Proxmox delete snapshot failed", "id", guestID, "name", snapName, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"ok": "snapshot deleted"})
}

// HandleProxmoxSnapshotRollback rolls back a VM/CT to a specific snapshot.
func (h *Handler) HandleProxmoxSnapshotRollback(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")
	snapName := r.URL.Query().Get("name")

	w.Header().Set("Content-Type", "application/json")

	if guestType == "" || guestID == "" || snapName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type, id or name"})
		return
	}

	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}

	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		json.NewEncoder(w).Encode(map[string]string{"ok": "mock: rollback simulated"})
		return
	}

	if err := h.Proxmox.RollbackSnapshot(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, pveType, guestID, snapName); err != nil {
		slog.Error("Proxmox rollback snapshot failed", "id", guestID, "name", snapName, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"ok": "rollback queued"})
}

// HandleProxmoxConsoleURL returns the Proxmox noVNC console URL for a VM/CT.
func (h *Handler) HandleProxmoxConsoleURL(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	guestType := r.URL.Query().Get("type")
	guestID := r.URL.Query().Get("id")

	w.Header().Set("Content-Type", "application/json")

	if guestType == "" || guestID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing type or id"})
		return
	}

	if cfg.ProxmoxURL == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Proxmox not configured"})
		return
	}

	// Build Proxmox noVNC URL - the standard path for accessing console via Proxmox web UI
	pveType := "qemu"
	if guestType == "CT" {
		pveType = "lxc"
	}
	consoleType := "kvm"
	if pveType == "lxc" {
		consoleType = "lxc"
	}

	// Proxmox noVNC console URL format
	consoleURL := fmt.Sprintf("%s/?console=%s&novnc=1&vmid=%s&node=%s",
		cfg.ProxmoxURL, consoleType, guestID, cfg.ProxmoxNode)

	json.NewEncoder(w).Encode(map[string]string{"url": consoleURL})
}

// HandleProxmoxCreateGuest creates a new VM or CT on the Proxmox node.
func (h *Handler) HandleProxmoxCreateGuest(w http.ResponseWriter, r *http.Request) {
	cfg := h.Config
	w.Header().Set("Content-Type", "application/json")

	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		json.NewEncoder(w).Encode(map[string]string{"ok": "mock: creation simulated"})
		return
	}

	var body struct {
		Type     string `json:"type"`     // "VM" or "CT"
		VMID     int    `json:"vmid"`
		Name     string `json:"name"`
		Cores    int    `json:"cores"`
		Memory   int    `json:"memory"`   // in MB
		DiskSize int    `json:"disk"`     // in GB
		Template string `json:"template"` // for CT only
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if body.Name == "" || body.VMID == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Name and VMID required"})
		return
	}
	if body.Cores == 0 {
		body.Cores = 1
	}
	if body.Memory == 0 {
		body.Memory = 512
	}
	if body.DiskSize == 0 {
		body.DiskSize = 8
	}

	var err error
	if body.Type == "CT" {
		err = h.Proxmox.CreateCT(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret,
			body.VMID, body.Name, body.Cores, body.Memory, body.DiskSize, body.Template)
	} else {
		err = h.Proxmox.CreateVM(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret,
			body.VMID, body.Name, body.Cores, body.Memory, body.DiskSize)
	}

	if err != nil {
		slog.Error("Proxmox create guest failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Audit log
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	services.LogAudit(h.DB, 0, username, "ProxmoxCreate", fmt.Sprintf("Created %s #%d %s", body.Type, body.VMID, body.Name), r.RemoteAddr)

	json.NewEncoder(w).Encode(map[string]string{"ok": "creation started"})
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
