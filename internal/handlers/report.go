package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"goacloud/internal/models"
)

// ReportData holds all metrics rendered by the printable infrastructure report.
type ReportData struct {
	GeneratedAt string
	Username    string

	// Proxmox / infrastructure
	CPU         int
	RAM         int
	Storage     int
	RAMUsedStr  string
	RAMTotalStr string
	VMs         []models.VM
	VMsRunning  int
	VMsStopped  int

	// Applications
	Apps        []models.App
	AppsUp      int
	AppsDown    int
	AppsUnknown int

	// Security (Wazuh)
	WazuhAgents       []models.WazuhAgent
	WazuhActive       int
	WazuhDisconnected int
	VulnCritical      int
	VulnHigh          int
	VulnMedium        int
	VulnLow           int

	// Platform
	SSHKeysCount         int
	UsersCount           int
	AnsibleSchedulesN    int
	AuditLogs7d          int

	// Derived
	InfraHealth string // OK / Dégradé / Critique
}

func (h *Handler) HandleReport(w http.ResponseWriter, r *http.Request) {
	// --- Session / user ---
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)

	// --- Proxmox stats ---
	h.ProxmoxCache.Mutex.RLock()
	stats := h.ProxmoxCache.Stats
	h.ProxmoxCache.Mutex.RUnlock()

	running, stopped := 0, 0
	for _, vm := range stats.VMs {
		if vm.Status == "running" {
			running++
		} else {
			stopped++
		}
	}

	// --- Apps ---
	apps, err := h.getApps()
	if err != nil {
		slog.Error("Report: getApps error", "error", err)
		apps = []models.App{}
	}
	appsUp, appsDown, appsUnknown := 0, 0, 0
	for _, a := range apps {
		switch a.HealthStatus {
		case "up":
			appsUp++
		case "down":
			appsDown++
		default:
			appsUnknown++
		}
	}

	// --- Wazuh agents ---
	var (
		agents          []models.WazuhAgent
		active, offline int
		crit, high, med, low int
	)
	if h.WazuhCache != nil {
		h.WazuhCache.Mutex.RLock()
		agents = append(agents, h.WazuhCache.Agents...)
		h.WazuhCache.Mutex.RUnlock()
		for _, a := range agents {
			if a.Status == "active" {
				active++
			} else {
				offline++
			}
			crit += a.VulnSummary.Critical
			high += a.VulnSummary.High
			med += a.VulnSummary.Medium
			low += a.VulnSummary.Low
		}
	}

	// --- Counts from DB (best-effort, ignore errors silently in report) ---
	sshKeys := 0
	_ = h.DB.QueryRow("SELECT COUNT(*) FROM ssh_keys").Scan(&sshKeys)
	usersN := 0
	_ = h.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&usersN)
	schedulesN := 0
	_ = h.DB.QueryRow("SELECT COUNT(*) FROM ansible_schedules WHERE enabled = TRUE").Scan(&schedulesN)
	audit7d := 0
	_ = h.DB.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE created_at >= NOW() - INTERVAL 7 DAY").Scan(&audit7d)

	// --- Derived infrastructure health ---
	health := "OK"
	if stats.CPU >= 90 || stats.RAM >= 90 || stats.Storage >= 90 || appsDown > 0 || crit > 0 {
		health = "Critique"
	} else if stats.CPU >= 75 || stats.RAM >= 75 || stats.Storage >= 75 || high > 0 || offline > 0 {
		health = "Dégradé"
	}

	data := ReportData{
		GeneratedAt: time.Now().Format("02/01/2006 à 15:04"),
		Username:    username,

		CPU:         stats.CPU,
		RAM:         stats.RAM,
		Storage:     stats.Storage,
		RAMUsedStr:  stats.RAMUsedStr,
		RAMTotalStr: stats.RAMTotalStr,
		VMs:         stats.VMs,
		VMsRunning:  running,
		VMsStopped:  stopped,

		Apps:        apps,
		AppsUp:      appsUp,
		AppsDown:    appsDown,
		AppsUnknown: appsUnknown,

		WazuhAgents:       agents,
		WazuhActive:       active,
		WazuhDisconnected: offline,
		VulnCritical:      crit,
		VulnHigh:          high,
		VulnMedium:        med,
		VulnLow:           low,

		SSHKeysCount:      sshKeys,
		UsersCount:        usersN,
		AnsibleSchedulesN: schedulesN,
		AuditLogs7d:       audit7d,

		InfraHealth: health,
	}

	if err := h.Templates.ExecuteTemplate(w, "report.html", data); err != nil {
		slog.Error("Report template error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}
