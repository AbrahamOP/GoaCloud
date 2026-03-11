package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"goacloud/internal/models"
)

type ReportData struct {
	GeneratedAt string
	CPU         int
	RAM         int
	Storage     int
	RAMUsedStr  string
	RAMTotalStr string
	VMs         []models.VM
	VMsRunning  int
	VMsStopped  int
	Apps        []models.App
	AppsUp      int
	AppsDown    int
}

func (h *Handler) HandleReport(w http.ResponseWriter, r *http.Request) {
	// Gather Proxmox stats
	h.ProxmoxCache.Mutex.RLock()
	stats := h.ProxmoxCache.Stats
	h.ProxmoxCache.Mutex.RUnlock()

	running := 0
	stopped := 0
	for _, vm := range stats.VMs {
		if vm.Status == "running" {
			running++
		} else {
			stopped++
		}
	}

	// Gather apps
	apps, err := h.getApps()
	if err != nil {
		slog.Error("Report: getApps error", "error", err)
		apps = []models.App{}
	}

	appsUp := 0
	appsDown := 0
	for _, a := range apps {
		if a.HealthStatus == "up" {
			appsUp++
		} else if a.HealthStatus == "down" {
			appsDown++
		}
	}

	data := ReportData{
		GeneratedAt: time.Now().Format("02/01/2006 15:04"),
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
	}

	if err := h.Templates.ExecuteTemplate(w, "report.html", data); err != nil {
		slog.Error("Report template error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}
