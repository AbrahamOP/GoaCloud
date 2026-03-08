package workers

import (
	"database/sql"
	"log/slog"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/services"
)

// StartCacheWorker starts the background worker that updates the VM IP cache.
func StartCacheWorker(db *sql.DB, cfg *config.Config, proxmox *services.ProxmoxService) {
	slog.Info("Starting VM Cache Worker...")
	updateVMCache(db, cfg, proxmox)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		updateVMCache(db, cfg, proxmox)
	}
}

func updateVMCache(db *sql.DB, cfg *config.Config, proxmox *services.ProxmoxService) {
	if cfg.ProxmoxURL == "" || cfg.ProxmoxTokenID == "" {
		slog.Info("Worker: Missing Proxmox configuration")
		return
	}

	slog.Info("Worker: Updating VM IP cache...")
	stats, err := proxmox.GetStats(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, true, true)
	if err != nil {
		slog.Error("Worker Error", "error", err)
		return
	}

	for _, vm := range stats.VMs {
		if _, err := db.Exec(`
			INSERT INTO vm_cache (vmid, name, ip_address, vm_type)
			VALUES (?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address), name = VALUES(name), updated_at = NOW()`,
			vm.ID, vm.Name, vm.IP, vm.Type); err != nil {
			slog.Error("Worker DB Error", "vmid", vm.ID, "error", err)
		}
	}
	slog.Info("Worker: VM cache updated", "count", len(stats.VMs))
}
