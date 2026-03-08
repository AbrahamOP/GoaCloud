package workers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/models"
	"goacloud/internal/services"
	"goacloud/internal/sse"
)

// StartCacheWorker starts the background worker that updates the VM IP cache and Proxmox stats cache.
func StartCacheWorker(db *sql.DB, cfg *config.Config, proxmox *services.ProxmoxService, cache *models.ProxmoxCache, broker *sse.Broker) {
	slog.Info("Starting VM Cache Worker...")
	updateVMCache(db, cfg, proxmox, cache, broker)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		updateVMCache(db, cfg, proxmox, cache, broker)
	}
}

func updateVMCache(db *sql.DB, cfg *config.Config, proxmox *services.ProxmoxService, cache *models.ProxmoxCache, broker *sse.Broker) {
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

	// Update in-memory Proxmox stats cache (used by /proxmox page)
	cache.Mutex.Lock()
	cache.Stats = stats
	cache.UpdatedAt = time.Now()
	cache.Mutex.Unlock()

	// Persist IPs to DB
	for _, vm := range stats.VMs {
		if _, err := db.Exec(`
			INSERT INTO vm_cache (vmid, name, ip_address, vm_type)
			VALUES (?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address), name = VALUES(name), updated_at = NOW()`,
			vm.ID, vm.Name, vm.IP, vm.Type); err != nil {
			slog.Error("Worker DB Error", "vmid", vm.ID, "error", err)
		}
	}
	// Record metrics for history/sparklines
	db.Exec("INSERT INTO metrics_history (cpu, ram, storage) VALUES (?, ?, ?)", stats.CPU, stats.RAM, stats.Storage)
	// Prune old entries (keep last 7 days)
	db.Exec("DELETE FROM metrics_history WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 7 DAY)")

	// Broadcast to SSE clients
	if broker != nil {
		if data, err := json.Marshal(stats); err == nil {
			broker.Publish(data)
		}
	}

	slog.Info("Worker: VM cache updated", "count", len(stats.VMs))
}
