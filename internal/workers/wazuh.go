package workers

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"goacloud/internal/models"
	"goacloud/internal/services"
)

// StartWazuhWorker starts the background worker that refreshes the Wazuh agent cache.
func StartWazuhWorker(
	ctx context.Context,
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	wazuhCache *models.WazuhCache,
	vulnCache *sync.Map,
) {
	slog.Info("Starting Wazuh Cache Worker...")
	UpdateWazuhCache(wazuhClient, wazuhIndexer, wazuhCache, vulnCache)

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Wazuh Worker stopped")
			return
		case <-ticker.C:
			UpdateWazuhCache(wazuhClient, wazuhIndexer, wazuhCache, vulnCache)
		}
	}
}

// UpdateWazuhCache fetches fresh agent data and vulnerability summaries.
func UpdateWazuhCache(
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	wazuhCache *models.WazuhCache,
	vulnCache *sync.Map,
) {
	if wazuhClient == nil {
		return
	}

	slog.Info("Worker: Updating Wazuh Cache...")
	agents, err := wazuhClient.GetAgents()
	if err != nil {
		slog.Error("Worker Error (Wazuh Agents)", "error", err)
		return
	}

	if wazuhIndexer != nil {
		var agentIDs []string
		for _, a := range agents {
			agentIDs = append(agentIDs, a.ID)
		}
		summaries, err := wazuhIndexer.GetVulnSummary(agentIDs)
		if err != nil {
			slog.Error("Worker Error (Vuln Summaries)", "error", err)
		} else {
			for i := range agents {
				if s, ok := summaries[agents[i].ID]; ok {
					agents[i].VulnSummary.Total = s.Total
					agents[i].VulnSummary.Critical = s.Critical
					agents[i].VulnSummary.High = s.High
					agents[i].VulnSummary.Medium = s.Medium
					agents[i].VulnSummary.Low = s.Low
				}
			}
		}
	}

	slog.Info("Worker: Prefetching vulnerability details...")
	for _, agent := range agents {
		var vulns []models.WazuhVuln
		var err error

		if wazuhIndexer != nil {
			vulns, err = wazuhIndexer.GetVulnerabilities(agent.ID)
		} else {
			vulns, err = wazuhClient.GetAgentVulnerabilitiesList(agent.ID)
		}

		if err != nil {
			slog.Error("Worker Error (Vuln Details)", "agentID", agent.ID, "error", err)
			continue
		}

		vulnCache.Store(agent.ID, models.CachedVulns{
			Data:   vulns,
			Expiry: time.Now().Add(10 * time.Minute),
		})

		if wazuhIndexer == nil {
			for i := range agents {
				if agents[i].ID == agent.ID {
					for _, v := range vulns {
						agents[i].VulnSummary.Total++
						switch v.Severity {
						case "Critical":
							agents[i].VulnSummary.Critical++
						case "High":
							agents[i].VulnSummary.High++
						case "Medium":
							agents[i].VulnSummary.Medium++
						case "Low":
							agents[i].VulnSummary.Low++
						}
					}
					break
				}
			}
		}
	}

	wazuhCache.Mutex.Lock()
	wazuhCache.Agents = agents
	wazuhCache.UpdatedAt = time.Now()
	wazuhCache.Mutex.Unlock()

	slog.Info("Worker: Wazuh Cache updated", "agents", len(agents))
}
