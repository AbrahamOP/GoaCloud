package workers

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"goacloud/internal/models"
	"goacloud/internal/services"
)

// StartSoarWorker starts the background worker that checks SOAR events and sends alerts.
func StartSoarWorker(
	ctx context.Context,
	db *sql.DB,
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	aiClient services.AIClient,
	discord *services.DiscordBot,
	soarConfig *models.SoarConfigState,
) {
	slog.Info("Starting SOAR Worker...")

	loadSoarConfig(db, soarConfig)

	agentStatus := &sync.Map{}
	alertDedup := &sync.Map{}

	// Populate initial state without alerting
	if wazuhClient != nil {
		agents, err := wazuhClient.GetAgents()
		if err == nil {
			for _, agent := range agents {
				agentStatus.Store(agent.ID, agent.Status)
			}
			slog.Info("SOAR Init: Loaded state", "agents", len(agents))
		}
	}

	// Start dedup cleaner
	go StartAlertDedupCleaner(ctx, alertDedup)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("SOAR Worker stopped")
			return
		case <-ticker.C:
			loadSoarConfig(db, soarConfig)
			checkSoarEvents(wazuhClient, wazuhIndexer, aiClient, discord, soarConfig, agentStatus, alertDedup)
		}
	}
}

// StartAlertDedupCleaner periodically removes old alert dedup entries to prevent memory leaks.
func StartAlertDedupCleaner(ctx context.Context, alertDedup *sync.Map) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Hour)
			alertDedup.Range(func(k, v interface{}) bool {
				if t, ok := v.(time.Time); ok && t.Before(cutoff) {
					alertDedup.Delete(k)
				}
				return true
			})
		}
	}
}

func loadSoarConfig(db *sql.DB, state *models.SoarConfigState) {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()

	row := db.QueryRow("SELECT alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages FROM soar_config WHERE id = 1")
	err := row.Scan(
		&state.Config.AlertStatus,
		&state.Config.AlertSSH,
		&state.Config.AlertSudo,
		&state.Config.AlertFIM,
		&state.Config.AlertPackages,
	)
	if err != nil {
		slog.Error("Error loading SOAR config from DB, using defaults", "error", err)
		state.Config = models.SoarConfig{AlertStatus: true, AlertSSH: true, AlertSudo: true, AlertFIM: true, AlertPackages: true}
	}
}

func checkSoarEvents(
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	aiClient services.AIClient,
	discord *services.DiscordBot,
	soarConfig *models.SoarConfigState,
	agentStatus *sync.Map,
	alertDedup *sync.Map,
) {
	if wazuhClient == nil {
		return
	}

	soarConfig.Mutex.RLock()
	cfg := soarConfig.Config
	soarConfig.Mutex.RUnlock()

	// 1. Check for Status Changes
	if cfg.AlertStatus {
		agents, err := wazuhClient.GetAgents()
		if err != nil {
			slog.Error("SOAR Worker Error (GetAgents)", "error", err)
		} else {
			for _, agent := range agents {
				prevStatusInterface, loaded := agentStatus.Load(agent.ID)
				agentStatus.Store(agent.ID, agent.Status)

				if loaded {
					prevStatus := prevStatusInterface.(string)
					if prevStatus != agent.Status {
						slog.Info("SOAR State Change", "agent", agent.Name, "from", prevStatus, "to", agent.Status)

						if agent.Status == "disconnected" {
							ctx := services.AIAlertContext{
								Title:       "🔴 Agent Perdu",
								Description: fmt.Sprintf("L'agent **%s** ne répond plus.", agent.Name),
								AgentName:   agent.Name,
								AgentIP:     agent.IP,
								RuleLevel:   10,
							}
							go sendEnrichedAlert(ctx, "critical", aiClient, discord)
						} else if agent.Status == "active" && prevStatus == "disconnected" {
							ctx := services.AIAlertContext{
								Title:       "🟢 Agent Retrouvé",
								Description: fmt.Sprintf("L'agent **%s** est de nouveau en ligne.", agent.Name),
								AgentName:   agent.Name,
								AgentIP:     agent.IP,
								RuleLevel:   0,
							}
							go sendEnrichedAlert(ctx, "info", aiClient, discord)
						}
					}
				}
			}
		}
	}

	// 2. Check for Indexer Alerts
	if wazuhIndexer != nil {
		alerts, err := wazuhIndexer.GetRecentAlerts(2 * time.Minute)
		if err != nil {
			slog.Error("SOAR Worker Error (Indexer)", "error", err)
		} else {
			for _, alert := range alerts {
				alertKey := alert.Agent.ID + alert.Rule.ID + alert.Timestamp
				if _, loaded := alertDedup.Load(alertKey); !loaded {
					alertDedup.Store(alertKey, time.Now())

					var title, msg, severity string
					shouldSend := false

					switch alert.Rule.ID {
					case "5402":
						if cfg.AlertSudo {
							shouldSend = true
							title = "👑 Élévation de Privilèges"
							msg = fmt.Sprintf("**Machine:** %s\n**Event:** Sudo to ROOT\n**Log:** `%s`", alert.Agent.Name, alert.FullLog)
							severity = "critical"
						}
					case "550", "553", "554":
						if cfg.AlertFIM {
							shouldSend = true
							title = "📝 Intégrité des Fichiers"
							msg = fmt.Sprintf("**Machine:** %s\n**Fichier:** `%s`\n**Event:** %s", alert.Agent.Name, alert.Syscheck.Path, alert.Rule.Description)
							severity = "high"
						}
					case "2902", "2903":
						if cfg.AlertPackages {
							shouldSend = true
							title = "📦 Gestion Logicielle"
							msg = fmt.Sprintf("**Machine:** %s\n**Changement:** %s\n**Log:** `%s`", alert.Agent.Name, alert.Rule.Description, alert.FullLog)
							severity = "info"
						}
					default:
						if cfg.AlertSSH {
							shouldSend = true
							title = "🛡️ Alerte Sécurité"
							msg = fmt.Sprintf("**Machine:** %s\n**Event:** %s\n**Source IP:** %s", alert.Agent.Name, alert.Rule.Description, alert.Data.SrcIP)
							severity = "medium"
							if alert.Rule.ID == "5712" {
								severity = "high"
							}
						}
					}

					if shouldSend {
						aiCtx := services.AIAlertContext{
							Title:       title,
							Description: msg,
							AgentName:   alert.Agent.Name,
							AgentIP:     alert.Agent.IP,
							RuleID:      alert.Rule.ID,
							RuleLevel:   alert.Rule.Level,
							FullLog:     alert.FullLog,
							SourceIP:    alert.Data.SrcIP,
						}
						go sendEnrichedAlert(aiCtx, severity, aiClient, discord)
					}
				}
			}
		}
	}
}

func sendEnrichedAlert(alertCtx services.AIAlertContext, severity string, aiClient services.AIClient, discord *services.DiscordBot) {
	if discord == nil || !discord.IsReady() {
		return
	}

	msg := alertCtx.Description

	if aiClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		analysis, err := aiClient.EnrichAlert(ctx, alertCtx)
		cancel()
		if err == nil {
			msg += fmt.Sprintf("\n\n🤖 **Analyse AI:**\n%s", analysis)
		} else {
			slog.Error("AI Enrichment Failed", "error", err)
		}
	}

	discord.SendAlert(alertCtx.Title, msg, severity)
}
