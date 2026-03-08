package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"goacloud/internal/services"
)

// HandleSoar renders the SOAR page.
func (h *Handler) HandleSoar(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	currentUser, _ := session.Values["username"].(string)

	data := struct {
		User string
	}{User: currentUser}

	if err := h.Templates.ExecuteTemplate(w, "soar.html", data); err != nil {
		slog.Error("Template error (soar.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// HandleSoarConfig handles GET (read config) and POST (update config).
func (h *Handler) HandleSoarConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		h.SoarConfig.Mutex.RLock()
		json.NewEncoder(w).Encode(h.SoarConfig.Config)
		h.SoarConfig.Mutex.RUnlock()
		return
	}

	if r.Method == http.MethodPost {
		h.SoarConfig.Mutex.Lock()
		if err := json.NewDecoder(r.Body).Decode(&h.SoarConfig.Config); err != nil {
			h.SoarConfig.Mutex.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.SoarConfig.Mutex.Unlock()

		if err := h.saveSoarConfig(); err != nil {
			slog.Error("Failed to persist SOAR config", "error", err)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// HandleDiscordTest sends a test Discord alert with AI enrichment.
func (h *Handler) HandleDiscordTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := services.AIAlertContext{
		Title:       "Test Notification",
		Description: "Ceci est un test depuis GoaCloud SOAR avec analyse AI.",
		AgentName:   "Test-Server",
		AgentIP:     "127.0.0.1",
		FullLog:     "Jan 01 12:00:00 test-server sshd[123]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2",
		SourceIP:    "192.168.1.50",
		RuleID:      "5716",
		RuleLevel:   5,
	}
	h.sendEnrichedDiscordAlert(ctx, "info")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Notification sent"))
}

// HandleAITest tests the AI client connectivity.
func (h *Handler) HandleAITest(w http.ResponseWriter, r *http.Request) {
	if h.AIClient == nil {
		http.Error(w, "AI Client not configured", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	analysis, err := h.AIClient.EnrichAlert(ctx, services.AIAlertContext{
		Title:       "Test Connection",
		Description: "Testing connectivity to AI provider.",
		AgentName:   "Debug-Node",
		FullLog:     "Test log entry for debugging purposes.",
	})

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  fmt.Sprintf("%v", err),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"analysis": analysis,
	})
}

func (h *Handler) sendEnrichedDiscordAlert(alertCtx services.AIAlertContext, severity string) {
	if h.Discord == nil || !h.Discord.IsReady() {
		return
	}

	msg := alertCtx.Description

	if h.AIClient != nil {
		aiCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		analysis, err := h.AIClient.EnrichAlert(aiCtx, alertCtx)
		cancel()
		if err == nil {
			msg += fmt.Sprintf("\n\n🤖 **Analyse AI:**\n%s", analysis)
		} else {
			slog.Error("AI Enrichment Failed", "error", err)
		}
	}

	h.Discord.SendAlert(alertCtx.Title, msg, severity)
}

func (h *Handler) saveSoarConfig() error {
	h.SoarConfig.Mutex.RLock()
	cfg := h.SoarConfig.Config
	h.SoarConfig.Mutex.RUnlock()

	_, err := h.DB.Exec(`
		INSERT INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages)
		VALUES (1, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		alert_status = VALUES(alert_status),
		alert_ssh = VALUES(alert_ssh),
		alert_sudo = VALUES(alert_sudo),
		alert_fim = VALUES(alert_fim),
		alert_packages = VALUES(alert_packages)
	`, cfg.AlertStatus, cfg.AlertSSH, cfg.AlertSudo, cfg.AlertFIM, cfg.AlertPackages)

	if err != nil {
		slog.Error("Error saving SOAR config to DB", "error", err)
		return err
	}

	slog.Info("SOAR Config saved to DB successfully")
	return nil
}
