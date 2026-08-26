package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"goacore/internal/middleware"
	"goacore/internal/services"
)

// HandleSoar renders the SOAR page.
func (h *Handler) HandleSoar(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	currentUser, _ := session.Values["username"].(string)

	// Resolve the effective AI provider/model for display with the boot precedence
	// DB > env, so the page reflects an in-app onboarding change without a restart.
	aiProvider, aiModel := h.Config.AIProvider, h.Config.AIModel
	if conn, _, err := h.Connections.GetAI(); err == nil && conn != nil {
		if provider, _ := services.AIExtra(conn); provider != "" {
			aiProvider = provider
		}
		if conn.TokenID != "" {
			aiModel = conn.TokenID
		}
	}
	// A nil AI() snapshot means the service is unconfigured/disabled: surface that so
	// the page does not advertise an enrichment provider that will never fire.
	aiConfigured := h.Registry.AI() != nil

	data := struct {
		User         string
		AIProvider   string
		AIModel      string
		AIConfigured bool
	}{
		User:         currentUser,
		AIProvider:   aiProvider,
		AIModel:      aiModel,
		AIConfigured: aiConfigured,
	}

	if err := h.Templates.ExecuteTemplate(w, "soar.html", data); err != nil {
		slog.Error("Template error (soar.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// HandleSoarConfig handles GET (read config) and POST (update config).
// POST requires Admin role.
func (h *Handler) HandleSoarConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		h.SoarConfig.Mutex.RLock()
		json.NewEncoder(w).Encode(h.SoarConfig.Config)
		h.SoarConfig.Mutex.RUnlock()
		return
	}

	if r.Method == http.MethodPost {
		if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
			return
		}

		h.SoarConfig.Mutex.Lock()
		if err := json.NewDecoder(r.Body).Decode(&h.SoarConfig.Config); err != nil {
			h.SoarConfig.Mutex.Unlock()
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		h.SoarConfig.Mutex.Unlock()

		// Persist before acknowledging: a failed write that returned 200 would let
		// the admin believe the toggle survived a reboot when it did not (silent
		// data loss). Surface the failure as 500 so the UI can report it.
		if err := h.saveSoarConfig(); err != nil {
			slog.Error("Failed to persist SOAR config", "error", err)
			http.Error(w, "Failed to persist SOAR configuration", http.StatusInternalServerError)
			return
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
		Description: "Ceci est un test depuis GoaCore SOAR avec analyse AI.",
		AgentName:   "Test-Server",
		AgentIP:     "127.0.0.1",
		FullLog:     "Jan 01 12:00:00 test-server sshd[123]: Failed password for invalid user admin from 203.0.113.50 port 22 ssh2",
		SourceIP:    "203.0.113.50",
		RuleID:      "5716",
		RuleLevel:   5,
	}
	h.sendEnrichedDiscordAlert(r.Context(), ctx, "info")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Notification sent"))
}

// HandleAITest tests the AI client connectivity.
func (h *Handler) HandleAITest(w http.ResponseWriter, r *http.Request) {
	// Read the AI client live from the registry (hot-reloadable); nil ⇒ unconfigured.
	ai := h.Registry.AI()
	if ai == nil {
		http.Error(w, "AI Client not configured", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	analysis, err := ai.EnrichAlert(ctx, services.AIAlertContext{
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

// sendEnrichedDiscordAlert is the SYNCHRONOUS test path (POST /api/soar/discord/test):
// an admin clicks "send test", waits, and gets immediate feedback. It is deliberately
// NOT factorized with workers.sendEnrichedAlert and deliberately does NOT go through the
// worker's aiEnrichSem semaphore:
//   - the two live in different packages (handlers vs workers) and the semaphore is a
//     workers-package var scoped to the autonomous SOAR tick, where a burst of alerts can
//     fan out N concurrent 120s Ollama calls; that gate must not be shared with a one-shot,
//     user-initiated test (a single call, no burst) or the admin's "test" could block behind
//     a backlog of real enrichments;
//   - the worker version also wraps the call in a panic-recover closure to avoid leaking the
//     only semaphore slot — a guarantee that only makes sense when the slot exists.
//
// Folding both into one services helper would have to thread the semaphore + recover policy
// through as params, pushing worker-specific concurrency rules out of the worker for marginal
// dedup (only the trailing SendAlert + "🤖 Analyse AI" formatting is truly shared). Per the
// vague-1 guardrail ("si la factorisation est risquée, ne pas la forcer"), they stay separate.
func (h *Handler) sendEnrichedDiscordAlert(reqCtx context.Context, alertCtx services.AIAlertContext, severity string) {
	// Read the live Discord bot and AI client from the registry at emit time, so an
	// in-app hot-reload of either is picked up without restart (both nil-guarded).
	discord := h.Registry.Discord()
	if discord == nil || !discord.IsReady() {
		return
	}

	msg := alertCtx.Description

	// Post first, enrich after: même contrat que le worker (l'alerte part tout
	// de suite, l'analyse IA arrive par édition du message), sans le sémaphore
	// pour les raisons documentées ci-dessus.
	// Empreinte vide : une alerte de test ne doit pas entrer dans le triage
	// apprenant (pas de boutons, pas de row soar_triage).
	messageID, err := discord.SendSoarAlert(alertCtx.Title, msg, severity, "")
	if err != nil {
		slog.Error("Discord SOAR alert failed", "error", err)
		return
	}

	if ai := h.Registry.AI(); ai != nil {
		// Borné par le contexte de la requête admin (le serveur coupe à
		// WriteTimeout=60s de toute façon) : si l'admin ferme, on annule.
		aiCtx, cancel := context.WithTimeout(reqCtx, 120*time.Second)
		analysis, err := ai.EnrichAlert(aiCtx, alertCtx)
		cancel()
		if err != nil {
			slog.Error("AI Enrichment Failed", "error", err)
			return
		}
		if err := discord.EditSoarAlertAnalysis(messageID, alertCtx.Title, msg, severity, analysis, ""); err != nil {
			slog.Error("Discord SOAR alert enrichment edit failed", "error", err, "message_id", messageID)
		}
	}
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
