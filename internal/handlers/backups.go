package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/services"
)

// HandleBackupPage renders the backup management & verification dashboard.
// Admin-only (gated at the router level): it will trigger restores/destroys.
// It lists the latest backups from Proxmox, auto-discovers targets and shows
// each one's RPO freshness status (N1 integrity check).
func (h *Handler) HandleBackupPage(w http.ResponseWriter, r *http.Request) {
	views, summary, err := h.Backup.Dashboard()
	if err != nil {
		slog.Error("backup: dashboard", "error", err)
	}

	// Rotation config now lives in the DB (backup_settings), editable from the UI
	// and read live by the worker. Fall back to defaults on error.
	settings, err := h.Backup.GetSettings()
	if err != nil {
		slog.Error("backup: get settings", "error", err)
	}

	// Whether the Proxmox channel is connected, so the page can guide a fresh admin
	// to /parametres/sauvegarde instead of showing an empty, jargon-y table. Reuses the
	// onboarding card logic (DB read only, no network call).
	channelConfigured := h.channelCard().Configured

	data := struct {
		Targets           []models.BackupTargetView
		Summary           models.BackupSummary
		RotationEnabled   bool
		RotationHour      int
		AutoVerifyEnabled bool
		ChannelConfigured bool
	}{
		Targets:           views,
		Summary:           summary,
		RotationEnabled:   settings.RotationEnabled,
		RotationHour:      settings.RotationHour,
		AutoVerifyEnabled: settings.AutoVerifyEnabled,
		ChannelConfigured: channelConfigured,
	}

	if err := h.Templates.ExecuteTemplate(w, "backups.html", data); err != nil {
		slog.Error("backup: render page", "error", err)
	}
}

// HandleBackupCreate triggers an on-demand vzdump for a target (POST /api/backups/create).
// Admin-only: gated at the router level, with an inline defense-in-depth check.
// Accepts {target_id, destination, remote} as JSON or form-encoded. destination
// defaults to "local"; for "both"/"remote" a real rclone remote is required.
// Returns the new run ID immediately.
func (h *Handler) HandleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	// Read target_id / destination / remote from JSON body or form values.
	targetID := 0
	destination := ""
	remote := ""
	var body struct {
		TargetID    int    `json:"target_id"`
		Destination string `json:"destination"`
		Remote      string `json:"remote"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.TargetID > 0 {
		targetID = body.TargetID
		destination = body.Destination
		remote = body.Remote
	} else if v := r.FormValue("target_id"); v != "" {
		targetID, _ = strconv.Atoi(v)
		destination = r.FormValue("destination")
		remote = r.FormValue("remote")
	}
	if targetID <= 0 {
		http.Error(w, "Invalid target_id", http.StatusBadRequest)
		return
	}

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)

	runID, err := h.Backup.TriggerBackup(targetID, destination, remote, username)
	if err != nil {
		slog.Error("backup: trigger", "target_id", targetID, "error", err)
		if errors.Is(err, services.ErrBackupInProgress) {
			http.Error(w, "Une sauvegarde est déjà en cours pour cette cible", http.StatusConflict)
			return
		}
		if errors.Is(err, services.ErrUnknownRemote) {
			http.Error(w, "Destination invalide : choisissez un remote rclone existant", http.StatusBadRequest)
			return
		}
		// Generic message to the client; the detail is already logged above.
		http.Error(w, "Échec du déclenchement de la sauvegarde", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"run_id": runID, "status": "running"})
}

// HandleBackupRemotes returns the user's rclone remotes and their capacity as JSON
// (GET /api/backups/remotes). Used to populate the destination selector and the
// "Destinations" view. Remote names come LIVE from the helper — never hardcoded.
func (h *Handler) HandleBackupRemotes(w http.ResponseWriter, r *http.Request) {
	remotes, err := h.Backup.ListRemotes()
	if err != nil {
		// Soft-fail with an empty list: the UI degrades to "Local only" rather than
		// breaking the page when the channel/rclone is unavailable.
		slog.Warn("backup: list remotes", "error", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]services.RemoteInfo{})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(remotes)
}

// HandleBackupTest triggers a restore test for a target (POST /api/backups/test).
// Admin-only: gated at the router level, with an inline defense-in-depth check.
// This launches a DESTRUCTIVE restore into a disposable sandbox VMID (9500-9599)
// for N2/N3. Accepts {target_id, level} as JSON or form-encoded; level defaults
// to N3. Returns the new test ID immediately (the work runs asynchronously).
func (h *Handler) HandleBackupTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	targetID := 0
	level := ""
	var body struct {
		TargetID int    `json:"target_id"`
		Level    string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.TargetID > 0 {
		targetID = body.TargetID
		level = body.Level
	}
	if targetID <= 0 {
		if v := r.FormValue("target_id"); v != "" {
			targetID, _ = strconv.Atoi(v)
		}
		if level == "" {
			level = r.FormValue("level")
		}
	}
	if targetID <= 0 {
		http.Error(w, "Invalid target_id", http.StatusBadRequest)
		return
	}

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	if username == "" {
		username = "manual"
	}

	testID, err := h.Backup.RunRestoreTest(targetID, level, username)
	if err != nil {
		slog.Error("restore-test: trigger", "target_id", targetID, "error", err)
		if errors.Is(err, services.ErrRestoreTestInProgress) {
			http.Error(w, "Un test de restauration est déjà en cours pour cette cible", http.StatusConflict)
			return
		}
		http.Error(w, "Échec du déclenchement du test de restauration", http.StatusInternalServerError)
		return
	}

	// A restore test restores a production archive into a disposable guest and
	// DESTROYS it afterwards: the trail names the target, the requested level and
	// the test id, so the verdict row (restore_tests) can be tied back to whoever
	// asked for it.
	requestedLevel := strings.ToUpper(strings.TrimSpace(level))
	if requestedLevel == "" {
		requestedLevel = "N3 (par défaut)"
	}
	go services.LogAudit(h.DB, 0, username, "BackupRestoreTest",
		fmt.Sprintf("Test de restauration déclenché sur la cible #%d (niveau demandé : %s, test #%d)",
			targetID, requestedLevel, testID), middleware.RealIP(r))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"test_id": testID, "verdict": "running"})
}

// HandleBackupTestsList returns recent restore tests as JSON (GET /api/backups/tests).
// Optional ?target_id= filters by target; otherwise all targets (capped at 50).
func (h *Handler) HandleBackupTestsList(w http.ResponseWriter, r *http.Request) {
	targetID := 0
	if v := r.URL.Query().Get("target_id"); v != "" {
		targetID, _ = strconv.Atoi(v)
	}

	tests, err := h.Backup.RecentTests(targetID, 50)
	if err != nil {
		slog.Error("restore-test: list tests", "error", err)
		http.Error(w, "Failed to list tests", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tests)
}

// HandleBackupRunsList returns recent backup runs as JSON (GET /api/backups/runs).
// Optional ?target_id= filters by target; otherwise all targets (capped at 50).
func (h *Handler) HandleBackupRunsList(w http.ResponseWriter, r *http.Request) {
	targetID := 0
	if v := r.URL.Query().Get("target_id"); v != "" {
		targetID, _ = strconv.Atoi(v)
	}

	runs, err := h.Backup.RecentRuns(targetID, 50)
	if err != nil {
		slog.Error("backup: list runs", "error", err)
		http.Error(w, "Failed to list runs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runs)
}

// HandleBackupSettings updates the global rotation settings (POST /api/backups/settings).
// Admin-only: gated at the router level, with an inline defense-in-depth check.
// Accepts {rotation_enabled, rotation_hour} as JSON. The worker reads these live
// from the DB so the change takes effect without a redeploy.
func (h *Handler) HandleBackupSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var body struct {
		RotationEnabled   bool `json:"rotation_enabled"`
		RotationHour      int  `json:"rotation_hour"`
		AutoVerifyEnabled bool `json:"auto_verify_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.Backup.SetSettings(body.RotationEnabled, body.RotationHour, body.AutoVerifyEnabled); err != nil {
		slog.Error("backup: set settings", "error", err)
		http.Error(w, "Paramètres invalides (heure 0-23)", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// HandleBackupTargetSettings updates a single target's healthcheck + retention
// (POST /api/backups/target-settings). Admin-only: gated at the router level,
// with an inline defense-in-depth check. Accepts
// {target_id, healthcheck_type, healthcheck_target, retention_count} as JSON.
func (h *Handler) HandleBackupTargetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var body struct {
		TargetID          int    `json:"target_id"`
		HealthcheckType   string `json:"healthcheck_type"`
		HealthcheckTarget string `json:"healthcheck_target"`
		RetentionCount    int    `json:"retention_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.TargetID <= 0 {
		http.Error(w, "Invalid target_id", http.StatusBadRequest)
		return
	}

	if err := h.Backup.UpdateTargetSettings(body.TargetID, body.HealthcheckType, body.HealthcheckTarget, body.RetentionCount); err != nil {
		slog.Error("backup: update target settings", "target_id", body.TargetID, "error", err)
		http.Error(w, "Paramètres de cible invalides", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// HandleBackupAvailableGuests liste les machines Proxmox connues (cache de monitoring)
// qui ne sont pas encore des cibles de sauvegarde, pour le sélecteur « Ajouter une
// machine » (GET /api/backups/available-guests). Admin-only.
func (h *Handler) HandleBackupAvailableGuests(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	guests, err := h.Backup.AvailableGuests()
	if err != nil {
		slog.Error("backup: available guests", "error", err)
		http.Error(w, "Erreur lors de la récupération des machines", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(guests)
}

// HandleBackupAddTarget enregistre manuellement une cible de sauvegarde
// (POST /api/backups/targets, {vmid, type, name}). Admin-only, avec garde inline.
func (h *Handler) HandleBackupAddTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	var body struct {
		VMID int    `json:"vmid"`
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Corps de requête invalide", http.StatusBadRequest)
		return
	}
	if err := h.Backup.AddTarget(body.VMID, body.Type, body.Name); err != nil {
		slog.Error("backup: add target", "vmid", body.VMID, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}
