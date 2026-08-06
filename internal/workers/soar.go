package workers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"goacore/internal/models"
	"goacore/internal/services"
)

// StartSoarWorker starts the background worker that checks SOAR events and sends alerts.
//
// The Wazuh API, Wazuh Indexer, AI AND Discord clients are all read LIVE from the
// registry at the top of each tick (registry.Wazuh()/Indexer()/AI()/Discord()) rather
// than captured once, so an in-app onboarding hot-reload takes effect on the next tick.
// Each tick's Discord snapshot is handed to checkSoarEvents / sendEnrichedAlert as a
// plain *DiscordBot param (their internal signatures are unchanged): the async
// go sendEnrichedAlert(...) therefore uses the tick's bot, not a later concurrent swap.
func StartSoarWorker(
	ctx context.Context,
	db *sql.DB,
	registry *services.ServiceRegistry,
	soarConfig *models.SoarConfigState,
) {
	slog.Info("Starting SOAR Worker...")

	// Initial load; errors are logged inside loadSoarConfig (fail-open defaults on
	// a never-loaded DB error), so the worker can still start and alert.
	_ = loadSoarConfig(db, soarConfig)

	agentStatus := &sync.Map{}
	alertDedup := &sync.Map{}

	// Populate initial state without alerting (read the Wazuh client live).
	if wazuhClient := registry.Wazuh(); wazuhClient != nil {
		agents, err := wazuhClient.GetAgents()
		if err == nil {
			for _, agent := range agents {
				agentStatus.Store(agent.ID, agent.Status)
			}
			slog.Info("SOAR Init: Loaded state", "agents", len(agents))
		}
	}

	// Rehydrate the dedup set from the DB so a restart does not re-post alerts
	// already sent: the in-memory map alone resets on restart while the lookback
	// window re-reads up to maxAlertLookback of history (the known "alertes
	// rejouées après restart" issue).
	if n := loadAlertDedup(db, alertDedup); n > 0 {
		slog.Info("SOAR Init: Rehydrated alert dedup", "entries", n)
	}

	// Start dedup cleaner
	go StartAlertDedupCleaner(ctx, db, alertDedup)

	// Track the last successful indexer poll so the lookback window can absorb
	// transient outages instead of silently dropping alerts that occurred in the
	// gap. Persisted in soar_state across restarts for the same anti-replay reason.
	lastAlertPoll := time.Now().Add(-2 * time.Minute)
	if v, err := loadSoarState(db, "last_alert_poll"); err == nil && v != "" {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			lastAlertPoll = t
		}
	}

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("SOAR Worker stopped")
			return
		case <-ticker.C:
			// A refresh error keeps the last-known-good config (logged inside);
			// proceed with the current snapshot rather than skipping the tick.
			_ = loadSoarConfig(db, soarConfig)
			// Snapshot ALL hot-reloadable clients (incl. Discord) for this tick.
			checkSoarEvents(ctx, db, registry.Wazuh(), registry.Indexer(), registry.AI(), registry.Discord(), soarConfig, agentStatus, alertDedup, &lastAlertPoll)
		}
	}
}

// maxAlertLookback caps the indexer query window so a long outage cannot trigger
// an unbounded (and expensive) range query when the worker recovers.
const maxAlertLookback = 30 * time.Minute

// alertDedupKey returns the deduplication key of one indexer alert.
//
// Wazuh's own alert id ("<epoch>.<offset>") is unique per alert, so it is the only
// correct key during a burst: the previous key (agent.id:rule.id:timestamp) takes the
// SAME value for a hundred SSH failures of the same second, and ninety-nine distinct
// alerts were then discarded as "already seen" — precisely when the operator needs
// them most.
//
// Fallback to the legacy composite key when the id is empty: an older indexer (or a
// mapping that does not surface `id`) must still dedup, and the entries already
// persisted in soar_alert_dedup before this fix are in that shape.
func alertDedupKey(a services.WazuhAlert) string {
	if id := strings.TrimSpace(a.ID); id != "" {
		return id
	}
	return a.Agent.ID + ":" + a.Rule.ID + ":" + a.Timestamp
}

// nextAlertCursor computes where the alert cursor must land after one poll.
//
//   - Complete window: the whole window was read, so the cursor advances to the start
//     of the poll (the pre-existing behaviour).
//   - TRUNCATED window (hard cap reached during an attack peak, or an unusable sort):
//     everything older than the last alert read has NOT been read. Advancing to
//     pollStart would skip that tail for good — a security alert skipped is skipped
//     forever — so the cursor stays on the oldest alert actually returned and the next
//     tick resumes there.
//
// If that timestamp is unusable (empty window, unparsable format), we fall back to
// pollStart: without a reliable marker, keeping the previous behaviour is better than
// inventing a position (and a cursor stuck in the past would re-post the same window
// at every tick).
func nextAlertCursor(win services.AlertWindow, pollStart time.Time) time.Time {
	if !win.Truncated {
		return pollStart
	}
	t, ok := win.OldestReturnedTime()
	if !ok {
		return pollStart
	}
	return t
}

// maxConcurrentEnrichments bounds how many AI (Ollama) enrichments run at once.
// A single tick can fan out one `go sendEnrichedAlert(...)` per state change and
// per indexer alert; without a cap a burst would launch N goroutines that each
// hold a 120s Ollama call open in parallel, saturating the model and producing
// timeouts in cascade (the known "AI enrichment concurrency" failure). Keeping
// this at 1 serializes the heavy calls (the cheap part — the blocked goroutine —
// just waits on the channel, so no alert is dropped). Bump to 2 only if the
// backing model is provisioned for it.
const maxConcurrentEnrichments = 1

// aiEnrichSem is a counting semaphore (buffered chan) that gates concurrent AI
// enrichments across every async sendEnrichedAlert goroutine.
var aiEnrichSem = make(chan struct{}, maxConcurrentEnrichments)

// StartAlertDedupCleaner periodically removes old alert dedup entries (memory
// map + soar_alert_dedup table) to prevent unbounded growth. db may be nil in
// tests; the DB sweep is then skipped.
func StartAlertDedupCleaner(ctx context.Context, db *sql.DB, alertDedup *sync.Map) {
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
			if db != nil {
				if _, err := db.Exec("DELETE FROM soar_alert_dedup WHERE seen_at < ?", cutoff.Unix()); err != nil {
					slog.Error("SOAR dedup DB cleanup failed", "error", err)
				}
			}
		}
	}
}

// loadSoarState reads one key from the soar_state KV table ("" if absent).
// db may be nil in tests → same "" fallback as an absent key.
func loadSoarState(db *sql.DB, key string) (string, error) {
	if db == nil {
		return "", nil
	}
	var v string
	err := db.QueryRow("SELECT v FROM soar_state WHERE k = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// saveSoarState upserts one key into the soar_state KV table (no-op if db is nil).
func saveSoarState(db *sql.DB, key, value string) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(
		"INSERT INTO soar_state (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)",
		key, value)
	return err
}

// loadAlertDedup rehydrates the in-memory dedup map from soar_alert_dedup
// (entries of the last 2h only — same horizon as the cleaner). Returns the
// number of entries loaded; errors are logged, not fatal (worst case: a few
// duplicate Discord posts right after a restart, the pre-existing behaviour).
func loadAlertDedup(db *sql.DB, alertDedup *sync.Map) int {
	if db == nil {
		return 0
	}
	rows, err := db.Query(
		"SELECT alert_key, seen_at FROM soar_alert_dedup WHERE seen_at >= ?",
		time.Now().Add(-2*time.Hour).Unix())
	if err != nil {
		slog.Error("SOAR dedup rehydration failed", "error", err)
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var key string
		var seenAt int64
		if err := rows.Scan(&key, &seenAt); err != nil {
			continue
		}
		alertDedup.Store(key, time.Unix(seenAt, 0))
		n++
	}
	return n
}

// persistAlertDedup records one posted alert key in soar_alert_dedup so it
// survives restarts. Best effort: on error the in-memory map still dedups
// within the current process lifetime.
func persistAlertDedup(db *sql.DB, key string) {
	if db == nil {
		return
	}
	if _, err := db.Exec(
		"INSERT IGNORE INTO soar_alert_dedup (alert_key, seen_at) VALUES (?, ?)",
		key, time.Now().Unix()); err != nil {
		slog.Error("SOAR dedup persistence failed", "error", err)
	}
}

// defaultSoarConfig is the fail-open default (every alert category enabled) used
// only when no config row exists yet — never to clobber a previously loaded one.
func defaultSoarConfig() models.SoarConfig {
	return models.SoarConfig{AlertStatus: true, AlertSSH: true, AlertSudo: true, AlertFIM: true, AlertPackages: true}
}

// loadSoarConfig refreshes state.Config from the DB. It returns the DB error (if
// any) so the caller can surface a real failure instead of it being swallowed.
//
// Failure handling avoids the silent "reset to all-enabled" bug:
//   - sql.ErrNoRows (no config saved yet): apply the fail-open defaults. This is
//     a legitimate first-boot state, not an error.
//   - any other DB error AFTER a good load: keep the last-known-good config so a
//     transient outage cannot quietly override an admin's saved toggles (e.g. a
//     deliberately disabled SSH alert flipping back on).
//   - any other DB error BEFORE the first good load: fall back to the fail-open
//     defaults (we have no better config and muting all alerting is worse), but
//     still report the error to the caller.
func loadSoarConfig(db *sql.DB, state *models.SoarConfigState) error {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()

	var cfg models.SoarConfig
	row := db.QueryRow("SELECT alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages FROM soar_config WHERE id = 1")
	err := row.Scan(
		&cfg.AlertStatus,
		&cfg.AlertSSH,
		&cfg.AlertSudo,
		&cfg.AlertFIM,
		&cfg.AlertPackages,
	)
	switch {
	case err == nil:
		state.Config = cfg
		state.Loaded = true
		return nil
	case errors.Is(err, sql.ErrNoRows):
		// No config persisted yet: legitimate first boot, use defaults.
		state.Config = defaultSoarConfig()
		state.Loaded = true
		return nil
	default:
		if state.Loaded {
			// Keep the last-known-good config; do not reset an admin's choices.
			slog.Error("Error refreshing SOAR config from DB, keeping last-known-good config", "error", err)
		} else {
			// Never loaded successfully: fail open so security alerting is not muted.
			slog.Error("Error loading SOAR config from DB, using fail-open defaults", "error", err)
			state.Config = defaultSoarConfig()
		}
		return err
	}
}

func checkSoarEvents(
	ctx context.Context,
	db *sql.DB,
	wazuhClient *services.WazuhClient,
	wazuhIndexer *services.WazuhIndexerClient,
	aiClient services.AIClient,
	discord *services.DiscordBot,
	soarConfig *models.SoarConfigState,
	agentStatus *sync.Map,
	alertDedup *sync.Map,
	lastAlertPoll *time.Time,
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

						// Sur échec du post Discord, restaurer le statut précédent :
						// la transition sera re-détectée (et re-alertée) au tick
						// suivant tant que l'état diverge — un "Agent Perdu" ne doit
						// pas être avalé par un hoquet Discord.
						agentID, prev := agent.ID, prevStatus
						retryOnFail := func(sent bool) {
							if !sent {
								agentStatus.Store(agentID, prev)
							}
						}
						if agent.Status == "disconnected" {
							alertInfo := services.AIAlertContext{
								Title:       "🔴 Agent Perdu",
								Description: fmt.Sprintf("L'agent **%s** ne répond plus.", agent.Name),
								AgentName:   agent.Name,
								AgentIP:     agent.IP,
								RuleLevel:   10,
							}
							go sendEnrichedAlert(ctx, alertInfo, "critical", aiClient, discord, retryOnFail)
						} else if agent.Status == "active" && prevStatus == "disconnected" {
							alertInfo := services.AIAlertContext{
								Title:       "🟢 Agent Retrouvé",
								Description: fmt.Sprintf("L'agent **%s** est de nouveau en ligne.", agent.Name),
								AgentName:   agent.Name,
								AgentIP:     agent.IP,
								RuleLevel:   0,
							}
							go sendEnrichedAlert(ctx, alertInfo, "info", aiClient, discord, retryOnFail)
						}
					}
				}
			}
		}
	}

	// 2. Check for Indexer Alerts
	if wazuhIndexer != nil {
		// Look back far enough to cover every cycle missed since the last
		// successful poll (capped), so a transient indexer outage doesn't
		// drop alerts. A 30s buffer guards against clock skew / ingest lag.
		pollStart := time.Now()
		lookback := time.Since(*lastAlertPoll) + 30*time.Second
		if lookback > maxAlertLookback {
			lookback = maxAlertLookback
			slog.Warn("SOAR lookback capped — alerts older than the cap may have been missed", "cap", maxAlertLookback)
		}

		win, err := wazuhIndexer.GetRecentAlertsWindow(lookback)
		if err != nil {
			slog.Error("SOAR Worker Error (Indexer)", "error", err)
		} else {
			// Le curseur ne dépasse JAMAIS ce qui a réellement été lu : sur une
			// fenêtre tronquée (plafond atteint pendant un pic), il reste sur la
			// plus ancienne alerte lue pour que le tick suivant reprenne la queue
			// de fenêtre au lieu de la perdre définitivement.
			cursor := nextAlertCursor(win, pollStart)
			if win.Truncated {
				// Signal d'exploitation : une troncature dit que le pic dépasse ce
				// qu'un tick peut absorber. On la journalise explicitement, avec le
				// point de reprise, plutôt que de la laisser deviner.
				slog.Warn("SOAR : fenêtre d'alertes tronquée — reprise au tick suivant depuis la plus ancienne alerte lue",
					"alertes_lues", len(win.Alerts),
					"total_indexeur", win.TotalReported,
					"curseur", cursor.Format(time.RFC3339))
			}
			*lastAlertPoll = cursor
			// Persist the cursor so a restart resumes where this poll ended
			// instead of re-reading (and re-posting) the lookback window.
			if serr := saveSoarState(db, "last_alert_poll", cursor.Format(time.RFC3339)); serr != nil {
				slog.Error("SOAR state persistence failed", "error", serr)
			}
			for _, alert := range win.Alerts {
				alertKey := alertDedupKey(alert)
				if _, loaded := alertDedup.Load(alertKey); !loaded {
					// Store mémoire tout de suite (empêche un double fan-out dans le
					// même process) mais persistance DB seulement APRÈS un post
					// Discord réussi (voir onSent) : un échec d'envoi rend la clé au
					// pool pour que le tick suivant retente — at-least-once, une
					// alerte de sécu ne doit jamais disparaître sur un hoquet Discord.
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
						key := alertKey
						go sendEnrichedAlert(ctx, aiCtx, severity, aiClient, discord, func(sent bool) {
							if sent {
								persistAlertDedup(db, key)
							} else {
								alertDedup.Delete(key)
							}
						})
					} else {
						// Catégorie désactivée : on persiste quand même pour ne pas
						// retraiter la même alerte à chaque tick de la fenêtre.
						persistAlertDedup(db, alertKey)
					}
				}
			}
		}
	}
}

// sendEnrichedAlert notifies Discord in two steps: the raw alert is posted
// IMMEDIATELY (notification latency never depends on the LLM), then the same
// message is edited in place once the AI analysis is available. An enrichment
// failure therefore degrades to "alerte brute déjà livrée", never to silence.
//
// onSent (nil accepté) est rappelé avec le résultat du POST initial : c'est le
// point d'ancrage at-least-once du caller (persister le dedup sur succès,
// rendre la clé / restaurer l'état sur échec pour retenter au tick suivant).
// parentCtx borne l'enrichissement : à l'arrêt du worker, l'appel Ollama en
// vol est annulé au lieu de survivre au process.
func sendEnrichedAlert(parentCtx context.Context, alertCtx services.AIAlertContext, severity string, aiClient services.AIClient, discord *services.DiscordBot, onSent func(sent bool)) {
	if onSent == nil {
		onSent = func(bool) {}
	}
	if discord == nil || !discord.IsReady() {
		onSent(false)
		return
	}

	msg := alertCtx.Description

	// 1. Post first — the alert reaches the user within the tick, enriched or not.
	messageID, err := discord.SendSoarAlert(alertCtx.Title, msg, severity)
	if err != nil {
		slog.Error("Discord SOAR alert failed", "error", err)
		onSent(false)
		return
	}
	onSent(true)

	if aiClient == nil {
		return
	}

	// 2. Enrich asynchronously, then edit the already-posted message.
	//
	// Gate the heavy Ollama call through the shared semaphore so a burst of
	// alerts never opens more than maxConcurrentEnrichments 120s calls at once.
	// Acquire blocks (rather than dropping) so every alert is still enriched in
	// turn; the waiting goroutine is cheap (it just parks on the channel).
	//
	// The acquire/release + EnrichAlert run inside a closure so the slot is freed
	// via defer even on panic. Without this, a single panic with
	// maxConcurrentEnrichments=1 would leak the only slot forever, deadlocking
	// every future enrichment on `aiEnrichSem <- struct{}{}` (the known "SOAR
	// s'arrete definitivement a la 1ere erreur" class of failure). recover() also
	// keeps a panic from tearing down the whole GoaCore process, since
	// sendEnrichedAlert runs in a detached goroutine.
	var analysis string
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic during AI enrichment: %v", r)
			}
		}()
		aiEnrichSem <- struct{}{}
		defer func() { <-aiEnrichSem }()
		ctx, cancel := context.WithTimeout(parentCtx, 120*time.Second)
		defer cancel()
		analysis, err = aiClient.EnrichAlert(ctx, alertCtx)
	}()
	if err != nil {
		// Le message brut est déjà parti : l'échec d'enrichissement ne coûte
		// que l'absence d'analyse, jamais l'absence de notification.
		slog.Error("AI Enrichment Failed", "error", err)
		return
	}

	// NB: si un hot-reload Discord intervient entre le post et l'édition, le
	// snapshot `discord` de ce tick peut pointer sur une session fermée ;
	// l'édition échoue alors proprement et l'alerte reste en version brute.
	if err := discord.EditSoarAlertAnalysis(messageID, alertCtx.Title, msg, severity, analysis); err != nil {
		slog.Error("Discord SOAR alert enrichment edit failed", "error", err, "message_id", messageID)
	}
}
