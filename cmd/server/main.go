package main

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/sessions"
	"goacore/assets"
	"goacore/internal/config"
	"goacore/internal/database"
	"goacore/internal/handlers"
	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/router"
	"goacore/internal/server"
	"goacore/internal/services"
	"goacore/internal/sse"
	"goacore/internal/workers"
)

func main() {
	// Structured JSON logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Load config
	cfg := config.Load()

	if cfg.SkipTLSVerify {
		slog.Warn("SKIP_TLS_VERIFY=true — TLS certificate verification disabled")
	}
	// Refuse to boot when a core credential is missing or unsafe. RequireForBoot
	// covers ONLY the always-required set: DB_USER/DB_PASS/DB_NAME (the database is
	// mandatory; empty creds would silently fall back to a guessable connection) and
	// SESSION_SECRET (which also derives the AES-256-GCM key encrypting in-app secrets,
	// so a copy-paste-without-edit deployment must never start with a publicly known or
	// too-short value). Optional services (Proxmox/Wazuh/AI/Discord) are NOT required —
	// they are configurable in-app, so a vierge instance still boots. The guard now
	// lives in config so it travels with the config (defence in depth).
	if err := cfg.RequireForBoot(); err != nil {
		slog.Error("Refusing to start — invalid core configuration", "error", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("Invalid configuration — refusing to start", "error", err)
		os.Exit(1)
	}
	// PROXMOX_URL is no longer fatal (it can be configured/fixed in-app). Surface a
	// malformed env value as a Warn so a typo is visible without blocking the boot.
	if w := cfg.ProxmoxURLWarning(); w != "" {
		slog.Warn(w)
	}
	// Install the proxy trust boundary used to resolve the client IP of a login
	// attempt (rate limiting). Empty by default = no X-Forwarded-For / X-Real-IP is
	// ever believed, because the app is directly reachable in HTTPS on 8443 and a
	// forged header would otherwise hand an attacker a fresh counter per attempt.
	// A malformed entry is fatal: silently trusting nothing (or everything) because
	// of a typo is exactly the kind of surprise this guard exists to prevent.
	if err := middleware.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		slog.Error("Invalid TRUSTED_PROXIES — refusing to start", "error", err)
		os.Exit(1)
	}
	if len(cfg.TrustedProxies) > 0 {
		slog.Info("Trusted proxies configured (X-Forwarded-For honoured from these only)", "cidrs", cfg.TrustedProxies)
	} else {
		slog.Info("No trusted proxy declared — forwarding headers ignored, rate limiting keys on the peer address")
	}

	// Database
	db, err := database.Connect(cfg)
	if err != nil {
		slog.Error("Cannot connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("Connected to MySQL database")

	// Une base qui n'a pas pu être amenée au schéma attendu (privilège ALTER manquant,
	// verrou, disque plein) doit interrompre le démarrage plutôt que de servir des 500
	// dispersées à l'usage : c'est tout l'intérêt du retour d'erreur de Migrate.
	if err := database.Migrate(db); err != nil {
		slog.Error("Migration de schéma impossible — refus de démarrer", "error", err)
		os.Exit(1)
	}

	// Templates
	tmpl := template.New("").Funcs(handlers.TemplateFuncMap())
	if _, statErr := os.Stat("assets/templates"); statErr == nil {
		slog.Info("Loading templates from disk (Development Mode)")
		tmpl, err = tmpl.ParseGlob("assets/templates/*.html")
	} else {
		slog.Info("Loading embedded templates (Production Mode)")
		tmpl, err = tmpl.ParseFS(assets.TemplatesFS, "templates/*.html")
	}
	if err != nil {
		slog.Error("Error parsing templates", "error", err)
		os.Exit(1)
	}

	// Services
	proxmoxService := services.NewProxmoxService(db, cfg.SkipTLSVerify)

	// SSH service first: it is the AES-256-GCM crypto engine (key derived from
	// SESSION_SECRET) reused to encrypt/decrypt the in-app Proxmox token, and it
	// carries the Proxmox creds for the root console — which ConfigStore refreshes
	// on a hot-reload via SetProxmoxCreds. It MUST exist before the ConfigStore and
	// the ConnectionStore, and before ReloadProxmox (which decrypts the DB secret).
	sshEncKey := handlers.DeriveSSHEncKey(cfg.SessionSecret)
	sshService := services.NewSSHService(
		db, sshEncKey,
		cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret,
		cfg.SkipTLSVerify,
	)
	sshService.MigrateEncryptSSHKeys()

	// Enregistre le magasin TOFU partagé comme source de vérité pour les deux chemins
	// qui ne construisent pas leur propre client SSH : le canal GoaBackup (vérification
	// des clés d'hôte de l'hyperviseur) et l'exécution Ansible (known_hosts temporaire).
	// Les deux sont fail-closed sans magasin enregistré — sans ces deux lignes, le canal
	// et les playbooks refusent toute connexion.
	services.SetDefaultChannelHostKeys(sshService)
	services.SetDefaultHostKeyStore(sshService)

	// Connection store (DB persistence of in-app infra creds) + ConfigStore (live,
	// concurrency-safe Proxmox connection, atomic.Pointer swap on reload).
	connStore := services.NewConnectionStore(db, sshService)
	configStore := config.NewConfigStore(cfg, sshService)

	// Resolve the effective Proxmox connection: DB row wins over env when present
	// and enabled; otherwise the env values already in cfg are the fallback. This
	// is tolerant by design — a missing/undecipherable row never aborts the boot.
	reloadProxmoxFromDB(connStore, configStore)

	backupService := services.NewBackupService(db, proxmoxService, configStore, cfg)

	// Wire the read-only Proxmox helper channel for restore testing behind a LIVE
	// registry (atomic.Pointer), so an in-app provision/rotation hot-reloads it without
	// a restart. The env-derived channel (GOABACKUP_SSH_KEY_FILE) is the frozen
	// rollback fallback — the HomeLab instance that mounts the key file must NOT regress.
	// Precedence at boot: a DB-provisioned in-app key (in-memory, decrypted) > env file.
	channelRegistry := services.NewChannelRegistry(services.NewProxmoxChannel(cfg))
	reloadChannelFromDB(connStore, channelRegistry)
	backupService.SetChannelProvider(channelRegistry)
	if channelRegistry.Channel().Configured() {
		slog.Info("Restore-test channel configured", "host", cfg.GoabackupSSHHost, "user", cfg.GoabackupSSHUser)
	} else {
		slog.Info("Restore-test channel not configured (no DB key and missing GOABACKUP_SSH_HOST/KEY_FILE)")
	}

	// Reconcile zombie backup runs left "running" by a previous restart: their
	// driving goroutine is gone, so they would otherwise stay stuck forever.
	if n, err := backupService.ReconcileRunningRuns(); err != nil {
		slog.Error("backup: reconcile running runs", "error", err)
	} else if n > 0 {
		slog.Info("backup: reconciled orphaned running runs", "count", n)
	}

	// Same reconciliation for orphaned restore tests (DB rows).
	if n, err := backupService.ReconcileRunningTests(); err != nil {
		slog.Error("restore-test: reconcile running tests", "error", err)
	} else if n > 0 {
		slog.Info("restore-test: reconciled orphaned running tests", "count", n)
	}

	var wazuhClient *services.WazuhClient
	if cfg.WazuhAPIURL != "" {
		slog.Info("Configuring Wazuh Client", "url", cfg.WazuhAPIURL)
		wazuhClient = services.NewWazuhClient(cfg.WazuhAPIURL, cfg.WazuhUser, cfg.WazuhPassword, cfg.SkipTLSVerify)
	} else {
		slog.Info("Wazuh URL not configured")
	}

	var wazuhIndexer *services.WazuhIndexerClient
	if cfg.WazuhIndexerURL != "" {
		slog.Info("Configuring Wazuh Indexer Client", "url", cfg.WazuhIndexerURL)
		wazuhIndexer = services.NewWazuhIndexerClient(cfg.WazuhIndexerURL, cfg.WazuhIndexerUser, cfg.WazuhIndexerPass, cfg.SkipTLSVerify)
	}

	var aiClient services.AIClient
	// Only build an AI client when a provider is explicitly configured. With the
	// AI_PROVIDER default now empty, a vierge instance no longer instantiates an
	// Ollama client aimed at localhost:11434 that would fail every SOAR tick — AI
	// enrichment stays cleanly disabled until configured (env or in-app onboarding).
	if cfg.AIProvider != "" {
		aiClient = services.NewAIClient(cfg.AIProvider, cfg.AIURL, cfg.AIAPIKey, cfg.AIModel, cfg.OpenAIBaseURL)
		if aiClient != nil {
			slog.Info("AI Client configured", "provider", cfg.AIProvider, "model", cfg.AIModel)
		}
	} else {
		slog.Info("AI enrichment disabled (no AI_PROVIDER — configure via onboarding)")
	}

	// Session store
	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 1,
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	}

	// Discord (env seed). The bot is published into the registry below; at shutdown we
	// close the CURRENT registry bot (which may have been hot-reloaded), not this boot
	// pointer — so the defer is registered after the registry is built (see below).
	var discordBot *services.DiscordBot
	if cfg.DiscordBotToken != "" && cfg.DiscordChannelID != "" {
		bot, botErr := services.NewDiscordBot(cfg.DiscordBotToken, cfg.DiscordChannelID, cfg.DiscordAuthChannel, cfg.DiscordAnsibleChannel)
		if botErr != nil {
			slog.Error("Failed to init Discord Bot", "error", botErr)
		} else {
			discordBot = bot
		}
	} else {
		slog.Info("Discord Bot not configured (missing token or channel)")
	}

	// Service registry: the LIVE, hot-reloadable clients (Wazuh API, Wazuh Indexer,
	// AI, Discord). Seed it from the env-built clients above (boot only, before any
	// worker starts), freezing each service's env snapshot for rollback. The DB rows
	// then override the seeds via reloadServicesFromDB, exactly like Proxmox.
	registry := services.NewServiceRegistry(cfg.SkipTLSVerify)
	registry.SeedWazuh(wazuhClient, cfg.WazuhAPIURL, cfg.WazuhUser, cfg.WazuhPassword)
	registry.SeedIndexer(wazuhIndexer, cfg.WazuhIndexerURL, cfg.WazuhIndexerUser, cfg.WazuhIndexerPass)
	registry.SeedAI(aiClient, cfg.AIProvider, cfg.AIURL, cfg.AIAPIKey, cfg.AIModel, cfg.OpenAIBaseURL)
	registry.SeedDiscord(discordBot, cfg.DiscordBotToken, cfg.DiscordChannelID, cfg.DiscordAuthChannel, cfg.DiscordAnsibleChannel)

	// Resolve each service's effective connection: a DB row (when present) overrides
	// the env seed via the registry hot-reload writers. Tolerant by design (a
	// missing/undecipherable row never aborts the boot). MUST run BEFORE the workers
	// start, like reloadProxmoxFromDB.
	reloadServicesFromDB(connStore, registry)

	// Close the CURRENT registry Discord session at shutdown — never the boot pointer,
	// which may have been replaced by a hot-reload (ApplyDiscord swaps + closes the old
	// session itself; this only handles the live one at process exit).
	defer func() {
		if b := registry.Discord(); b != nil {
			b.Close()
		}
	}()

	// Wire Discord notifications into the backup service via the registry as a
	// DiscordProvider (nil-safe). Every emit reads the LIVE bot through the provider, so
	// a hot-reload swap is picked up without re-wiring.
	backupService.SetDiscordProvider(registry)

	// Purge any guest leaked in the disposable sandbox range [9500,9599] on the
	// host (a crash mid-test can leave one behind). No legitimate guest ever lives
	// there — the whole range is disposable by definition. Done AFTER the DB
	// reconciliation above and AFTER Discord is wired so zombie alerts can fire.
	if channelRegistry.Channel().Configured() {
		if n, err := backupService.ReconcileSandboxGuests(); err != nil {
			slog.Error("restore-test: reconcile sandbox guests", "error", err)
		} else if n > 0 {
			slog.Warn("restore-test: purged leaked sandbox guests at boot", "count", n)
		}
	}

	// Shared state
	wazuhCache := &models.WazuhCache{}
	proxmoxCache := &models.ProxmoxCache{}
	vulnCache := &sync.Map{}
	soarConfigState := &models.SoarConfigState{}
	soarConfigState.Config = models.SoarConfig{
		AlertStatus:   true,
		AlertSSH:      true,
		AlertSudo:     true,
		AlertFIM:      true,
		AlertPackages: true,
	}

	// SSE broker
	sseBroker := sse.NewBroker()

	// Rate limiter
	rateLimiter := middleware.NewRateLimiter()

	// Handler
	h := &handlers.Handler{
		DB:           db,
		Templates:    tmpl,
		SessionStore: store,
		// All four registry-held services (Wazuh API / Indexer / AI / Discord) are read
		// live via Registry — there is no boot-time client field on the Handler.
		Config:       cfg,
		WazuhCache:   wazuhCache,
		ProxmoxCache: proxmoxCache,
		VulnCache:    vulnCache,
		SoarConfig:   soarConfigState,
		RateLimiter:  rateLimiter,
		SSHService:   sshService,
		Proxmox:      proxmoxService,
		Backup:       backupService,
		SSEBroker:    sseBroker,
		ConfigStore:  configStore,
		Connections:  connStore,
		Registry:     registry,
		// The live read-only Proxmox channel (goabackup): the onboarding-canal handlers
		// read it for the live disk-free probe and hot-reload it on provision/rotation.
		ChannelRegistry: channelRegistry,
	}

	// Background workers with context for graceful shutdown
	workerCtx, workerCancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	startWorker := func(name string, fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(workerCtx)
		}()
	}

	startWorker("cache", func(ctx context.Context) {
		workers.StartCacheWorker(ctx, db, configStore, proxmoxService, proxmoxCache, sseBroker)
	})
	startWorker("wazuh", func(ctx context.Context) {
		// Reads the Wazuh API + Indexer clients live from the registry at the top of
		// each tick, so an in-app onboarding hot-reload takes effect next tick.
		workers.StartWazuhWorker(ctx, registry, wazuhCache, vulnCache)
	})
	startWorker("soar", func(ctx context.Context) {
		// Reads ALL hot-reloadable clients (Wazuh API + Indexer + AI + Discord) live
		// from the registry at the top of each tick (in-app onboarding hot-reload takes
		// effect next tick).
		workers.StartSoarWorker(ctx, db, registry, soarConfigState)
	})
	startWorker("proxmox-auth", func(ctx context.Context) {
		// registry is the DiscordProvider — the auth monitor reads the live bot per tick.
		workers.StartProxmoxAuthMonitor(ctx, configStore, proxmoxService, registry)
	})
	startWorker("health", func(ctx context.Context) {
		workers.StartHealthWorker(ctx, db)
	})
	startWorker("ansible", func(ctx context.Context) {
		// registry is the DiscordProvider — the scheduler reads the live bot per tick.
		workers.StartAnsibleScheduler(ctx, db, sshService, registry)
	})
	startWorker("backup-test-scheduler", func(ctx context.Context) {
		// Rotation enablement/hour are read live from the DB (backup_settings) by
		// the worker; the GOABACKUP_TEST_* env vars no longer drive it. Restore-test
		// alerts are emitted by BackupService via its DiscordProvider — no Discord here.
		workers.StartBackupTestScheduler(ctx, backupService)
	})

	// TLS cert
	if err := server.EnsureCert(); err != nil {
		slog.Error("Error generating TLS certificate", "error", err)
		os.Exit(1)
	}

	// Router
	appRouter := router.New(h, store, db, cfg.CookieSecure)

	// Start server
	srv := server.New(cfg.HTTPPort, cfg.HTTPSPort, appRouter)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("Shutting down server...")

	// Stop all background workers
	workerCancel()
	workerDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workerDone)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	// Wait for workers to finish (with timeout)
	select {
	case <-workerDone:
		slog.Info("All workers stopped")
	case <-ctx.Done():
		slog.Warn("Timeout waiting for workers to stop")
	}

	// Draine les orchestrations longues (vzdump, tests de restauration). Contrairement
	// aux workers, elles ne sont JAMAIS annulées en vol : couper un test de restauration
	// en cours empêcherait le defer qui détruit le sandbox de s'exécuter, et laisserait
	// un clone démarré de la VM de production sur l'hyperviseur du client. Le budget est
	// volontairement distinct de celui de l'arrêt HTTP — un test de restauration le
	// dépasse par nature — et son expiration est un AVERTISSEMENT de fuite, pas un échec.
	// Un exploitant qui lance des tests longs doit relever `stop_grace_period` en face.
	const backupDrainTimeout = 60 * time.Second
	drainCtx, drainCancel := context.WithTimeout(context.Background(), backupDrainTimeout)
	defer drainCancel()
	if err := backupService.Wait(drainCtx); err != nil {
		slog.Warn("Sauvegarde ou test de restauration encore en cours à l'arrêt — un invité sandbox peut survivre sur l'hyperviseur ; il sera purgé au prochain démarrage",
			"error", err)
	} else {
		slog.Info("Sauvegardes et tests de restauration drainés")
	}

	slog.Info("Server stopped gracefully")
}

// reloadProxmoxFromDB resolves the effective Proxmox connection at boot with the
// precedence DB(enabled row) > env > defaults, and publishes it through the
// ConfigStore (atomic swap + SSH creds refresh). It is intentionally tolerant:
//
//   - no DB row            → keep the env values already loaded in cfg (fallback),
//   - row present+enabled  → DB values WIN (override env),
//   - undecipherable secret → log + fall back to env, never abort the boot.
//
// The effective source is logged once so ops can tell where the live config came
// from (DB / env / unconfigured).
func reloadProxmoxFromDB(connStore *services.ConnectionStore, configStore *config.ConfigStore) {
	conn, secret, err := connStore.GetProxmox()
	if err != nil {
		// Most likely an undecipherable secret (SESSION_SECRET changed). Record the
		// errored status, do NOT override the env fallback, and keep booting.
		slog.Warn("Proxmox connection in DB could not be loaded — falling back to env", "error", err)
		if serr := connStore.SetStatus("proxmox", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)"); serr != nil {
			slog.Warn("Proxmox: set connection status failed", "error", serr)
		}
		logProxmoxSource(configStore, "env")
		return
	}
	if conn == nil || !conn.Enabled {
		// No DB override: env (already in cfg) is the source of truth.
		logProxmoxSource(configStore, "env")
		return
	}
	storage, bridge := services.ProxmoxExtra(conn)
	restoreStorage, cryptRemote, sandboxBridge, sandboxVlan := services.ProxmoxSandboxExtra(conn)
	configStore.ApplyProxmox(config.ProxmoxConn{
		URL:            conn.URL,
		Node:           conn.Node,
		TokenID:        conn.TokenID,
		TokenSecret:    secret,
		Storage:        storage,
		Bridge:         bridge,
		SandboxVlan:    sandboxVlan,
		RestoreStorage: restoreStorage,
		CryptRemote:    cryptRemote,
		SandboxBridge:  sandboxBridge,
	})
	logProxmoxSource(configStore, "DB")
}

// reloadChannelFromDB resolves the effective goabackup channel at boot with the
// precedence DB(in-app key) > env(key file) > unconfigured, and publishes it through
// the ChannelRegistry's atomic swap. It mirrors reloadProxmoxFromDB's tolerance: a
// missing row keeps the env-seeded (key-file) channel; an undecipherable secret logs +
// records an errored status and keeps the env seed (re-provision path), never aborting
// the boot.
//
// A row whose secret is EMPTY is the import-env case (host/user recorded, but the key
// stays on disk as a FILE): we deliberately keep the env-seeded file channel rather
// than publishing a keyless in-memory channel, so the file fallback keeps working.
// Only a row carrying a real private-key PEM overrides the env seed (in-memory key,
// never on disk).
func reloadChannelFromDB(connStore *services.ConnectionStore, reg *services.ChannelRegistry) {
	conn, secret, err := connStore.GetGoabackupChannel()
	if err != nil {
		slog.Warn("goabackup channel in DB could not be loaded — falling back to env key file", "error", err)
		if serr := connStore.SetStatus("goabackup-channel", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)"); serr != nil {
			slog.Warn("goabackup channel: set connection status failed", "error", serr)
		}
		return
	}
	if conn == nil || !conn.Enabled {
		// No DB override: the env-seeded (key-file) channel stays the source of truth.
		return
	}
	if secret == "" {
		// import-env row (host/user only, no in-app key): keep the env file channel.
		slog.Info("goabackup channel: DB row carries no in-app key (import-env) — using env key file")
		return
	}
	// A real in-app private key: publish an in-memory channel (key never on disk).
	reg.ApplyChannel(conn.URL, conn.TokenID, []byte(secret))
	slog.Info("goabackup channel resolved", "source", "DB")
}

// logProxmoxSource logs the effective Proxmox configuration source once at boot.
func logProxmoxSource(configStore *config.ConfigStore, source string) {
	if configStore.ProxmoxConfigured() {
		slog.Info("Proxmox configuration resolved", "source", source)
	} else {
		slog.Info("Proxmox configuration resolved", "source", "unconfigured")
	}
}

// reloadServicesFromDB resolves each registry-held service's effective connection at
// boot with the precedence DB(enabled row) > env > unconfigured, and publishes it
// through the registry Apply* hot-reload writers (atomic swap). It is the
// generalisation of reloadProxmoxFromDB and, like it, MUST run before the workers
// start. It is intentionally tolerant per service: a missing row keeps the env seed,
// an undecipherable secret logs + records an errored status and keeps the env seed,
// never aborting the boot.
//
// All four services (Wazuh API, Indexer, AI, Discord) override the env seed immediately
// when a usable DB row exists. For Discord, ApplyDiscord opens the new Gateway session
// before swapping (and closes the env-seeded one); a failure here is logged and leaves
// the env bot live, never aborting the boot.
func reloadServicesFromDB(connStore *services.ConnectionStore, registry *services.ServiceRegistry) {
	// Wazuh Indexer.
	if conn, secret, err := connStore.GetWazuhIndexer(); err != nil {
		slog.Warn("Wazuh Indexer connection in DB could not be loaded — keeping env", "error", err)
		_ = connStore.SetStatus("wazuh-indexer", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)")
	} else if conn != nil && conn.Enabled {
		registry.ApplyIndexer(conn.URL, conn.TokenID, secret)
		slog.Info("Wazuh Indexer configuration resolved", "source", "DB")
	}

	// Wazuh API.
	if conn, secret, err := connStore.GetWazuh(); err != nil {
		slog.Warn("Wazuh API connection in DB could not be loaded — keeping env", "error", err)
		_ = connStore.SetStatus("wazuh", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)")
	} else if conn != nil && conn.Enabled {
		registry.ApplyWazuh(conn.URL, conn.TokenID, secret)
		slog.Info("Wazuh API configuration resolved", "source", "DB")
	}

	// AI enrichment.
	if conn, secret, err := connStore.GetAI(); err != nil {
		slog.Warn("AI connection in DB could not be loaded — keeping env", "error", err)
		_ = connStore.SetStatus("ai", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)")
	} else if conn != nil && conn.Enabled {
		provider, openaiBase := services.AIExtra(conn)
		registry.ApplyAI(provider, conn.URL, secret, conn.TokenID, openaiBase)
		slog.Info("AI configuration resolved", "source", "DB", "provider", provider)
	}

	// Discord (ApplyDiscord performs a full hot-reload of the bot session — see registry.go).
	if conn, secret, err := connStore.GetDiscord(); err != nil {
		slog.Warn("Discord connection in DB could not be loaded — keeping env", "error", err)
		_ = connStore.SetStatus("discord", "error", "secret indéchiffrable (SESSION_SECRET modifié ?)")
	} else if conn != nil && conn.Enabled {
		authCh, ansibleCh := services.DiscordExtra(conn)
		if aerr := registry.ApplyDiscord(secret, conn.TokenID, authCh, ansibleCh); aerr != nil {
			slog.Warn("Discord hot-reload from DB failed — keeping env bot", "error", aerr)
		} else {
			slog.Info("Discord configuration resolved", "source", "DB")
		}
	}
}
