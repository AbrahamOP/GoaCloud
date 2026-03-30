package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/sessions"
	"goacloud/assets"
	"goacloud/internal/config"
	"goacloud/internal/database"
	"goacloud/internal/handlers"
	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/router"
	"goacloud/internal/server"
	"goacloud/internal/services"
	"goacloud/internal/sse"
	"goacloud/internal/workers"
)

func main() {
	// Structured JSON logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Load config
	cfg := config.Load()

	if cfg.SkipTLSVerify {
		slog.Warn("SKIP_TLS_VERIFY=true — TLS certificate verification disabled")
	}
	if cfg.SessionSecret == "super-secret-key-change-me" {
		slog.Error("SESSION_SECRET is the default value — refusing to start. Set a strong secret via SESSION_SECRET env var.")
		os.Exit(1)
	}

	// Database
	db, err := database.Connect(cfg)
	if err != nil {
		slog.Error("Cannot connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("Connected to MySQL database")

	database.Migrate(db)

	// Templates
	funcMap := template.FuncMap{
		"json": func(v interface{}) (template.JS, error) {
			a, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			// Escape </script> and <!-- to prevent injection in <script> blocks
			s := strings.ReplaceAll(string(a), "</", `<\/`)
			s = strings.ReplaceAll(s, "<!--", `<\!--`)
			return template.JS(s), nil
		},
	}
	tmpl := template.New("").Funcs(funcMap)
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
	if cfg.AIURL != "" || cfg.AIAPIKey != "" || cfg.AIProvider == "ollama" {
		aiClient = services.NewAIClient(cfg.AIProvider, cfg.AIURL, cfg.AIAPIKey, cfg.AIModel)
		if aiClient != nil {
			slog.Info("AI Client configured", "provider", cfg.AIProvider, "model", cfg.AIModel)
		}
	} else {
		slog.Info("AI enrichment disabled (missing configuration)")
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

	// Derive SSH encryption key from session secret
	sshEncKey := handlers.DeriveSSHEncKey(cfg.SessionSecret)

	sshService := services.NewSSHService(
		db, sshEncKey,
		cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret,
		cfg.SkipTLSVerify,
	)
	sshService.MigrateEncryptSSHKeys()

	// Discord
	var discordBot *services.DiscordBot
	if cfg.DiscordBotToken != "" && cfg.DiscordChannelID != "" {
		bot, botErr := services.NewDiscordBot(cfg.DiscordBotToken, cfg.DiscordChannelID, cfg.DiscordAuthChannel, cfg.DiscordAnsibleChannel)
		if botErr != nil {
			slog.Error("Failed to init Discord Bot", "error", botErr)
		} else {
			discordBot = bot
			defer discordBot.Close()
		}
	} else {
		slog.Info("Discord Bot not configured (missing token or channel)")
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
		WazuhClient:  wazuhClient,
		WazuhIndexer: wazuhIndexer,
		AIClient:     aiClient,
		Discord:      discordBot,
		Config:       cfg,
		WazuhCache:   wazuhCache,
		ProxmoxCache: proxmoxCache,
		VulnCache:    vulnCache,
		SoarConfig:   soarConfigState,
		RateLimiter:  rateLimiter,
		SSHService:   sshService,
		Proxmox:      proxmoxService,
		SSEBroker:    sseBroker,
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
		workers.StartCacheWorker(ctx, db, cfg, proxmoxService, proxmoxCache, sseBroker)
	})
	startWorker("wazuh", func(ctx context.Context) {
		workers.StartWazuhWorker(ctx, wazuhClient, wazuhIndexer, wazuhCache, vulnCache)
	})
	startWorker("soar", func(ctx context.Context) {
		workers.StartSoarWorker(ctx, db, wazuhClient, wazuhIndexer, aiClient, discordBot, soarConfigState)
	})
	startWorker("proxmox-auth", func(ctx context.Context) {
		workers.StartProxmoxAuthMonitor(ctx, cfg, proxmoxService, discordBot)
	})
	startWorker("health", func(ctx context.Context) {
		workers.StartHealthWorker(ctx, db)
	})
	startWorker("ansible", func(ctx context.Context) {
		workers.StartAnsibleScheduler(ctx, db, sshService, discordBot)
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

	slog.Info("Server stopped gracefully")
}
