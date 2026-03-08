package main

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"sync"

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
		slog.Warn("SESSION_SECRET is the default value — set a strong secret in production!")
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
			return template.JS(a), nil
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
		bot, botErr := services.NewDiscordBot(cfg.DiscordBotToken, cfg.DiscordChannelID, cfg.DiscordAuthChannel)
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
	}

	// Background workers
	go workers.StartCacheWorker(db, cfg, proxmoxService, proxmoxCache)
	go workers.StartWazuhWorker(wazuhClient, wazuhIndexer, wazuhCache, vulnCache)
	go workers.StartSoarWorker(db, wazuhClient, wazuhIndexer, aiClient, discordBot, soarConfigState)
	go workers.StartProxmoxAuthMonitor(cfg, proxmoxService, discordBot)

	// TLS cert
	if err := server.EnsureCert(); err != nil {
		slog.Error("Error generating TLS certificate", "error", err)
		os.Exit(1)
	}

	// Router
	appRouter := router.New(h, store, db)

	// Start server
	srv := server.New(cfg.HTTPPort, cfg.HTTPSPort, appRouter)
	if err := srv.Start(); err != nil {
		slog.Error("HTTPS server error", "error", err)
		os.Exit(1)
	}
}
