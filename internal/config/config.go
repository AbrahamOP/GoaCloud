package config

import "os"

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Database
	DBUser string
	DBPass string
	DBHost string
	DBName string

	// Proxmox
	ProxmoxURL         string
	ProxmoxNode        string
	ProxmoxTokenID     string
	ProxmoxTokenSecret string

	// Wazuh API
	WazuhAPIURL  string
	WazuhUser    string
	WazuhPassword string

	// Wazuh Indexer
	WazuhIndexerURL  string
	WazuhIndexerUser string
	WazuhIndexerPass string

	// AI
	AIProvider string
	AIURL      string
	AIAPIKey   string
	AIModel    string

	// Discord
	DiscordBotToken       string
	DiscordChannelID      string
	DiscordAuthChannel    string
	DiscordAnsibleChannel string

	// Server
	HTTPPort      string
	HTTPSPort     string
	SessionSecret string
	CookieSecure  bool
	SkipTLSVerify bool
}

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	cfg := &Config{
		DBUser:             getEnv("DB_USER", "root"),
		DBPass:             getEnv("DB_PASS", "root"),
		DBHost:             getEnv("DB_HOST", "127.0.0.1:3306"),
		DBName:             getEnv("DB_NAME", "goacloud"),
		ProxmoxURL:         getEnv("PROXMOX_URL", ""),
		ProxmoxNode:        getEnv("PROXMOX_NODE", "pve"),
		ProxmoxTokenID:     getEnv("PROXMOX_TOKEN_ID", ""),
		ProxmoxTokenSecret: getEnv("PROXMOX_TOKEN_SECRET", ""),
		WazuhAPIURL:        getEnv("WAZUH_API_URL", ""),
		WazuhUser:          getEnv("WAZUH_USER", ""),
		WazuhPassword:      getEnv("WAZUH_PASSWORD", ""),
		WazuhIndexerURL:    getEnv("WAZUH_INDEXER_URL", ""),
		WazuhIndexerUser:   getEnv("WAZUH_INDEXER_USER", ""),
		WazuhIndexerPass:   getEnv("WAZUH_INDEXER_PASSWORD", ""),
		AIProvider:         getEnv("AI_PROVIDER", "ollama"),
		AIURL:              getEnv("AI_URL", ""),
		AIAPIKey:           getEnv("AI_API_KEY", ""),
		AIModel:            getEnv("AI_MODEL", ""),
		DiscordBotToken:    getEnv("DISCORD_BOT_TOKEN", ""),
		DiscordChannelID:   getEnv("DISCORD_CHANNEL_ID", ""),
		DiscordAuthChannel:    getEnv("DISCORD_AUTH_CHANNEL_ID", ""),
		DiscordAnsibleChannel: getEnv("DISCORD_ANSIBLE_CHANNEL_ID", ""),
		HTTPPort:           getEnv("PORT", "8080"),
		HTTPSPort:          getEnv("HTTPS_PORT", "8443"),
		SessionSecret:      getEnv("SESSION_SECRET", "super-secret-key-change-me"),
		CookieSecure:       getEnv("COOKIE_SECURE", "true") != "false",
		SkipTLSVerify:      getEnv("SKIP_TLS_VERIFY", "false") == "true",
	}

	// Legacy Ollama support
	if cfg.AIProvider == "ollama" && cfg.AIURL == "" {
		cfg.AIURL = getEnv("OLLAMA_URL", "")
	}
	if cfg.AIModel == "" {
		cfg.AIModel = getEnv("OLLAMA_MODEL", "")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
