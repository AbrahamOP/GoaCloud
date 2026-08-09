package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

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
	// Storage and bridge used when creating VMs/CTs. Empty = auto-detect via the
	// Proxmox API (first active storage supporting images/rootfs, first bridge).
	ProxmoxStorage string
	ProxmoxBridge  string

	// Restore-test sandbox tuning (frozen-at-boot env layer of the resolution
	// order DB extra_json > env > auto-detect > literal). All have safe defaults.
	//
	// SandboxVlan is the isolation VLAN forced on every sandbox NIC before boot
	// (a routed-nowhere cul-de-sac on the firewall). RestoreStorage overrides the
	// storage a restore-test guest is restored into (empty = pm.Storage then
	// auto-detect). DefaultBackupStorage is the fallback Proxmox storage scanned
	// for vzdump archives when a target carries no explicit storage. DiskCeilingPct
	// and MinLocalAvailGiB are the disk pre-flight guards.
	SandboxVlan          int
	RestoreStorage       string
	DefaultBackupStorage string
	DiskCeilingPct       float64
	MinLocalAvailGiB     int
	// SandboxBridge is the bridge sandbox NICs are forced onto (coupled to SandboxVlan).
	// Empty = the hard vmbr1 fallback at resolution time. It is DELIBERATELY distinct
	// from ProxmoxBridge (the creation bridge) so a prod creation bridge is never
	// inherited as the isolation bridge.
	SandboxBridge string

	// Wazuh API
	WazuhAPIURL   string
	WazuhUser     string
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
	// OpenAIBaseURL targets an OpenAI-compatible endpoint (self-hosted/sovereign).
	OpenAIBaseURL string

	// Discord
	DiscordBotToken       string
	DiscordChannelID      string
	DiscordAuthChannel    string
	DiscordAnsibleChannel string

	// AnsibleDefaultRemoteUser is an OPTIONAL suggested SSH user pre-filled in the
	// schedule-creation form (env ANSIBLE_DEFAULT_REMOTE_USER). Default empty: the
	// admin MUST pick a remote_user explicitly — there is deliberately NO 'root'
	// fallback (root SSH is disabled fleet-wide, PermitRootLogin=no).
	AnsibleDefaultRemoteUser string

	// GoaBackup restore-test channel (read-only SSH helper on the Proxmox host)
	GoabackupSSHHost    string
	GoabackupSSHUser    string
	GoabackupSSHKeyFile string

	// GoaBackup scheduled restore-test rotation
	BackupTestRotationEnabled bool
	BackupTestHour            int

	// Server
	HTTPPort      string
	HTTPSPort     string
	SessionSecret string
	CookieSecure  bool
	SkipTLSVerify bool

	// TrustedProxies is the list of CIDR blocks (env TRUSTED_PROXIES, comma or
	// space separated; a bare IP is read as a single-host block) whose forwarding
	// headers — X-Forwarded-For / X-Real-IP — may be believed when resolving the
	// client IP that keys the login rate limiter.
	//
	// EMPTY BY DEFAULT, and that default is a security decision: GoaCore serves
	// HTTPS itself on 8443, so anything able to reach the port can forge those
	// headers. Trusting them unconditionally would let an attacker mint a fresh
	// counter on every attempt and never be blocked. With an empty list NO header
	// is trusted and the limiter keys on the real r.RemoteAddr.
	//
	// Set it ONLY to the address(es) of the reverse proxy actually in front of the
	// app, e.g. TRUSTED_PROXIES=192.0.2.1/32 (Traefik) or 10.0.0.0/8. The list
	// is installed into the middleware at boot (main.go) and a malformed entry is
	// fatal — a typo must never silently widen or void the trust boundary.
	TrustedProxies []string

	// secretFileErrs collects the KEY_FILE references that could not be read at
	// Load time (see getEnvSecret). They are reported by RequireForBoot/Validate so
	// a mistyped or unmounted secret file refuses the boot instead of quietly
	// leaving GoaCore with an empty credential.
	secretFileErrs []string
}

// secretFileSuffix implements the Docker convention for secrets: for any variable
// KEY handled by getEnvSecret, KEY_FILE=/run/secrets/xxx reads the secret from the
// file instead of the environment.
const secretFileSuffix = "_FILE"

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	var secretErrs []string

	// getEnvSecret reads a secret, preferring the file named by KEY_FILE over the
	// KEY variable itself. Environment variables are readable by anyone who can
	// reach the Docker daemon (docker inspect) or the process (/proc/<pid>/environ);
	// a file mounted from a Docker/Swarm secret, or from a tmpfs, is not.
	//
	// KEY_FILE WINS over KEY when both are set: an operator who mounts a secret
	// means it, and a stale KEY left over in the compose file must not shadow it.
	// A file that cannot be read (or is empty) is recorded as an error rather than
	// silently downgraded to the fallback — see secretFileErrs.
	getEnvSecret := func(key, fallback string) string {
		path := strings.TrimSpace(os.Getenv(key + secretFileSuffix))
		if path == "" {
			return getEnv(key, fallback)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			secretErrs = append(secretErrs, fmt.Sprintf("%s%s=%q: %v", key, secretFileSuffix, path, err))
			return ""
		}
		// Trailing newline: `echo secret > file` and most secret managers add one.
		value := strings.TrimSpace(string(raw))
		if value == "" {
			secretErrs = append(secretErrs, fmt.Sprintf("%s%s=%q: file is empty", key, secretFileSuffix, path))
		}
		return value
	}

	cfg := &Config{
		// No DB credential defaults: DB_USER/DB_PASS MUST be injected by the
		// compose/env file (see docker-compose.yml — the host DB_PASSWORD maps to the
		// container DB_PASS). An empty user/pass is rejected fail-fast by
		// RequireForBoot() below, so the app never silently connects as a guessable
		// root/root. DB_HOST keeps a sane localhost default; DB_NAME keeps "goacloud"
		// (the existing production schema name — changing it would break the live DB).
		DBUser:             getEnv("DB_USER", ""),
		DBPass:             getEnvSecret("DB_PASS", ""),
		DBHost:             getEnv("DB_HOST", "127.0.0.1:3306"),
		DBName:             getEnv("DB_NAME", "goacloud"),
		ProxmoxURL:         getEnv("PROXMOX_URL", ""),
		ProxmoxNode:        getEnv("PROXMOX_NODE", "pve"),
		ProxmoxTokenID:     getEnv("PROXMOX_TOKEN_ID", ""),
		ProxmoxTokenSecret: getEnvSecret("PROXMOX_TOKEN_SECRET", ""),
		ProxmoxStorage:     getEnv("PROXMOX_STORAGE", ""),
		ProxmoxBridge:      getEnv("PROXMOX_BRIDGE", ""),
		// VLAN 1-4094, default 99. A 0/out-of-range env yields the bounded default;
		// the resolver still floors a 0 from any layer back to 99 (hard fallback).
		SandboxVlan:          getEnvIntBounded("GOABACKUP_SANDBOX_VLAN", 99, 1, 4094),
		RestoreStorage:       getEnv("GOABACKUP_RESTORE_STORAGE", ""),
		SandboxBridge:        getEnv("GOABACKUP_SANDBOX_BRIDGE", ""),
		DefaultBackupStorage: getEnv("GOABACKUP_DEFAULT_STORAGE", "local"),
		// Ceiling bounded <=95 (a 95%+ thin pool is already critical); default 85.
		DiskCeilingPct:   float64(getEnvIntBounded("GOABACKUP_DISK_CEILING_PCT", 85, 1, 95)),
		MinLocalAvailGiB: getEnvIntBounded("GOABACKUP_MIN_LOCAL_AVAIL_GIB", 5, 0, 1024),
		WazuhAPIURL:      getEnv("WAZUH_API_URL", ""),
		WazuhUser:        getEnv("WAZUH_USER", ""),
		WazuhPassword:    getEnvSecret("WAZUH_PASSWORD", ""),
		WazuhIndexerURL:  getEnv("WAZUH_INDEXER_URL", ""),
		WazuhIndexerUser: getEnv("WAZUH_INDEXER_USER", ""),
		WazuhIndexerPass: getEnvSecret("WAZUH_INDEXER_PASSWORD", ""),
		// Default empty (not "ollama"): a vierge instance with no AI_PROVIDER must NOT
		// instantiate an Ollama client pointed at localhost:11434 that fails every SOAR
		// tick. AI enrichment stays cleanly "disabled" until configured (env or in-app).
		// Production is unaffected — it sets AI_PROVIDER explicitly in its env.
		AIProvider:            getEnv("AI_PROVIDER", ""),
		AIURL:                 getEnv("AI_URL", ""),
		AIAPIKey:              getEnvSecret("AI_API_KEY", ""),
		AIModel:               getEnv("AI_MODEL", ""),
		OpenAIBaseURL:         getEnv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
		DiscordBotToken:       getEnvSecret("DISCORD_BOT_TOKEN", ""),
		DiscordChannelID:      getEnv("DISCORD_CHANNEL_ID", ""),
		DiscordAuthChannel:    getEnv("DISCORD_AUTH_CHANNEL_ID", ""),
		DiscordAnsibleChannel: getEnv("DISCORD_ANSIBLE_CHANNEL_ID", ""),
		// Empty by default: no 'root' suggestion. The admin must choose a user.
		AnsibleDefaultRemoteUser: getEnv("ANSIBLE_DEFAULT_REMOTE_USER", ""),
		GoabackupSSHHost:         getEnv("GOABACKUP_SSH_HOST", ""),
		GoabackupSSHUser:         getEnv("GOABACKUP_SSH_USER", "goabackup"),
		GoabackupSSHKeyFile:      getEnv("GOABACKUP_SSH_KEY_FILE", ""),

		BackupTestRotationEnabled: getEnvBool("GOABACKUP_TEST_ROTATION_ENABLED", false),
		BackupTestHour:            getEnvIntBounded("GOABACKUP_TEST_HOUR", 4, 0, 23),

		HTTPPort:      getEnv("PORT", "8080"),
		HTTPSPort:     getEnv("HTTPS_PORT", "8443"),
		SessionSecret: getEnvSecret("SESSION_SECRET", "super-secret-key-change-me"),
		CookieSecure:  getEnv("COOKIE_SECURE", "true") != "false",
		SkipTLSVerify: getEnv("SKIP_TLS_VERIFY", "false") == "true",
		// No default: no proxy is trusted until the operator names one.
		TrustedProxies: getEnvList("TRUSTED_PROXIES"),
	}

	// Legacy Ollama support
	if cfg.AIProvider == "ollama" && cfg.AIURL == "" {
		cfg.AIURL = getEnv("OLLAMA_URL", "")
	}
	if cfg.AIModel == "" {
		cfg.AIModel = getEnv("OLLAMA_MODEL", "")
	}

	cfg.secretFileErrs = secretErrs
	return cfg
}

// secretFileError reports the KEY_FILE references that could not be read. It is
// checked by BOTH boot guards below, whichever runs first: an unreadable secret
// file must produce "your secret file is unreadable", not the misleading "your
// SESSION_SECRET is missing" that an empty fallback would trigger.
func (c *Config) secretFileError() error {
	if len(c.secretFileErrs) == 0 {
		return nil
	}
	return fmt.Errorf("unusable secret file(s): %s", strings.Join(c.secretFileErrs, "; "))
}

// Validate checks that configured service URLs are well-formed. Catching a
// malformed URL here (fail-fast at startup) avoids a nil-request panic later,
// deep inside a worker, when http.NewRequest is handed a bad URL derived from
// these values.
//
// PROXMOX_URL is deliberately NOT in this blocking set: since Jalon 1 the Proxmox
// connection can be configured in-app (DB) on top of (or instead of) the env, so a
// malformed PROXMOX_URL coming from the environment must not prevent the app from
// booting — the operator can still fix it via onboarding. Its form is re-validated
// at Save time (ValidateURL) and a boot-time Warn is emitted (ProxmoxURLWarning).
func (c *Config) Validate() error {
	if err := c.secretFileError(); err != nil {
		return err
	}
	for name, raw := range map[string]string{
		"WAZUH_API_URL":     c.WazuhAPIURL,
		"WAZUH_INDEXER_URL": c.WazuhIndexerURL,
		"AI_URL":            c.AIURL,
	} {
		if raw == "" {
			continue
		}
		if err := ValidateURL(raw); err != nil {
			return fmt.Errorf("%s is not a valid absolute URL: %q", name, raw)
		}
	}
	return nil
}

// boot-time placeholders for SESSION_SECRET that must never reach production. The
// set is shared with the boot guard in main.go (kept in sync) and the unit test.
var weakSessionSecrets = map[string]bool{
	"":                                  true,
	"super-secret-key-change-me":        true, // internal/config default (pre-hardening)
	"change-me-to-a-long-random-secret": true, // .env.example placeholder
}

// RequireForBoot enforces the small set of credentials WITHOUT which the app cannot
// safely run, so the rejection travels with the config (defence in depth) instead of
// living only in main.go. It deliberately covers ONLY the always-required core:
//
//   - DB_USER / DB_PASS / DB_NAME — the database is mandatory; an empty user/pass
//     would otherwise silently fall back to a guessable connection. (DB_NAME has a
//     historical default of "goacloud", so it is only ever empty if explicitly cleared.)
//   - SESSION_SECRET — also derives the AES-256-GCM key for in-app secrets; a missing,
//     known-placeholder, or <32-char value is refused.
//
// It does NOT require any OPTIONAL service (Proxmox, Wazuh, AI, Discord): those are
// configurable in-app and a vierge instance must boot without them. Production is
// unaffected — it injects DB_USER/DB_PASS/DB_NAME and a strong SESSION_SECRET via its
// env, so every check below passes.
func (c *Config) RequireForBoot() error {
	if err := c.secretFileError(); err != nil {
		return err
	}
	var missing []string
	if c.DBUser == "" {
		missing = append(missing, "DB_USER")
	}
	if c.DBPass == "" {
		missing = append(missing, "DB_PASS (host DB_PASSWORD)")
	}
	if c.DBName == "" {
		missing = append(missing, "DB_NAME")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %v — set them in your .env / compose env file", missing)
	}
	if weakSessionSecrets[c.SessionSecret] || len(c.SessionSecret) < 32 {
		return fmt.Errorf("SESSION_SECRET is missing, a known placeholder, or shorter than 32 chars — generate one with: openssl rand -hex 32")
	}
	return nil
}

// ValidateURL reports whether raw is a well-formed absolute URL (scheme + host).
// It is the single source of truth for URL form validation, reused by Validate()
// and by the onboarding Save handler before persisting a Proxmox connection.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid absolute URL: %q", raw)
	}
	return nil
}

// ProxmoxURLWarning returns a non-empty message when PROXMOX_URL is set in the
// environment but malformed. The caller logs it as a Warn at boot so a typo is
// visible without being fatal (the app still starts; onboarding can fix it).
func (c *Config) ProxmoxURLWarning() string {
	if c.ProxmoxURL == "" {
		return ""
	}
	if err := ValidateURL(c.ProxmoxURL); err != nil {
		return fmt.Sprintf("PROXMOX_URL is malformed (%q) — Proxmox features stay disabled until fixed via onboarding", c.ProxmoxURL)
	}
	return ""
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// getEnvList reads a comma/space separated env var into a slice, dropping empty
// items. A missing or blank var yields a nil slice (the "nothing listed" case,
// which callers must treat as "no entry", never as "all entries").
func getEnvList(key string) []string {
	raw := os.Getenv(key)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// getEnvBool reads a boolean env var. Accepts true/1/yes/on (case-insensitive).
func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// getEnvIntBounded reads an int env var, clamping it to [min,max]. A missing or
// unparseable value yields the fallback (which is assumed already in range).
func getEnvIntBounded(key string, fallback, min, max int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
