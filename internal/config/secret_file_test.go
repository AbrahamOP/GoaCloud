package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSecret drops a secret file the way a Docker/Swarm secret would be mounted
// (content plus the trailing newline every `echo` and most secret managers add).
func writeSecret(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// Secrets passed through the environment are readable by anyone who can reach the
// Docker daemon (docker inspect) or the process (/proc/<pid>/environ). The _FILE
// convention is the way out, so it has to actually feed the config.
func TestLoadReadsSecretsFromFiles(t *testing.T) {
	secret := strings.Repeat("a", 64)
	t.Setenv("SESSION_SECRET_FILE", writeSecret(t, "session_secret", secret))
	t.Setenv("DB_PASS_FILE", writeSecret(t, "db_pass", "s3cr3t-db"))
	t.Setenv("PROXMOX_TOKEN_SECRET_FILE", writeSecret(t, "pve_token", "pve-token"))
	t.Setenv("WAZUH_PASSWORD_FILE", writeSecret(t, "wazuh", "wazuh-pass"))
	t.Setenv("WAZUH_INDEXER_PASSWORD_FILE", writeSecret(t, "indexer", "indexer-pass"))
	t.Setenv("AI_API_KEY_FILE", writeSecret(t, "ai_key", "ai-key"))
	t.Setenv("DISCORD_BOT_TOKEN_FILE", writeSecret(t, "discord", "discord-token"))
	t.Setenv("DB_USER", "goacore")

	cfg := Load()

	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"SESSION_SECRET", cfg.SessionSecret, secret},
		{"DB_PASS", cfg.DBPass, "s3cr3t-db"},
		{"PROXMOX_TOKEN_SECRET", cfg.ProxmoxTokenSecret, "pve-token"},
		{"WAZUH_PASSWORD", cfg.WazuhPassword, "wazuh-pass"},
		{"WAZUH_INDEXER_PASSWORD", cfg.WazuhIndexerPass, "indexer-pass"},
		{"AI_API_KEY", cfg.AIAPIKey, "ai-key"},
		{"DISCORD_BOT_TOKEN", cfg.DiscordBotToken, "discord-token"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q (read from %s_FILE, newline trimmed)", tc.name, tc.got, tc.want, tc.name)
		}
	}

	if err := cfg.RequireForBoot(); err != nil {
		t.Errorf("RequireForBoot() = %v, want nil with every secret supplied as a file", err)
	}
}

// A mounted secret is an explicit intent: a stale value left over in the compose
// environment must not shadow it.
func TestSecretFileWinsOverTheEnvironmentVariable(t *testing.T) {
	t.Setenv("DB_PASS", "stale-from-compose")
	t.Setenv("DB_PASS_FILE", writeSecret(t, "db_pass", "from-the-mounted-secret"))

	if got := Load().DBPass; got != "from-the-mounted-secret" {
		t.Errorf("DBPass = %q, want the file content", got)
	}
}

// An unreadable or empty secret file must refuse the boot. Falling back to the
// env (or to the built-in placeholder) would start GoaCore with a session key the
// operator believes is secret — and, for SESSION_SECRET, that key also encrypts
// every credential stored in the database.
func TestUnreadableSecretFileRefusesBoot(t *testing.T) {
	strong := strings.Repeat("a", 64)

	tests := []struct {
		name string
		set  func(t *testing.T)
	}{
		{
			name: "missing file",
			set: func(t *testing.T) {
				t.Setenv("SESSION_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))
			},
		},
		{
			name: "empty file",
			set: func(t *testing.T) {
				t.Setenv("SESSION_SECRET_FILE", writeSecret(t, "session_secret", ""))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SESSION_SECRET", strong)
			t.Setenv("DB_USER", "goacore")
			t.Setenv("DB_PASS", "db-pass")
			tt.set(t)

			cfg := Load()
			if cfg.SessionSecret == strong {
				t.Fatal("an unusable SESSION_SECRET_FILE silently fell back to the environment variable")
			}
			err := cfg.RequireForBoot()
			if err == nil {
				t.Fatal("RequireForBoot() = nil, want a refusal")
			}
			if !strings.Contains(err.Error(), "SESSION_SECRET_FILE") {
				t.Errorf("RequireForBoot() = %v, want the offending variable named", err)
			}
			if err := cfg.Validate(); err == nil {
				t.Error("Validate() = nil, want the same refusal (defence in depth)")
			}
		})
	}
}

// Without any _FILE variable, the environment stays the source of truth: the
// convention is additive, existing deployments are untouched.
func TestSecretsStillReadFromTheEnvironmentByDefault(t *testing.T) {
	t.Setenv("SESSION_SECRET", "env-secret")
	t.Setenv("DB_PASS", "env-db-pass")

	cfg := Load()
	if cfg.SessionSecret != "env-secret" || cfg.DBPass != "env-db-pass" {
		t.Errorf("Load() = %q/%q, want the environment values", cfg.SessionSecret, cfg.DBPass)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}
