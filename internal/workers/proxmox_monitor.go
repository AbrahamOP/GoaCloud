package workers

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"goacloud/internal/config"
	"goacloud/internal/services"
)

// StartProxmoxAuthMonitor starts the background worker that monitors Proxmox authentication events.
func StartProxmoxAuthMonitor(cfg *config.Config, proxmox *services.ProxmoxService, discord *services.DiscordBot) {
	if cfg.ProxmoxURL == "" {
		return
	}

	time.Sleep(20 * time.Second)
	slog.Info("Starting Proxmox Auth Monitor...")

	lastN := proxmoxSyslogGetLastN(cfg, proxmox)

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		lastN = checkProxmoxAuthEvents(cfg, proxmox, discord, lastN)
	}
}

func proxmoxSyslogGetLastN(cfg *config.Config, proxmox *services.ProxmoxService) int {
	entries := proxmox.FetchSyslog(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, 0, 500)
	maxN := 0
	for _, e := range entries {
		if e.N > maxN {
			maxN = e.N
		}
	}
	return maxN
}

func checkProxmoxAuthEvents(cfg *config.Config, proxmox *services.ProxmoxService, discord *services.DiscordBot, lastN int) int {
	entries := proxmox.FetchSyslog(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, lastN, 200)

	for _, entry := range entries {
		if entry.N <= lastN {
			continue
		}
		lastN = entry.N
		line := entry.T

		if !strings.Contains(line, "pvedaemon") {
			continue
		}

		if discord == nil || !discord.IsReady() {
			continue
		}

		if strings.Contains(line, "successful auth for user") {
			user := proxmoxExtractUser(line)
			go discord.SendAuthAlert(
				"✅ Connexion Proxmox réussie",
				fmt.Sprintf("**Utilisateur :** %s\n**Serveur :** %s\n**Log :** `%s`", user, cfg.ProxmoxURL, line),
				false,
			)
		} else if strings.Contains(line, "authentication failure") || strings.Contains(line, "failed auth") {
			user := proxmoxExtractUser(line)
			go discord.SendAuthAlert(
				"❌ Échec de connexion Proxmox",
				fmt.Sprintf("**Utilisateur :** %s\n**Serveur :** %s\n**Log :** `%s`", user, cfg.ProxmoxURL, line),
				false,
			)
		}
	}

	return lastN
}

func proxmoxExtractUser(line string) string {
	for _, prefix := range []string{"for user '", "for user "} {
		if idx := strings.Index(line, prefix); idx != -1 {
			rest := line[idx+len(prefix):]
			rest = strings.TrimPrefix(rest, "'")
			if end := strings.IndexAny(rest, "' \t"); end != -1 {
				return rest[:end]
			}
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return "inconnu"
}
