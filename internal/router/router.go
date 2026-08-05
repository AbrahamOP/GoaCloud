package router

import (
	"database/sql"
	"io/fs"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"goacore/assets"
	"goacore/internal/handlers"
	appMiddleware "goacore/internal/middleware"
)

// New creates and returns the application router with all routes registered.
func New(h *handlers.Handler, store *sessions.CookieStore, db *sql.DB, cookieSecure bool) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chiMiddleware.Recoverer)
	r.Use(appMiddleware.SecurityHeaders)
	r.Use(appMiddleware.CSRFProtection(store, cookieSecure))

	// Static assets: serve from disk in dev mode, embedded FS in prod
	var staticHandler http.Handler
	if _, err := os.Stat("assets/static"); err == nil {
		staticHandler = http.FileServer(http.Dir("assets/static"))
	} else {
		sub, _ := fs.Sub(assets.StaticFS, "static")
		staticHandler = http.FileServer(http.FS(sub))
	}
	r.Handle("/static/*", http.StripPrefix("/static/", staticHandler))

	// Public routes (no auth required)
	r.Get("/setup", h.HandleSetup)
	r.Post("/setup", h.HandleSetup)
	r.Get("/login", h.HandleLogin)
	r.Post("/login", h.HandleLogin)
	// Logout is POST-only (CSRF-protected) so it can't be forced via <img src=/logout>.
	r.Post("/logout", h.HandleLogout)

	// Observability. Unauthenticated because a probe (Docker HEALTHCHECK, Traefik,
	// an orchestrator) carries no session cookie, and outside every group so the
	// OnboardingGate can never turn a health check into a 303 to /onboarding on a
	// fresh instance. The payload is two fixed words — see handlers/health.go, which
	// also documents why no /metrics endpoint is exposed here.
	r.Get("/healthz", h.HandleHealthz)
	r.Get("/readyz", h.HandleReadyz)

	// Channel installer script — PUBLIC on purpose, authenticated by a single-use
	// token minted in-app (?t=...) and burned on first use. The admin runs the curl
	// from a Proxmox root shell that has no GoaCore session: behind the session gate
	// curl -L would follow the 303 to /login, get the login page with a 200 (so -f
	// never trips) and pipe HTML into bash. See HandleOnboardingChannelInstallerToken.
	// The Admin-only preview route (/api/onboarding/canal/installer.sh) serves the
	// same bytes to a logged-in browser.
	r.Get("/canal/installer.sh", h.HandleOnboardingChannelInstallerToken)

	// Authenticated routes (any logged-in user, incl. Viewer — read-only surface)
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return appMiddleware.AuthMiddleware(store, db, next)
		})
		// Onboarding gate: while Proxmox is unconfigured, steer the Proxmox-dependent
		// pages to /onboarding/proxmox (409 on their /api/* routes). Non-blocking
		// everywhere else (dashboard, profile, wazuh, onboarding itself).
		r.Use(func(next http.Handler) http.Handler {
			return appMiddleware.OnboardingGate(h.ConfigStore.ProxmoxConfigured, next)
		})

		r.Get("/", h.HandleOverview)
		r.Get("/applications", h.HandleDashboard)
		r.Get("/api/overview/data", h.HandleOverviewData)
		r.Get("/api/overview/backups", h.HandleOverviewBackups)
		r.Get("/report", h.HandleReport)

		// Proxmox — read-only views
		r.Get("/proxmox", h.HandleProxmox)
		r.Get("/api/proxmox/stats", h.HandleProxmoxAPI)
		r.Get("/api/proxmox/guest", h.HandleProxmoxGuestDetail)
		r.Get("/api/proxmox/ips", h.HandleProxmoxIPs)
		r.Get("/api/proxmox/snapshots", h.HandleProxmoxSnapshots)
		r.Get("/api/proxmox/metrics", h.HandleMetricsHistory)
		r.Get("/api/events", h.HandleSSE)

		// Wazuh & SOAR — read-only views
		r.Get("/wazuh", h.HandleWazuh)
		r.Get("/soar", h.HandleSoar)
		r.Get("/api/soar/config", h.HandleSoarConfig)
		r.Get("/api/wazuh/vulns/{agentID}", h.HandleWazuhVulns)
		r.Get("/api/wazuh/cve/summary", h.HandleWazuhCVESummary)
		r.Get("/api/wazuh/agents/refresh", h.HandleWazuhAgentsRefresh)
		r.Get("/api/wazuh/geo", h.HandleWazuhGeoData)

		// Settings hub — self-service sections (any role). The admin sections
		// (services, utilisateurs, proxmox, sauvegarde) live in the Admin-only group
		// below; the cog → /parametres index redirects each role to a reachable section.
		r.Get("/parametres", h.HandleSettingsIndex)
		r.Get("/parametres/profil", h.HandleSettingsProfil)
		r.Get("/parametres/securite", h.HandleSettingsSecurite)

		// Profile (self-service). /profile is a legacy alias for the hub profile section.
		r.Get("/profile", h.HandleSettingsProfil)
		r.Post("/api/profile/update", h.HandleUpdateProfile)
		r.Post("/api/profile/github", h.HandleUpdateGithub)
		r.Get("/api/me", h.HandleMe)
		// Revokes EVERY session of the caller (epoch bump), including a stolen cookie.
		// Self-service by design: it acts on the caller's OWN account only.
		r.Post("/logout-all", h.HandleLogoutAll)

		// MFA (self-service)
		r.Get("/api/mfa/setup", h.HandleSetupMFA)
		r.Post("/api/mfa/verify", h.HandleVerifyMFA)
		r.Post("/api/mfa/disable", h.HandleDisableMFA)

		// Search
		r.Get("/api/search", h.HandleSearch)

		// NB: the apps catalogue is READ-ONLY here. Every mutation on it lives in the
		// Admin-only group below — see the comment there.
	})

	// Admin-only routes (infra-sensitive: shell, VM control, keys, users, exec).
	// Gated at the router level so a new sensitive handler can never be exposed
	// to Viewers by forgetting an inline check.
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return appMiddleware.AuthMiddleware(store, db, next)
		})
		// Audit trail, mounted BEFORE AdminOnly on purpose: a Viewer poking an admin
		// route leaves an "HTTP 403" entry instead of no entry at all. It records only
		// state-changing methods, and only "METHOD /path" + outcome — never the query
		// string or the body, which carry TOTP codes, API tokens and private keys.
		r.Use(appMiddleware.AuditTrail(store, appMiddleware.DBAuditSink(db)))
		r.Use(func(next http.Handler) http.Handler {
			return appMiddleware.AdminOnly(store, db, next)
		})
		// Same onboarding gate as the authenticated group: the Proxmox-dependent
		// admin pages (/backups, /console, /ansible, /ssh) and their /api/* routes
		// are gated until Proxmox is configured; /onboarding/* is exempt by allowlist.
		r.Use(func(next http.Handler) http.Handler {
			return appMiddleware.OnboardingGate(h.ConfigStore.ProxmoxConfigured, next)
		})

		// Onboarding — in-app Proxmox connection (page + live test + save + env import).
		// Admin-only by group; the gate exempts these paths so they stay reachable on
		// a fresh, unconfigured instance.
		r.Get("/onboarding/proxmox", h.HandleOnboardingProxmox)
		r.Post("/onboarding/proxmox", h.HandleOnboardingProxmox)
		r.Post("/api/onboarding/proxmox/test", h.HandleOnboardingProxmoxTest)
		r.Post("/api/onboarding/proxmox/import-env", h.HandleOnboardingImportEnv)
		// Rollback: delete the in-app DB row, revert to the env fallback live.
		r.Post("/api/onboarding/proxmox/delete", h.HandleOnboardingDeleteProxmox)

		// Onboarding — unified Connexions page for the registry-held services
		// (Wazuh API, Wazuh Indexer, AI, Discord). Proxmox keeps its dedicated page
		// (linked from here). Not in the OnboardingGate allowlist ⇒ reachable on a
		// fresh instance. All four service quartets are wired.
		r.Get("/onboarding/connexions", h.HandleOnboardingConnexions)
		r.Post("/onboarding/wazuh-indexer", h.HandleOnboardingWazuhIndexer)
		r.Post("/api/onboarding/wazuh-indexer/test", h.HandleOnboardingWazuhIndexerTest)
		r.Post("/api/onboarding/wazuh-indexer/import-env", h.HandleOnboardingWazuhIndexerImportEnv)
		r.Post("/api/onboarding/wazuh-indexer/delete", h.HandleOnboardingWazuhIndexerDelete)
		r.Post("/onboarding/wazuh", h.HandleOnboardingWazuh)
		r.Post("/api/onboarding/wazuh/test", h.HandleOnboardingWazuhTest)
		r.Post("/api/onboarding/wazuh/import-env", h.HandleOnboardingWazuhImportEnv)
		r.Post("/api/onboarding/wazuh/delete", h.HandleOnboardingWazuhDelete)
		r.Post("/onboarding/ai", h.HandleOnboardingAI)
		r.Post("/api/onboarding/ai/test", h.HandleOnboardingAITest)
		r.Post("/api/onboarding/ai/import-env", h.HandleOnboardingAIImportEnv)
		r.Post("/api/onboarding/ai/delete", h.HandleOnboardingAIDelete)
		r.Post("/onboarding/discord", h.HandleOnboardingDiscord)
		r.Post("/api/onboarding/discord/test", h.HandleOnboardingDiscordTest)
		r.Post("/api/onboarding/discord/import-env", h.HandleOnboardingDiscordImportEnv)
		r.Post("/api/onboarding/discord/delete", h.HandleOnboardingDiscordDelete)

		// Settings hub — Admin-only sections. Services is the master-detail over the
		// four registry services (same POST endpoints as above). Proxmox/Sauvegarde are
		// aliases that re-use the dedicated onboarding handlers (re-chromed into the hub).
		r.Get("/parametres/services", h.HandleSettingsServices)
		r.Get("/parametres/utilisateurs", h.HandleSettingsUtilisateurs)
		r.Get("/parametres/proxmox", h.HandleOnboardingProxmox)
		r.Get("/parametres/sauvegarde", h.HandleOnboardingChannel)

		// Onboarding — read-only Proxmox helper CHANNEL (goabackup) + cloud self-service.
		// GoaCore GENERATES the ed25519 key and SERVES an auditable install script the
		// admin runs in root on THEIR Proxmox; it never opens an SSH session to install.
		// Provision (POST CSRF) generates+persists+hot-reloads the key; installer.sh/
		// helper.sh are Admin-only GETs serving the script/helper (pubkey is public, the
		// private key never leaves the DB); test runs a live disk-free proof; delete rolls
		// back and shows the host-side revocation command. Exempt from the OnboardingGate
		// by the /onboarding prefix ⇒ reachable on a fresh instance.
		r.Get("/onboarding/canal", h.HandleOnboardingChannel)
		r.Post("/api/onboarding/canal/provision", h.HandleOnboardingChannelProvision)
		r.Get("/api/onboarding/canal/installer.sh", h.HandleOnboardingChannelInstaller)
		r.Get("/api/onboarding/canal/helper.sh", h.HandleOnboardingChannelHelper)
		r.Post("/api/onboarding/canal/test", h.HandleOnboardingChannelTest)
		r.Post("/api/onboarding/canal/import-env", h.HandleOnboardingChannelImportEnv)
		r.Post("/api/onboarding/canal/delete", h.HandleOnboardingChannelDelete)

		// Proxmox — state-changing / sensitive
		r.Post("/api/proxmox/guest/power", h.HandleProxmoxPowerAction)
		r.Post("/api/proxmox/snapshots", h.HandleProxmoxSnapshotCreate)
		r.Delete("/api/proxmox/snapshots", h.HandleProxmoxSnapshotDelete)
		r.Post("/api/proxmox/snapshots/rollback", h.HandleProxmoxSnapshotRollback)
		r.Get("/api/proxmox/console", h.HandleProxmoxConsoleURL)
		r.Post("/api/proxmox/guest/create", h.HandleProxmoxCreateGuest)

		// SOAR — configuration & outbound tests
		r.Post("/api/soar/discord/test", h.HandleDiscordTest)
		r.Post("/api/soar/ai/test", h.HandleAITest)
		r.Post("/api/soar/config", h.HandleSoarConfig)

		// SSH Manager (lists keys, generates/deploys/deletes)
		r.Get("/ssh", h.HandleSSHManager)
		r.Post("/ssh", h.HandleSSHManager)
		r.Get("/api/ssh/generate", h.HandleSSHManager)
		r.Post("/api/ssh/generate", h.HandleSSHManager)
		r.Post("/api/ssh/deploy", h.HandleSSHDeploy)
		r.Delete("/api/ssh/delete", h.HandleSSHDelete)

		// Console — opens a root SSH shell on guests
		r.Get("/console", h.HandleConsolePage)
		r.Get("/api/ssh/ws", h.HandleSSHWebSocket)

		// Ansible — executes playbooks on the fleet
		r.Get("/ansible", h.HandleAnsible)
		r.Post("/api/ansible/run", h.HandleAnsibleRun)
		r.Post("/api/ansible/upload", h.HandleAnsibleUpload)
		r.Get("/api/ansible/playbook", h.HandleAnsiblePlaybookGet)
		r.Put("/api/ansible/playbook", h.HandleAnsiblePlaybookUpdate)
		r.Get("/api/ansible/schedules", h.HandleAnsibleSchedules)
		r.Post("/api/ansible/schedules", h.HandleAnsibleSchedules)
		r.Delete("/api/ansible/schedules", h.HandleAnsibleScheduleDelete)
		r.Post("/api/ansible/schedules/toggle", h.HandleAnsibleScheduleToggle)

		// Backups — management & restore testing (triggers restore/destroy)
		r.Get("/backups", h.HandleBackupPage)
		r.Post("/api/backups/create", h.HandleBackupCreate)
		r.Get("/api/backups/remotes", h.HandleBackupRemotes)
		r.Get("/api/backups/runs", h.HandleBackupRunsList)
		r.Post("/api/backups/test", h.HandleBackupTest)
		r.Get("/api/backups/tests", h.HandleBackupTestsList)
		r.Post("/api/backups/settings", h.HandleBackupSettings)
		r.Post("/api/backups/target-settings", h.HandleBackupTargetSettings)
		r.Get("/api/backups/available-guests", h.HandleBackupAvailableGuests)
		r.Post("/api/backups/targets", h.HandleBackupAddTarget)

		// Applications catalogue — MUTATIONS.
		//
		// The `apps` table is GLOBAL: it has no user_id, so every row is the shared
		// catalogue of the instance. Editing one is therefore an administrative act,
		// not a personal preference, and it is a sharp one: rewriting the external_url
		// of "Proxmox" turns the dashboard's own link into a credential-harvesting
		// page for every user. These routes used to sit in the authenticated group,
		// which let a Viewer — the role a small company gives a trainee or a
		// contractor — wipe or rewrite the whole catalogue while the product promised
		// Viewers were read-only.
		//
		// /api/apps/pin is here for the same reason: `UPDATE apps SET is_pinned` has
		// no per-user dimension either, so pinning is a change to everyone's dashboard,
		// not a favourite. It moves back to the authenticated group the day pins get
		// their own (user_id, app_id) table.
		r.Get("/add", h.HandleAddApp)
		r.Post("/add", h.HandleAddApp)
		r.Post("/api/apps/pin", h.HandleTogglePin)
		r.Post("/api/apps/update", h.HandleUpdateApp)
		r.Post("/api/apps/reorder", h.HandleReorderApps)
		r.Delete("/api/apps/delete", h.HandleDeleteApp)

		// User management & audit trail. /users is a legacy alias for the hub
		// Utilisateurs section.
		r.Get("/users", h.HandleSettingsUtilisateurs)
		r.Get("/audit-logs", h.HandleAuditLogs)
		r.Post("/api/users/add", h.HandleAddUser)
		r.Post("/api/users/delete", h.HandleDeleteUser)
		r.Post("/api/users/update", h.HandleUpdateUser)
		// Lost phone, or a SESSION_SECRET rotation that left every stored TOTP secret
		// undecipherable: without this the only way back into an account was a manual
		// UPDATE in the database. Also bumps the target's session epoch.
		r.Post("/api/users/reset-mfa", h.HandleResetUserMFA)
	})

	return r
}
