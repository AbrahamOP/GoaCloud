package router

import (
	"database/sql"
	"io/fs"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"goacloud/assets"
	"goacloud/internal/handlers"
	appMiddleware "goacloud/internal/middleware"
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
	r.Get("/logout", h.HandleLogout)
	r.Post("/logout", h.HandleLogout)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return appMiddleware.AuthMiddleware(store, db, next)
		})

		r.Get("/", h.HandleDashboard)
		r.Get("/report", h.HandleReport)
		r.Get("/add", h.HandleAddApp)
		r.Post("/add", h.HandleAddApp)

		// Proxmox
		r.Get("/proxmox", h.HandleProxmox)
		r.Get("/api/proxmox/stats", h.HandleProxmoxAPI)
		r.Get("/api/proxmox/guest", h.HandleProxmoxGuestDetail)
		r.Get("/api/proxmox/ips", h.HandleProxmoxIPs)
		r.Post("/api/proxmox/guest/power", h.HandleProxmoxPowerAction)
		r.Get("/api/proxmox/snapshots", h.HandleProxmoxSnapshots)
		r.Post("/api/proxmox/snapshots", h.HandleProxmoxSnapshotCreate)
		r.Delete("/api/proxmox/snapshots", h.HandleProxmoxSnapshotDelete)
		r.Post("/api/proxmox/snapshots/rollback", h.HandleProxmoxSnapshotRollback)
		r.Get("/api/proxmox/console", h.HandleProxmoxConsoleURL)
		r.Post("/api/proxmox/guest/create", h.HandleProxmoxCreateGuest)
		r.Get("/api/proxmox/metrics", h.HandleMetricsHistory)
		r.Get("/api/events", h.HandleSSE)

		// Wazuh & SOAR
		r.Get("/wazuh", h.HandleWazuh)
		r.Get("/soar", h.HandleSoar)
		r.Post("/api/soar/discord/test", h.HandleDiscordTest)
		r.Post("/api/soar/ai/test", h.HandleAITest)
		r.Get("/api/soar/config", h.HandleSoarConfig)
		r.Post("/api/soar/config", h.HandleSoarConfig)
		r.Get("/api/wazuh/vulns/{agentID}", h.HandleWazuhVulns)
		r.Get("/api/wazuh/cve/summary", h.HandleWazuhCVESummary)
		r.Get("/api/wazuh/agents/refresh", h.HandleWazuhAgentsRefresh)
		r.Get("/api/wazuh/geo", h.HandleWazuhGeoData)

		// SSH Manager
		r.Get("/ssh", h.HandleSSHManager)
		r.Post("/ssh", h.HandleSSHManager)
		r.Get("/api/ssh/generate", h.HandleSSHManager)
		r.Post("/api/ssh/generate", h.HandleSSHManager)
		r.Post("/api/ssh/deploy", h.HandleSSHDeploy)
		r.Delete("/api/ssh/delete", h.HandleSSHDelete)

		// Console
		r.Get("/console", h.HandleConsolePage)
		r.Get("/api/ssh/ws", h.HandleSSHWebSocket)

		// Ansible
		r.Get("/ansible", h.HandleAnsible)
		r.Post("/api/ansible/run", h.HandleAnsibleRun)
		r.Post("/api/ansible/upload", h.HandleAnsibleUpload)
		r.Get("/api/ansible/schedules", h.HandleAnsibleSchedules)
		r.Post("/api/ansible/schedules", h.HandleAnsibleSchedules)
		r.Delete("/api/ansible/schedules", h.HandleAnsibleScheduleDelete)
		r.Post("/api/ansible/schedules/toggle", h.HandleAnsibleScheduleToggle)

		// User Management
		r.Get("/users", h.HandleUsers)
		r.Get("/audit-logs", h.HandleAuditLogs)
		r.Post("/api/users/add", h.HandleAddUser)
		r.Post("/api/users/delete", h.HandleDeleteUser)
		r.Post("/api/users/update", h.HandleUpdateUser)

		// Profile
		r.Get("/profile", h.HandleProfile)
		r.Post("/api/profile/update", h.HandleUpdateProfile)
		r.Post("/api/profile/github", h.HandleUpdateGithub)
		r.Get("/api/me", h.HandleMe)

		// MFA
		r.Get("/api/mfa/setup", h.HandleSetupMFA)
		r.Post("/api/mfa/verify", h.HandleVerifyMFA)
		r.Post("/api/mfa/disable", h.HandleDisableMFA)

		// Search
		r.Get("/api/search", h.HandleSearch)

		// Apps management
		r.Post("/api/apps/pin", h.HandleTogglePin)
		r.Post("/api/apps/update", h.HandleUpdateApp)
		r.Delete("/api/apps/delete", h.HandleDeleteApp)
	})

	return r
}
