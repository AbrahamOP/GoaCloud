package handlers

import (
	"database/sql"
	"html/template"
	"sync"

	"github.com/gorilla/sessions"
	"goacloud/internal/config"
	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
)

// Handler holds all handler dependencies (replaces global variables).
type Handler struct {
	DB           *sql.DB
	Templates    *template.Template
	SessionStore *sessions.CookieStore
	WazuhClient  *services.WazuhClient
	WazuhIndexer *services.WazuhIndexerClient
	AIClient     services.AIClient
	Discord      *services.DiscordBot
	Config       *config.Config
	WazuhCache   *models.WazuhCache
	VulnCache    *sync.Map
	SoarConfig   *models.SoarConfigState
	RateLimiter  *middleware.RateLimiter
	SSHService   *services.SSHService
	Proxmox      *services.ProxmoxService
}
