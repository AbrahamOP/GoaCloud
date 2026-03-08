package models

// App represents an external application/link in the dashboard.
type App struct {
	ID            int
	Name          string
	Description   string
	ExternalURL   string
	IconURL       string
	Category      string
	HealthStatus  string // "up", "down", "unknown"
	HealthRespMs  int    // response time in ms
	HealthLastChk string // last check time
	IsPinned      bool
}
