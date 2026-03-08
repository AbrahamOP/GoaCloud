package models

// App represents an external application/link in the dashboard.
type App struct {
	ID          int
	Name        string
	Description string
	ExternalURL string
	IconURL     string
	Category    string
}
