package models

// User represents an application user.
type User struct {
	ID         int
	Username   string
	Email      string
	Role       string
	CreatedAt  string
	MFAEnabled bool
	MFASecret  string
	GithubURL  string
}

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID        int
	UserID    int
	Username  string
	Action    string
	Details   string
	IPAddress string
	CreatedAt string
}
