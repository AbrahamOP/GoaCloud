package models

import (
	"sync"
	"time"
)

// SoarConfig holds SOAR alert configuration.
type SoarConfig struct {
	AlertStatus   bool `json:"alert_status"`
	AlertSSH      bool `json:"alert_ssh"`
	AlertSudo     bool `json:"alert_sudo"`
	AlertFIM      bool `json:"alert_fim"`
	AlertPackages bool `json:"alert_packages"`
}

// SoarConfigState wraps SoarConfig with a mutex for concurrent access.
type SoarConfigState struct {
	Config SoarConfig
	Mutex  sync.RWMutex
}

// WazuhCache holds the cached Wazuh agent list.
type WazuhCache struct {
	Agents    []WazuhAgent
	UpdatedAt time.Time
	Mutex     sync.RWMutex
}

// CachedVulns holds vulnerability data with an expiry time.
type CachedVulns struct {
	Data   []WazuhVuln
	Expiry time.Time
}

// WazuhAgent represents a Wazuh agent.
type WazuhAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	NodeName      string `json:"node_name"`
	LastKeepAlive string `json:"lastKeepAlive"`
	OS            struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	} `json:"os"`
	VulnSummary struct {
		Total    int `json:"total"`
		High     int `json:"high"`
		Critical int `json:"critical"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"vuln_summary"`
}

// WazuhVuln represents a single vulnerability from Wazuh.
type WazuhVuln struct {
	CVE       string `json:"cve"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Condition string `json:"condition"`
	Package   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}
