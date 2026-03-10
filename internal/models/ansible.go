package models

import "time"

// AnsibleSchedule represents a scheduled playbook execution.
type AnsibleSchedule struct {
	ID              int        `json:"id"`
	Playbook        string     `json:"playbook"`
	VMID            int        `json:"vmid"`
	VMName          string     `json:"vm_name"`
	KeyID           int        `json:"key_id"`
	KeyName         string     `json:"key_name"`
	IntervalMinutes int        `json:"interval_minutes"`
	Enabled         bool       `json:"enabled"`
	NextRun         time.Time  `json:"next_run"`
	LastRun         *time.Time `json:"last_run"`
	LastStatus      string     `json:"last_status"`
	LastOutput      string     `json:"last_output,omitempty"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
}
