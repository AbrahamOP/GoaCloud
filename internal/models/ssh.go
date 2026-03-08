package models

import "time"

// SSHKey represents a stored SSH key pair.
type SSHKey struct {
	ID            int
	Name          string
	KeyType       string
	PublicKey     string
	PrivateKey    string
	Fingerprint   string
	CreatedAt     time.Time
	AssociatedVMs string // Comma-separated list of VM names/IDs
}
