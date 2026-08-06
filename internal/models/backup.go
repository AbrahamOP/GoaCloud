package models

import "time"

// BackupTarget represents an entity (VM/LXC/app) managed and verified by GoaBackup.
type BackupTarget struct {
	ID             int
	Name           string
	TargetType     string // "qemu", "lxc", "app"
	SourceRef      string // VMID (e.g. "110") or path for app backups
	Storage        string // Proxmox storage holding the dumps (e.g. "local")
	Enabled        bool
	RPOHours       int    // freshness threshold (hours) before an RPO breach
	ScheduleCron   string // optional cron expression for backups (informational)
	RetentionCount int    // number of backups to keep
	// RetentionEnabled is the explicit opt-in switch for archive rotation. It is
	// FALSE by default (schema + migration 4) because RetentionCount inherits a
	// value nobody chose: purging on it would destroy archives GoaCore never
	// produced. Only BackupService.UpdateTargetRetention flips it, and the UI must
	// present that as the destructive gesture it is.
	RetentionEnabled  bool
	HealthcheckType   string // "none", "port", "service", "sql"
	HealthcheckTarget string // port / service name / SQL command, per HealthcheckType
	CreatedAt         time.Time
}

// BackupRun is a single execution of a backup job (vzdump or app dump).
type BackupRun struct {
	ID          int
	TargetID    int
	BackupType  string // "vzdump", "app"
	Status      string // "pending", "running", "completed", "failed"
	StartedAt   *time.Time
	CompletedAt *time.Time
	SizeBytes   int64
	ArchivePath string // volid (local run) or archive file name (off-site push)
	// Checksum is NOT populated yet: the read-only Proxmox channel exposes no hashing
	// operation, and hashing a multi-gigabyte vzdump archive from the app would be
	// prohibitive. The archive identity of a restore proof therefore rests on
	// ArchivePath (see RestoreTest.RunID).
	Checksum    string
	Source      string // "manual", "scheduler", "external" (discovered)
	Message     string // error or info detail
	CreatedBy   string
	UPID        string // Proxmox task UPID (vzdump), for cross-referencing the task log
	Destination string // "local", "both", "remote" — where the backup is intended to live
	Remote      string // rclone remote name (empty for destination "local")
	PushStatus  string // "ok", "failed" or "" (no push attempted) — off-site copy outcome
	CreatedAt   time.Time
}

// BackupEntry is one backup archive reported by the Proxmox storage content API.
type BackupEntry struct {
	VolID     string // e.g. "local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst"
	VMID      int
	Type      string // "lxc" or "qemu"
	Storage   string
	SizeBytes int64
	CTime     time.Time
	Notes     string
	Format    string
}

// BackupTargetView is a target enriched with its latest backup + RPO status, for the UI.
type BackupTargetView struct {
	Target            BackupTarget
	HasBackup         bool
	LastBackupAt      time.Time
	LastBackupSize    int64
	FreshnessHours    float64
	RPOStatus         string // "ok", "warn", "breach", "none"
	LastBackupAtStr   string
	LastBackupSizeStr string
	LastBackupAgeStr  string
}

// BackupSummary aggregates RPO coverage across all targets for the KPI strip.
type BackupSummary struct {
	Total       int
	OK          int
	Warn        int
	Breach      int
	None        int
	AtRisk      int // Warn + Breach
	CoveragePct int
}

// RestoreTest is a single restore/verification run against a backup.
type RestoreTest struct {
	ID          int
	TargetID    int
	RunID       *int   // backup_run of the archive actually restored (nil: archive not produced by GoaCore)
	Level       string // "N1" (integrity), "N2" (restore+boot), "N3" (+healthcheck)
	Verdict     string // "pending", "running", "passed", "failed"
	SandboxVMID int    // disposable VMID used (95xx); 0 for N1-only
	RTOSeconds  int    // measured restore-to-ready time
	StartedAt   *time.Time
	CompletedAt *time.Time
	Logs        string
	TriggeredBy string // "manual", "scheduler"
	CreatedAt   time.Time
}
