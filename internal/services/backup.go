package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"goacore/internal/config"
	"goacore/internal/models"
)

// fallbackBackupStorage is the compiled default Proxmox storage scanned for vzdump
// archives when neither the target nor GOABACKUP_DEFAULT_STORAGE overrides it. The
// effective value is BackupService.defaultBackupStorage, seeded in NewBackupService.
const fallbackBackupStorage = "local"

// ErrBackupInProgress is returned when a backup is already running for a target.
var ErrBackupInProgress = errors.New("a backup is already running for this target")

// ErrNoRotationTarget is the sentinel returned by NextRotationTarget when there is
// no enabled backup target to schedule a restore test for. It is NOT fatal: the
// scheduler logs it and waits for the next opportunity.
var ErrNoRotationTarget = errors.New("no enabled backup target available for rotation")

// ErrUnknownRemote is returned when a backup is requested with an off-site
// destination (both/remote) but the chosen rclone remote is empty or is not one
// of the user's actual remotes. Remotes are NEVER hardcoded — they are validated
// live against the helper's rclone config.
var ErrUnknownRemote = errors.New("unknown or empty rclone remote")

// ErrServiceShuttingDown is returned when a new long-running orchestration (backup
// or restore test) is requested while the service is draining for shutdown. Starting
// one at that point would leave a half-finished restore — a booted clone of the
// customer's production guest whose destroy defer never runs — on the hypervisor.
var ErrServiceShuttingDown = errors.New("backup service is shutting down")

// Backup destinations. local = vzdump only; both = vzdump then copy to a remote,
// keeping the local copy; remote = vzdump then push to a remote and drop the
// local copy (true off-site destination).
const (
	DestinationLocal  = "local"
	DestinationBoth   = "both"
	DestinationRemote = "remote"
)

// validDestinations is the closed set of accepted backup destinations.
var validDestinations = map[string]bool{
	DestinationLocal:  true,
	DestinationBoth:   true,
	DestinationRemote: true,
}

// RemoteInfo describes one rclone remote and its capacity, for the UI. Sizes are
// best-effort: when `rclone about` does not report a value (or fails) the field
// is 0.
type RemoteInfo struct {
	Name       string
	UsedBytes  int64
	FreeBytes  int64
	TotalBytes int64
}

// validateDestination normalizes and validates a backup destination + remote
// pair. It is pure (no I/O) and table-testable: it checks the destination is in
// the closed set and that a remote is required (non-empty) for off-site
// destinations. The caller is responsible for the live "is this remote real?"
// check against RcloneRemotes. Returns the cleaned destination and remote.
func validateDestination(destination, remote string) (string, string, error) {
	d := strings.TrimSpace(strings.ToLower(destination))
	if d == "" {
		d = DestinationLocal
	}
	if !validDestinations[d] {
		return "", "", fmt.Errorf("invalid destination %q (allowed: local, both, remote)", destination)
	}
	r := strings.TrimSpace(remote)
	if d == DestinationLocal {
		// A remote is meaningless for a local-only backup; drop it.
		return d, "", nil
	}
	if r == "" {
		return "", "", ErrUnknownRemote
	}
	return d, r, nil
}

// sanitizeName cleans a target name coming from an untrusted source (Proxmox
// guest config / vm_cache, freely settable by a guest owner) before it is stored
// or rendered. It whitelists [A-Za-z0-9 ._-], drops anything else, trims and
// truncates to 64 characters, and falls back to "VM <vmid>" if empty.
func sanitizeName(name string, vmid int) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == ' ', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	cleaned := strings.TrimSpace(b.String())
	if len(cleaned) > 64 {
		cleaned = strings.TrimSpace(cleaned[:64])
	}
	if cleaned == "" {
		return fmt.Sprintf("VM %d", vmid)
	}
	return cleaned
}

// BackupService orchestrates backup inventory, RPO evaluation and restore testing.
type BackupService struct {
	db       *sql.DB
	proxmox  *ProxmoxService
	cfgStore *config.ConfigStore
	// discordProvider yields the LIVE Discord bot at emit time (never a frozen
	// pointer captured at wiring time), so a hot-reload swap reaches every alert.
	// nil-safe: an unset provider, or one that returns a nil bot, simply skips the
	// notification.
	discordProvider DiscordProvider
	// channelProvider yields the LIVE read-only Proxmox channel at the head of each
	// op (never a frozen pointer captured at wiring time), so a provision/rotation
	// hot-reload reaches every backup/restore path. nil-safe: an unset provider, or
	// one that returns a nil channel, degrades to a clean "channel not configured".
	channelProvider ChannelProvider

	// testInFlight tracks which target IDs currently have a restore test running,
	// to enforce one test at a time per target (anti-concurrency).
	//
	// sandboxInUse tracks which sandbox VMIDs ([9500,9599]) are currently reserved
	// by an in-flight test. It is the GLOBAL (cross-target) reservation that makes
	// it impossible for two concurrent tests on DIFFERENT targets to elect — and
	// then overwrite each other on — the same disposable VMID. Both maps are
	// protected by testMu.
	testMu       sync.Mutex
	testInFlight map[int]bool
	sandboxInUse map[int]bool

	// tasks / draining make the service's long-running orchestrations (vzdump
	// polling, restore tests) part of the APPLICATION lifecycle instead of being
	// fire-and-forget goroutines nobody waits for. Every `go` launched by the service
	// goes through startTask, and Wait(ctx) drains them at shutdown so a stop can
	// never abandon a booted sandbox clone (its destroy defer would never run) nor
	// mark "failed" a vzdump that Proxmox is about to complete.
	taskMu   sync.Mutex
	tasks    sync.WaitGroup
	draining bool

	// Disk pre-flight thresholds for the restore-test engine, seeded once at
	// construction from env (compiled defaults otherwise). They are static tuning,
	// not a hot-reloadable connection attribute, so they live on the service rather
	// than in the Proxmox snapshot.
	diskDataPctCeiling float64
	minLocalAvailBytes int64

	// defaultBackupStorage is the fallback Proxmox storage scanned for vzdump
	// archives when a target carries no explicit storage (env-overridable). Distinct
	// from the restore storage — this is a SCAN default, not a restore destination.
	defaultBackupStorage string
}

// NewBackupService creates a BackupService. The *config.ConfigStore is the live
// source of the Proxmox connection: every method that talks to Proxmox re-reads a
// coherent snapshot (cfgStore.ProxmoxSnapshot()) at its head, so an in-app
// re-onboarding is picked up by in-flight and future runs without a restart.
//
// cfg supplies the static (non-hot-reloadable) restore-test tuning: the disk
// pre-flight thresholds and the vzdump scan-default storage, each already bounded /
// defaulted by config.Load(). It may be nil (tests) → compiled defaults apply.
func NewBackupService(db *sql.DB, proxmox *ProxmoxService, cfgStore *config.ConfigStore, cfg *config.Config) *BackupService {
	ceiling := defaultDiskDataPctCeiling
	minAvail := int64(defaultMinLocalAvailBytes)
	scanStorage := fallbackBackupStorage
	if cfg != nil {
		if cfg.DiskCeilingPct > 0 {
			ceiling = cfg.DiskCeilingPct
		}
		if cfg.MinLocalAvailGiB >= 0 {
			minAvail = int64(cfg.MinLocalAvailGiB) * 1024 * 1024 * 1024
		}
		if cfg.DefaultBackupStorage != "" {
			scanStorage = cfg.DefaultBackupStorage
		}
	}
	return &BackupService{
		db:                   db,
		proxmox:              proxmox,
		cfgStore:             cfgStore,
		testInFlight:         make(map[int]bool),
		sandboxInUse:         make(map[int]bool),
		diskDataPctCeiling:   ceiling,
		minLocalAvailBytes:   minAvail,
		defaultBackupStorage: scanStorage,
	}
}

// startTask launches one of the service's long-running orchestrations inside the
// service's own wait group, so cmd/server/main.go can drain them at shutdown via
// Wait(ctx). It returns false — WITHOUT launching anything — once the service is
// draining: refusing a new restore/backup during shutdown is the whole point (a
// restore started at t-1s would leave a running clone of a production guest behind).
func (s *BackupService) startTask(fn func()) bool {
	s.taskMu.Lock()
	if s.draining {
		s.taskMu.Unlock()
		return false
	}
	s.tasks.Add(1)
	s.taskMu.Unlock()

	go func() {
		defer s.tasks.Done()
		fn()
	}()
	return true
}

// Wait drains the service: it first refuses any NEW orchestration (subsequent
// TriggerBackup / RunRestoreTest calls return ErrServiceShuttingDown), then blocks
// until every in-flight backup / restore test has finished — including the deferred
// destruction of its sandbox — or until ctx expires.
//
// It is the counterpart of the worker wait group in cmd/server/main.go: the workers
// are cancelled by their context, these orchestrations are DRAINED (never cancelled
// mid-restore, which is exactly what would leak a guest). Returns ctx.Err() when the
// shutdown deadline fires before the drain completes, so the caller can log the leak
// risk instead of exiting silently.
func (s *BackupService) Wait(ctx context.Context) error {
	s.taskMu.Lock()
	s.draining = true
	s.taskMu.Unlock()

	done := make(chan struct{})
	go func() {
		s.tasks.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		slog.Warn("backup: shutdown deadline reached with orchestrations still in flight — a sandbox guest may be left behind")
		return ctx.Err()
	}
}

// SetDiscordProvider wires the LIVE Discord source for backup / restore-test
// notifications (optional; nil-safe). It stores the provider (the registry), not a
// bot, so every emit reads the CURRENT bot via discordBot() and a hot-reload swap is
// picked up without re-wiring.
func (s *BackupService) SetDiscordProvider(p DiscordProvider) {
	s.discordProvider = p
}

// discordBot returns the live Discord bot at call time, or nil when Discord is
// unconfigured / disabled (nil provider, or provider returning nil). Every emit site
// MUST resolve through this, never cache the result, so a reload takes effect.
func (s *BackupService) discordBot() *DiscordBot {
	if s.discordProvider == nil {
		return nil
	}
	return s.discordProvider.Discord()
}

// SetChannelProvider wires the LIVE read-only Proxmox channel source (the
// ChannelRegistry). Every channel op resolves through liveChannel() at its head, so a
// provision/rotation hot-reload is picked up by in-flight and future runs without a
// restart. This is the preferred wiring; SetChannel is the static-pointer shim.
func (s *BackupService) SetChannelProvider(p ChannelProvider) {
	s.channelProvider = p
}

// SetChannel wires a single, FROZEN channel pointer for restore testing (optional;
// nil-safe — the feature degrades to clear errors if absent). It is the retro-compat
// shim: it wraps the pointer in a static provider so liveChannel() keeps working. New
// callers should prefer SetChannelProvider so a hot-reload reaches them.
func (s *BackupService) SetChannel(c *ProxmoxChannel) {
	s.channelProvider = staticChannelProvider{c: c}
}

// liveChannel resolves the channel to use for the current op. It NEVER returns nil:
// an unset provider or a provider returning nil collapses to an empty (unconfigured)
// *ProxmoxChannel, so every caller can safely call Configured()/ops and get a clean
// "not configured" error rather than a nil panic. Resolve through this at the head of
// every op — never cache the result — so a hot-reload takes effect on the next op.
func (s *BackupService) liveChannel() *ProxmoxChannel {
	if s.channelProvider == nil {
		return &ProxmoxChannel{}
	}
	if c := s.channelProvider.Channel(); c != nil {
		return c
	}
	return &ProxmoxChannel{}
}

// staticChannelProvider adapts a single frozen *ProxmoxChannel to the ChannelProvider
// contract, for the SetChannel retro-compat path and tests. It returns the same
// pointer every call (no hot-reload), which is exactly the legacy behaviour.
type staticChannelProvider struct{ c *ProxmoxChannel }

func (p staticChannelProvider) Channel() *ProxmoxChannel { return p.c }

// ListRemotes returns the user's rclone remotes with their capacity, for the UI.
// The remote names come LIVE from the helper (rclone listremotes) — they are never
// hardcoded — so a PME sees exactly its own destinations. The `about` capacity is
// best-effort: if it fails for a given remote, the name is still returned with all
// sizes at 0 (tolerant), so one broken backend never hides the rest of the list.
// Returns a clear error if the channel is not configured.
func (s *BackupService) ListRemotes() ([]RemoteInfo, error) {
	// Resolve the LIVE channel once at the head of the op (hot-reload aware).
	channel := s.liveChannel()
	if !channel.Configured() {
		return nil, fmt.Errorf("rclone destinations unavailable: Proxmox channel not configured")
	}
	names, err := channel.RcloneRemotes()
	if err != nil {
		return nil, fmt.Errorf("list rclone remotes: %w", err)
	}
	infos := make([]RemoteInfo, 0, len(names))
	for _, name := range names {
		info := RemoteInfo{Name: name}
		used, free, total, aerr := channel.RcloneAbout(name)
		if aerr != nil {
			// Tolerant: keep the remote in the list with zero sizes.
			slog.Warn("backup: rclone about failed", "remote", name, "error", aerr)
		} else {
			info.UsedBytes, info.FreeBytes, info.TotalBytes = used, free, total
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// Dashboard lists backups from Proxmox, auto-discovers targets, and returns each
// target enriched with its latest backup and RPO status, plus a coverage summary.
func (s *BackupService) Dashboard() ([]models.BackupTargetView, models.BackupSummary, error) {
	pm := s.cfgStore.ProxmoxSnapshot()
	entries, err := s.proxmox.ListBackups(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret, s.defaultBackupStorage)
	if err != nil {
		// Soft-fail: still render DB targets without fresh backup data.
		slog.Error("backup: list backups", "error", err)
	}

	// Latest archive per VMID.
	latest := make(map[int]models.BackupEntry)
	for _, e := range entries {
		if e.VMID == 0 {
			continue
		}
		if cur, ok := latest[e.VMID]; !ok || e.CTime.After(cur.CTime) {
			latest[e.VMID] = e
		}
	}

	// VM names from the existing cache.
	names := make(map[int]string)
	if rows, err := s.db.Query("SELECT vmid, name FROM vm_cache"); err == nil {
		for rows.Next() {
			var id int
			var n string
			if rows.Scan(&id, &n) == nil {
				names[id] = n
			}
		}
		rows.Close()
	}

	// Auto-discovery: ensure a target row exists for each VMID that has a backup.
	for vmid, e := range latest {
		// The name comes from the Proxmox guest config (vm_cache), which a guest
		// owner can freely set — sanitize before persisting.
		name := sanitizeName(names[vmid], vmid)
		if _, err := s.db.Exec(
			`INSERT IGNORE INTO backup_targets (name, target_type, source_ref, storage) VALUES (?, ?, ?, ?)`,
			name, e.Type, fmt.Sprintf("%d", vmid), e.Storage); err != nil {
			slog.Error("backup: upsert target", "vmid", vmid, "error", err)
		}
	}

	targets, err := s.loadTargets()
	if err != nil {
		return nil, models.BackupSummary{}, err
	}

	now := time.Now()
	views := make([]models.BackupTargetView, 0, len(targets))
	summary := models.BackupSummary{Total: len(targets)}

	for _, t := range targets {
		v := models.BackupTargetView{Target: t, RPOStatus: "none", LastBackupAtStr: "—", LastBackupSizeStr: "—", LastBackupAgeStr: "—"}
		vmid, _ := strconv.Atoi(t.SourceRef)
		if e, ok := latest[vmid]; ok {
			age := now.Sub(e.CTime)
			v.HasBackup = true
			v.LastBackupAt = e.CTime
			v.LastBackupSize = e.SizeBytes
			v.FreshnessHours = age.Hours()
			v.RPOStatus = rpoStatus(age, t.RPOHours)
			v.LastBackupAtStr = e.CTime.Format("02/01/2006 15:04")
			v.LastBackupSizeStr = humanSize(e.SizeBytes)
			v.LastBackupAgeStr = humanAge(age)
		}
		switch v.RPOStatus {
		case "ok":
			summary.OK++
		case "warn":
			summary.Warn++
		case "breach":
			summary.Breach++
		default:
			summary.None++
		}
		views = append(views, v)
	}

	summary.AtRisk = summary.Warn + summary.Breach
	if summary.Total > 0 {
		summary.CoveragePct = summary.OK * 100 / summary.Total
	}
	return views, summary, nil
}

// BackupSettings holds the global rotation configuration for scheduled restore
// tests. It lives in the backup_settings table (single row id=1) so the UI can
// change it and the worker reads it live, with no redeployment.
type BackupSettings struct {
	RotationEnabled bool
	RotationHour    int
	// AutoVerifyEnabled : si vrai, une vérification d'intégrité (N1, lecture seule)
	// est lancée automatiquement après chaque sauvegarde cloud réussie.
	AutoVerifyEnabled bool
}

// validHealthcheckTypes is the closed set of healthcheck strategies a target can
// declare.
var validHealthcheckTypes = map[string]bool{"none": true, "service": true, "port": true}

// validateTargetSettings is the pure, table-testable validation for a target's
// healthcheck + retention settings. It normalizes the healthcheck type (trim +
// lowercase) and returns the cleaned values, or an error if any field is invalid.
func validateTargetSettings(healthcheckType, healthcheckTarget string, retentionCount int) (string, string, error) {
	t := strings.TrimSpace(strings.ToLower(healthcheckType))
	if t == "" {
		t = "none"
	}
	if !validHealthcheckTypes[t] {
		return "", "", fmt.Errorf("invalid healthcheck type %q (allowed: none, service, port)", healthcheckType)
	}
	target := strings.TrimSpace(healthcheckTarget)
	if t == "port" {
		if target == "" {
			return "", "", errors.New("healthcheck target (port) is required when type is port")
		}
		port, err := strconv.Atoi(target)
		if err != nil || port < 1 || port > 65535 {
			return "", "", fmt.Errorf("healthcheck target must be a numeric port 1-65535, got %q", healthcheckTarget)
		}
	}
	if t == "none" {
		target = ""
	}
	if retentionCount < 0 {
		return "", "", fmt.Errorf("retention count must be >= 0, got %d", retentionCount)
	}
	return t, target, nil
}

// maxRPOHours bounds an acceptable RPO to one year. Beyond that the value stops
// being a contractual objective and becomes a way to make the coverage KPI green by
// accident.
const maxRPOHours = 8760

// validateRPOHours is the pure, table-testable validation of a target's RPO
// objective (in hours). It refuses 0 and negatives on purpose: rpoStatus() reads
// any value <= 0 as "always ok", so accepting it would silently paint a never-backed-
// up target green in the coverage KPI — the exact opposite of what the metric is for.
func validateRPOHours(rpoHours int) error {
	if rpoHours <= 0 {
		return fmt.Errorf("le RPO doit être d'au moins 1 heure, reçu %d", rpoHours)
	}
	if rpoHours > maxRPOHours {
		return fmt.Errorf("le RPO ne peut pas dépasser %d heures (1 an), reçu %d", maxRPOHours, rpoHours)
	}
	return nil
}

// validateRotationHour bounds the rotation hour to a valid 0-23 range.
func validateRotationHour(hour int) error {
	if hour < 0 || hour > 23 {
		return fmt.Errorf("rotation hour must be between 0 and 23, got %d", hour)
	}
	return nil
}

// GetSettings returns the global backup rotation settings (row id=1). If the row
// is somehow absent it falls back to safe defaults {disabled, 4h} instead of
// erroring, so the worker never crashes on a missing row.
func (s *BackupService) GetSettings() (BackupSettings, error) {
	var bs BackupSettings
	// COALESCE : la colonne auto_verify_enabled peut être absente d'une table très
	// ancienne le temps que la migration ADD COLUMN passe ; on reste robuste.
	err := s.db.QueryRow(
		`SELECT rotation_enabled, rotation_hour, COALESCE(auto_verify_enabled, FALSE) FROM backup_settings WHERE id = 1`).
		Scan(&bs.RotationEnabled, &bs.RotationHour, &bs.AutoVerifyEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupSettings{RotationEnabled: false, RotationHour: 4}, nil
	}
	if err != nil {
		return BackupSettings{}, fmt.Errorf("get backup settings: %w", err)
	}
	return bs, nil
}

// SetSettings updates the global rotation settings (row id=1). The hour is
// validated to 0-23 before any write.
func (s *BackupService) SetSettings(enabled bool, hour int, autoVerify bool) error {
	if err := validateRotationHour(hour); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`UPDATE backup_settings SET rotation_enabled = ?, rotation_hour = ?, auto_verify_enabled = ? WHERE id = 1`,
		enabled, hour, autoVerify)
	if err != nil {
		return fmt.Errorf("set backup settings: %w", err)
	}
	return nil
}

// maybeAutoVerify lance une vérification d'intégrité N1 (cryptcheck off-site, lecture
// seule) sur la cible si l'option est active. Appelé après une sauvegarde cloud
// réussie. Best-effort : un test déjà en cours (ErrRestoreTestInProgress) ou une erreur
// est seulement loggé et ne perturbe jamais le flux de sauvegarde. Le rapport (UI +
// Discord) est produit par RunRestoreTest comme pour un test manuel.
func (s *BackupService) maybeAutoVerify(targetID int, name string) {
	bs, err := s.GetSettings()
	if err != nil || !bs.AutoVerifyEnabled {
		return
	}
	if _, terr := s.RunRestoreTest(targetID, "N1", "auto (après sauvegarde)"); terr != nil {
		slog.Warn("backup: auto-verify N1 non lancé", "target_id", targetID, "name", name, "error", terr)
	}
}

// GuestOption décrit une machine Proxmox connue (cache de monitoring) proposable
// comme nouvelle cible de sauvegarde dans l'UI.
type GuestOption struct {
	VMID int    `json:"vmid"`
	Name string `json:"name"`
	Type string `json:"type"` // "qemu" (VM) | "lxc" (CT)
}

// AvailableGuests liste les machines connues (vm_cache, alimenté par le monitoring
// Proxmox) qui ne sont PAS encore des cibles de sauvegarde — pour le sélecteur
// « Ajouter une machine ». Ne dépend que de la DB (pas d'appel Proxmox).
func (s *BackupService) AvailableGuests() ([]GuestOption, error) {
	rows, err := s.db.Query(`
		SELECT vmid, name, vm_type FROM vm_cache
		WHERE CAST(vmid AS CHAR) NOT IN (SELECT source_ref FROM backup_targets)
		ORDER BY vmid`)
	if err != nil {
		return nil, fmt.Errorf("available guests: %w", err)
	}
	defer rows.Close()
	out := []GuestOption{}
	for rows.Next() {
		var g GuestOption
		var name, vmType sql.NullString
		if err := rows.Scan(&g.VMID, &name, &vmType); err != nil {
			continue
		}
		g.Name = name.String
		g.Type = vmType.String
		out = append(out, g)
	}
	return out, rows.Err()
}

// AddTarget enregistre manuellement une cible de sauvegarde (machine Proxmox) qui n'a
// pas encore d'archive, afin de pouvoir la sauvegarder depuis l'UI. vmType doit être
// "qemu" (VM) ou "lxc" (CT) — le même type que celui attendu par vzdump. Le nom est
// nettoyé avant persistance. Idempotent (INSERT IGNORE sur source_ref).
func (s *BackupService) AddTarget(vmid int, vmType, name string) error {
	if vmid <= 0 {
		return fmt.Errorf("VMID invalide : %d", vmid)
	}
	vmType = strings.ToLower(strings.TrimSpace(vmType))
	if vmType != "qemu" && vmType != "lxc" {
		return fmt.Errorf("type invalide %q (attendu : qemu ou lxc)", vmType)
	}
	name = sanitizeName(name, vmid)
	if _, err := s.db.Exec(
		`INSERT IGNORE INTO backup_targets (name, target_type, source_ref, storage) VALUES (?, ?, ?, ?)`,
		name, vmType, strconv.Itoa(vmid), s.defaultBackupStorage); err != nil {
		return fmt.Errorf("add backup target: %w", err)
	}
	return nil
}

// UpdateTargetSettings updates a single target's healthcheck strategy and backup
// retention count. All inputs are validated (closed healthcheck-type set, numeric
// port when type=port, non-negative retention) before any write.
func (s *BackupService) UpdateTargetSettings(targetID int, healthcheckType, healthcheckTarget string, retentionCount int) error {
	if targetID <= 0 {
		return fmt.Errorf("invalid target id %d", targetID)
	}
	cleanType, cleanTarget, err := validateTargetSettings(healthcheckType, healthcheckTarget, retentionCount)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`UPDATE backup_targets SET healthcheck_type = ?, healthcheck_target = ?, retention_count = ? WHERE id = ?`,
		cleanType, cleanTarget, retentionCount, targetID)
	if err != nil {
		return fmt.Errorf("update target settings: %w", err)
	}
	return nil
}

// UpdateTargetRPO updates a single target's RPO objective (hours), the contractual
// metric that drives the ok/warn/breach status and the coverage KPI. It was until now
// frozen at the schema default (24 h) with no way to change it, which made the KPI
// unusable for a customer whose objective is 4 h — or 7 days. The value is validated
// (1..8760) before any write, exactly like the healthcheck settings above.
func (s *BackupService) UpdateTargetRPO(targetID, rpoHours int) error {
	if targetID <= 0 {
		return fmt.Errorf("invalid target id %d", targetID)
	}
	if err := validateRPOHours(rpoHours); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE backup_targets SET rpo_hours = ? WHERE id = ?`, rpoHours, targetID)
	if err != nil {
		return fmt.Errorf("update target rpo: %w", err)
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return fmt.Errorf("cible %d introuvable", targetID)
	}
	return nil
}

// backupPollInterval is how often the async worker polls the vzdump task status.
const backupPollInterval = 5 * time.Second

// backupTimeout caps how long a single on-demand backup may run before giving up.
const backupTimeout = 30 * time.Minute

// TriggerBackup records a manual backup run, launches an async vzdump, and returns
// the new run ID immediately. The actual dump + polling + notification happen in a
// recover-guarded goroutine so a failure can never panic the server.
//
// destination is one of {local, both, remote}. For both/remote, remote must be a
// real rclone remote of the user (validated live against the helper); GoaCore
// never hardcodes remote names. ErrUnknownRemote is returned when the remote is
// empty or not present in RcloneRemotes.
func (s *BackupService) TriggerBackup(targetID int, destination, remote, username string) (int, error) {
	// Validate the destination + remote pair (pure) before any I/O.
	destination, remote, err := validateDestination(destination, remote)
	if err != nil {
		return 0, err
	}

	// For off-site destinations, the channel is mandatory and the remote must be
	// one of the user's real rclone remotes (listed dynamically, never hardcoded).
	if destination != DestinationLocal {
		channel := s.liveChannel()
		if !channel.Configured() {
			return 0, fmt.Errorf("destination %q requires the Proxmox channel, which is not configured", destination)
		}
		remotes, rerr := channel.RcloneRemotes()
		if rerr != nil {
			return 0, fmt.Errorf("list rclone remotes: %w", rerr)
		}
		known := false
		for _, rn := range remotes {
			if rn == remote {
				known = true
				break
			}
		}
		if !known {
			return 0, ErrUnknownRemote
		}
	}

	// Look up the target (vmid + type) before doing anything else.
	var vmidStr, targetType, name, storage string
	err = s.db.QueryRow(
		`SELECT source_ref, target_type, name, storage FROM backup_targets WHERE id = ?`,
		targetID).Scan(&vmidStr, &targetType, &name, &storage)
	if err != nil {
		return 0, fmt.Errorf("target not found: %w", err)
	}
	vmid, convErr := strconv.Atoi(vmidStr)
	if convErr != nil || vmid <= 0 {
		return 0, fmt.Errorf("target %d has no valid VMID (%q)", targetID, vmidStr)
	}
	// Defense in depth: rows predating sanitization (or edited directly) may hold
	// an unsafe name. Sanitize again before it flows into Discord notifications.
	name = sanitizeName(name, vmid)
	if storage == "" {
		storage = s.defaultBackupStorage
	}

	// Map the Proxmox guest type for the API path. Auto-discovered targets store
	// "lxc"/"qemu" already; default to qemu if unknown.
	pveType := "qemu"
	if targetType == "lxc" {
		pveType = "lxc"
	}

	// Anti-concurrency: refuse to start a second vzdump while one is still running
	// for this target. The check + insert is atomic via INSERT ... SELECT ... WHERE
	// NOT EXISTS, so two concurrent requests cannot both win the race.
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO backup_runs (target_id, backup_type, status, started_at, source, created_by, message, destination, remote)
		 SELECT ?, ?, 'running', ?, 'manual', ?, ?, ?, ?
		 FROM DUAL
		 WHERE NOT EXISTS (
		     SELECT 1 FROM backup_runs WHERE target_id = ? AND status = 'running'
		 )`,
		targetID, "vzdump", now, username, "Sauvegarde à la demande lancée", destination, remote, targetID)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return 0, ErrBackupInProgress
	}
	runID64, _ := res.LastInsertId()
	runID := int(runID64)

	// The dump orchestration belongs to the application lifecycle (see startTask): a
	// shutdown drains it instead of abandoning it half-way.
	if !s.startTask(func() {
		s.runBackupAsync(runID, targetID, vmid, name, pveType, storage, destination, remote)
	}) {
		s.finishRun(runID, "failed", 0, "", "Sauvegarde non lancée : arrêt du service en cours")
		return 0, ErrServiceShuttingDown
	}

	return runID, nil
}

// destinationLabel renders a human-readable destination for messages/notifications:
// "Local", "Local + <remote>" or "<remote>" (off-site only). Pure.
func destinationLabel(destination, remote string) string {
	switch destination {
	case DestinationBoth:
		return "Local + " + remote
	case DestinationRemote:
		return remote
	default:
		return "Local"
	}
}

// runBackupAsync performs the vzdump, polls until completion, optionally pushes the
// archive off-site (rclone), updates the run row and notifies Discord. It is
// recover-guarded so it can never crash the process.
func (s *BackupService) runBackupAsync(runID, targetID, vmid int, name, pveType, storage, destination, remote string) {
	destLabel := destinationLabel(destination, remote)
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("backup: panic in async worker recovered", "run_id", runID, "panic", rec)
			s.finishRun(runID, "failed", 0, "", fmt.Sprintf("panic interne: %v", rec))
			s.notifyBackup(name, vmid, "vzdump", "failed", destLabel, fmt.Sprintf("panic interne: %v", rec))
		}
	}()

	pm := s.cfgStore.ProxmoxSnapshot()
	s.notifyBackup(name, vmid, "vzdump", "started", destLabel, "")

	upid, err := s.proxmox.CreateBackup(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, pveType, strconv.Itoa(vmid), storage)
	if err != nil {
		msg := fmt.Sprintf("Échec du déclenchement vzdump: %v", err)
		slog.Error("backup: create vzdump", "run_id", runID, "vmid", vmid, "error", err)
		s.finishRun(runID, "failed", 0, "", msg)
		s.notifyBackup(name, vmid, "vzdump", "failed", destLabel, msg)
		return
	}
	slog.Info("backup: vzdump started", "run_id", runID, "vmid", vmid, "upid", upid)
	s.setRunUPID(runID, upid)

	deadline := time.Now().Add(backupTimeout)
	for {
		if time.Now().After(deadline) {
			msg := fmt.Sprintf("Timeout après %s (tâche %s toujours en cours)", backupTimeout, upid)
			slog.Error("backup: vzdump timeout", "run_id", runID, "vmid", vmid, "upid", upid)
			s.finishRun(runID, "failed", 0, "", msg)
			s.notifyBackup(name, vmid, "vzdump", "failed", destLabel, msg)
			return
		}
		time.Sleep(backupPollInterval)

		// Re-read a fresh, coherent snapshot each poll so a hot-reload mid-run is
		// honoured on the very next iteration.
		pm := s.cfgStore.ProxmoxSnapshot()
		status, exitStatus, statErr := s.proxmox.GetTaskStatus(pm.URL, pm.Node,
			pm.TokenID, pm.TokenSecret, upid)
		if statErr != nil {
			// Transient polling error: log and keep trying until the deadline.
			slog.Warn("backup: poll task status", "run_id", runID, "upid", upid, "error", statErr)
			continue
		}
		if status == "running" {
			continue
		}
		// status == "stopped" (or anything non-running): task finished.
		if exitStatus == "OK" {
			size, archive := s.lookupLatestArchive(vmid, storage)
			// The local vzdump succeeded. If an off-site destination was requested,
			// push it now; a push failure means the destination objective was NOT
			// met, so the whole run is marked failed (the local copy still exists).
			if destination == DestinationLocal {
				msg := fmt.Sprintf("Sauvegarde terminée (tâche %s)", upid)
				slog.Info("backup: vzdump completed", "run_id", runID, "vmid", vmid, "archive", archive, "size", size)
				s.finishRunDest(runID, "completed", size, archive, destination, remote, "", msg)
				s.notifyBackup(name, vmid, "vzdump", "completed", destLabel, msg)
				// Rotation : la sauvegarde vient de réussir, on peut purger les archives
				// excédentaires de CETTE machine (jamais avant : on ne supprime rien tant
				// qu'on n'a pas une archive fraîche de plus).
				s.applyRetention(targetID, vmid, storage)
				return
			}

			keepLocal := destination == DestinationBoth
			// Resolve the LIVE channel at the head of the push (hot-reload aware).
			pushedArchive, pushErr := s.liveChannel().RclonePush(vmid, remote, keepLocal)
			if pushErr != nil {
				msg := fmt.Sprintf("vzdump local OK mais échec de l'envoi vers %s : %v (la copie locale est conservée)", remote, pushErr)
				slog.Error("backup: rclone push failed", "run_id", runID, "vmid", vmid, "remote", remote, "error", pushErr)
				s.finishRunDest(runID, "failed", size, archive, destination, remote, "failed", msg)
				s.notifyBackup(name, vmid, "vzdump", "failed", destLabel, msg)
				return
			}
			if pushedArchive != "" {
				archive = pushedArchive
			}
			var msg string
			if destination == DestinationRemote {
				msg = fmt.Sprintf("Sauvegarde envoyée sur %s, copie locale supprimée (tâche %s)", remote, upid)
			} else {
				msg = fmt.Sprintf("Sauvegarde terminée localement et copiée sur %s (tâche %s)", remote, upid)
			}
			slog.Info("backup: vzdump + push completed", "run_id", runID, "vmid", vmid, "remote", remote, "destination", destination, "archive", archive)
			s.finishRunDest(runID, "completed", size, archive, destination, remote, "ok", msg)
			s.notifyBackup(name, vmid, "vzdump", "completed", destLabel, msg)
			// Rotation des archives locales excédentaires (voir applyRetention). Pour
			// destination=remote la copie locale vient d'être supprimée par rclone : la
			// rotation ne concerne alors que d'anciennes archives restées sur le storage.
			s.applyRetention(targetID, vmid, storage)
			// Vérification d'intégrité automatique de la copie off-site fraîchement poussée
			// (si activée dans les paramètres). Lecture seule, sans incidence sur la prod.
			s.maybeAutoVerify(targetID, name)
		} else {
			msg := fmt.Sprintf("vzdump a échoué: %s", exitStatus)
			slog.Error("backup: vzdump failed", "run_id", runID, "vmid", vmid, "exit", exitStatus)
			s.finishRunDest(runID, "failed", 0, "", destination, remote, "", msg)
			s.notifyBackup(name, vmid, "vzdump", "failed", destLabel, msg)
		}
		return
	}
}

// lookupLatestArchive re-queries the storage for the most recent archive of vmid,
// best-effort to fill size/path on a successful run. Errors are non-fatal.
func (s *BackupService) lookupLatestArchive(vmid int, storage string) (int64, string) {
	pm := s.cfgStore.ProxmoxSnapshot()
	entries, err := s.proxmox.ListBackups(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, storage)
	if err != nil {
		slog.Warn("backup: list archives after success", "vmid", vmid, "error", err)
		return 0, ""
	}
	var best models.BackupEntry
	found := false
	for _, e := range entries {
		if e.VMID != vmid {
			continue
		}
		if !found || e.CTime.After(best.CTime) {
			best = e
			found = true
		}
	}
	if !found {
		return 0, ""
	}
	return best.SizeBytes, best.VolID
}

// archivesToPrune elects the archives of vmid that must be deleted so that only the
// `keep` most recent ones remain. It is the PURE core of the retention rotation, and
// it is deliberately conservative — this is the only place in GoaCore that decides to
// destroy a customer's backup:
//
//   - keep <= 0 (réglage absent / rétention désactivée) ⇒ NOTHING is ever pruned;
//   - entries belonging to another VMID are never candidates, and a volid whose file
//     name does not carry vmid either (same VMID coherence check as the restore
//     engine's M1 guard) — a mislabelled listing must not cost a foreign archive;
//   - with fewer than (or exactly) keep archives, nothing is pruned.
//
// Election order: most recent first (CTime desc), volid as a tie-breaker so two
// archives sharing a timestamp give a deterministic, reproducible decision.
func archivesToPrune(entries []models.BackupEntry, vmid, keep int) []models.BackupEntry {
	if keep <= 0 || vmid <= 0 {
		return nil
	}
	owned := make([]models.BackupEntry, 0, len(entries))
	for _, e := range entries {
		if e.VMID != vmid || !volIDBelongsToVMID(e.VolID, vmid) {
			continue
		}
		owned = append(owned, e)
	}
	if len(owned) <= keep {
		return nil
	}
	sort.Slice(owned, func(i, j int) bool {
		if owned[i].CTime.Equal(owned[j].CTime) {
			return owned[i].VolID > owned[j].VolID
		}
		return owned[i].CTime.After(owned[j].CTime)
	})
	return owned[keep:]
}

// retentionCountFor reads the target's configured retention (number of archives to
// keep). Any DB error yields 0 — i.e. "rétention désactivée", the safe answer: a
// transient DB hiccup must never be read as "keep nothing".
func (s *BackupService) retentionCountFor(targetID int) int {
	if s.db == nil {
		return 0
	}
	var keep sql.NullInt64
	if err := s.db.QueryRow(
		`SELECT retention_count FROM backup_targets WHERE id = ?`, targetID).Scan(&keep); err != nil {
		slog.Error("backup: read retention count", "target_id", targetID, "error", err)
		return 0
	}
	if !keep.Valid || keep.Int64 <= 0 {
		return 0
	}
	return int(keep.Int64)
}

// applyRetention enforces the target's retention_count AFTER a successful backup:
// it lists the archives of the target's VMID on its storage and deletes the oldest
// ones beyond the N most recent. Without it the setting is a lie the UI tells the
// customer, and the archives pile up until the Proxmox storage is full (which also
// blocks the restore tests via the disk guard).
//
// Best-effort by design: it NEVER fails the run that just succeeded. Every deletion
// is logged (a destructive act on customer data must be auditable), and the actual
// DELETE re-checks VMID ownership host-side (DeleteBackupArchive).
func (s *BackupService) applyRetention(targetID, vmid int, storage string) {
	keep := s.retentionCountFor(targetID)
	if keep <= 0 {
		// Aucune rétention configurée : on ne supprime rien, jamais.
		return
	}
	if storage == "" {
		storage = s.defaultBackupStorage
	}

	pm := s.cfgStore.ProxmoxSnapshot()
	entries, err := s.proxmox.ListBackups(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret, storage)
	if err != nil {
		slog.Error("backup: retention listing failed", "target_id", targetID, "vmid", vmid, "storage", storage, "error", err)
		return
	}

	prune := archivesToPrune(entries, vmid, keep)
	if len(prune) == 0 {
		return
	}
	slog.Info("backup: retention rotation", "target_id", targetID, "vmid", vmid,
		"storage", storage, "keep", keep, "to_delete", len(prune))
	for _, e := range prune {
		archiveStorage := e.Storage
		if archiveStorage == "" {
			archiveStorage = storage
		}
		if _, derr := s.proxmox.DeleteBackupArchive(pm.URL, pm.Node, pm.TokenID,
			pm.TokenSecret, archiveStorage, e.VolID, vmid); derr != nil {
			slog.Error("backup: retention delete failed", "vmid", vmid, "volid", e.VolID, "error", derr)
			continue
		}
		slog.Info("backup: retention archive deleted", "target_id", targetID, "vmid", vmid,
			"volid", e.VolID, "created_at", e.CTime, "size", e.SizeBytes)
	}
}

// setRunUPID persists the Proxmox task UPID on a run as soon as it is known.
func (s *BackupService) setRunUPID(runID int, upid string) {
	if _, err := s.db.Exec(`UPDATE backup_runs SET upid = ? WHERE id = ?`, upid, runID); err != nil {
		slog.Error("backup: update run upid", "run_id", runID, "error", err)
	}
}

// ReconcileRunningRuns marks any run still flagged "running" as failed. Such rows
// are zombies: their driving goroutine was killed by a server restart, so they can
// never reach a terminal state on their own. Returns the number of runs reconciled.
func (s *BackupService) ReconcileRunningRuns() (int64, error) {
	res, err := s.db.Exec(
		`UPDATE backup_runs
		 SET status = 'failed', completed_at = NOW(), message = 'Interrompu (redémarrage serveur)'
		 WHERE status = 'running'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// finishRun updates a backup_runs row to its terminal state, leaving the
// destination columns untouched (they were set at insert time). Used by the
// panic-recover path where destination context is not in scope.
func (s *BackupService) finishRun(runID int, status string, size int64, archive, message string) {
	_, err := s.db.Exec(
		`UPDATE backup_runs
		 SET status = ?, completed_at = ?, size_bytes = ?, archive_path = ?, message = ?
		 WHERE id = ?`,
		status, time.Now(), size, archive, message, runID)
	if err != nil {
		slog.Error("backup: update run", "run_id", runID, "error", err)
	}
}

// finishRunDest updates a backup_runs row to its terminal state and records the
// resolved destination + remote + push outcome. pushStatus is "ok", "failed" or
// "" (no push attempted).
func (s *BackupService) finishRunDest(runID int, status string, size int64, archive, destination, remote, pushStatus, message string) {
	_, err := s.db.Exec(
		`UPDATE backup_runs
		 SET status = ?, completed_at = ?, size_bytes = ?, archive_path = ?,
		     destination = ?, remote = ?, push_status = ?, message = ?
		 WHERE id = ?`,
		status, time.Now(), size, archive, destination, remote, pushStatus, message, runID)
	if err != nil {
		slog.Error("backup: update run", "run_id", runID, "error", err)
	}
}

// notifyBackup sends a Discord backup alert if a bot is configured (nil-safe).
// destLabel is the human-readable destination (Local / Local+remote / remote) and
// is prepended to the details so the off-site target is visible in the alert.
// The actual network call runs in its own recover-guarded goroutine so a slow or
// failing Discord can never sit in the critical path of finishRun / state polling.
func (s *BackupService) notifyBackup(name string, vmid int, backupType, status, destLabel, details string) {
	// Resolve the LIVE bot at emit time so a hot-reload swap reaches this alert.
	discord := s.discordBot()
	if discord == nil || !discord.IsReady() {
		return
	}
	full := details
	if destLabel != "" {
		line := "Destination : " + destLabel
		if full == "" {
			full = line
		} else {
			full = line + "\n" + full
		}
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("backup: panic in Discord notification recovered", "panic", rec)
			}
		}()
		if err := discord.SendBackupAlert(name, vmid, backupType, status, full); err != nil {
			slog.Error("backup: Discord notification failed", "error", err)
		}
	}()
}

// RecentRuns returns recent backup runs, optionally filtered by target, newest first.
func (s *BackupService) RecentRuns(targetID, limit int) ([]models.BackupRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	base := `SELECT id, target_id, backup_type, status, started_at, completed_at,
		size_bytes, archive_path, source, message, created_by, upid,
		destination, remote, push_status, created_at
		FROM backup_runs`
	if targetID > 0 {
		rows, err = s.db.Query(base+` WHERE target_id = ? ORDER BY id DESC LIMIT ?`, targetID, limit)
	} else {
		rows, err = s.db.Query(base+` ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []models.BackupRun
	for rows.Next() {
		var run models.BackupRun
		var started, completed sql.NullTime
		var archive, message, createdBy, upid, destination, remote, pushStatus sql.NullString
		var size sql.NullInt64
		if err := rows.Scan(&run.ID, &run.TargetID, &run.BackupType, &run.Status,
			&started, &completed, &size, &archive, &run.Source, &message,
			&createdBy, &upid, &destination, &remote, &pushStatus, &run.CreatedAt); err != nil {
			slog.Error("backup: scan run", "error", err)
			continue
		}
		if started.Valid {
			run.StartedAt = &started.Time
		}
		if completed.Valid {
			run.CompletedAt = &completed.Time
		}
		run.SizeBytes = size.Int64
		run.ArchivePath = archive.String
		run.Message = message.String
		run.CreatedBy = createdBy.String
		run.UPID = upid.String
		run.Destination = destination.String
		run.Remote = remote.String
		run.PushStatus = pushStatus.String
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

// loadTargets returns all backup targets ordered by numeric source ref.
func (s *BackupService) loadTargets() ([]models.BackupTarget, error) {
	rows, err := s.db.Query(`SELECT id, name, target_type, source_ref, storage, enabled,
		rpo_hours, retention_count, healthcheck_type, healthcheck_target, created_at
		FROM backup_targets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []models.BackupTarget
	for rows.Next() {
		var t models.BackupTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.TargetType, &t.SourceRef, &t.Storage,
			&t.Enabled, &t.RPOHours, &t.RetentionCount, &t.HealthcheckType,
			&t.HealthcheckTarget, &t.CreatedAt); err != nil {
			slog.Error("backup: scan target", "error", err)
			continue
		}
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool {
		a, _ := strconv.Atoi(targets[i].SourceRef)
		b, _ := strconv.Atoi(targets[j].SourceRef)
		return a < b
	})
	return targets, rows.Err()
}

// rotationRow is one candidate considered by the scheduled-test rotation: an
// enabled backup target and (a marker for) the age of its most recent restore
// test. lastTest.Valid is false when the target has NEVER been tested.
type rotationRow struct {
	ID              int
	Name            string
	SourceRef       string
	HealthcheckType string
}

// rotationLevel derives the restore-test level for a target from its healthcheck
// configuration: N3 (restore + boot + in-guest healthcheck) when a healthcheck is
// configured, N2 (restore + boot only) otherwise. Pure and table-testable.
func rotationLevel(healthcheckType string) string {
	t := strings.TrimSpace(strings.ToLower(healthcheckType))
	if t != "" && t != "none" {
		return "N3"
	}
	return "N2"
}

// NextRotationTarget selects the enabled backup target that is the most "behind"
// on restore testing: the one whose most recent restore_tests row is the oldest,
// with NEVER-tested targets taking absolute priority. It returns the target ID,
// the derived test level (N2/N3), and the target name.
//
// If there is no enabled target it returns ErrNoRotationTarget (a non-fatal
// sentinel the scheduler handles gracefully).
//
// SQL: LEFT JOIN each enabled target onto the MAX(created_at) of its restore
// tests; order never-tested first (last_test IS NOT NULL ⇒ 0 sorts ahead), then
// by oldest last_test ascending. Ties break on the lowest target id for a stable,
// deterministic rotation.
func (s *BackupService) NextRotationTarget() (int, string, string, error) {
	const q = `
		SELECT bt.id, bt.name, bt.source_ref, COALESCE(bt.healthcheck_type, '')
		FROM backup_targets bt
		LEFT JOIN (
		    SELECT target_id, MAX(created_at) AS last_test
		    FROM restore_tests
		    GROUP BY target_id
		) rt ON rt.target_id = bt.id
		WHERE bt.enabled = TRUE
		ORDER BY rt.last_test IS NOT NULL, rt.last_test ASC, bt.id ASC
		LIMIT 1`

	var row rotationRow
	err := s.db.QueryRow(q).Scan(&row.ID, &row.Name, &row.SourceRef, &row.HealthcheckType)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", ErrNoRotationTarget
	}
	if err != nil {
		return 0, "", "", fmt.Errorf("select rotation target: %w", err)
	}

	name := sanitizeName(row.Name, mustAtoi(row.SourceRef))
	return row.ID, rotationLevel(row.HealthcheckType), name, nil
}

// SchedulerTestRanToday reports whether a scheduler-triggered restore test has
// already been created today (server local date). It backs the scheduler's daily
// dedup so the rotation fires at most once per day even though the worker ticks
// every 60s throughout the configured hour.
func (s *BackupService) SchedulerTestRanToday() (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM restore_tests
		 WHERE triggered_by = 'scheduler' AND DATE(created_at) = CURDATE()`).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// rpoStatus classifies a backup age against the target RPO threshold.
func rpoStatus(age time.Duration, rpoHours int) string {
	if rpoHours <= 0 {
		return "ok"
	}
	h := age.Hours()
	switch {
	case h <= float64(rpoHours):
		return "ok"
	case h <= float64(rpoHours)*2:
		return "warn"
	default:
		return "breach"
	}
}

// humanSize formats a byte count as a human-readable string.
func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// humanAge formats a duration as a compact age (min / h / j).
func humanAge(d time.Duration) string {
	h := d.Hours()
	switch {
	case h < 1:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case h < 48:
		return fmt.Sprintf("%d h", int(h))
	default:
		return fmt.Sprintf("%d j", int(h/24))
	}
}
