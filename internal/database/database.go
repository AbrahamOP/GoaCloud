package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"goacore/internal/config"
)

// Connect opens the database connection with retry logic.
func Connect(cfg *config.Config) (*sql.DB, error) {
	mysqlCfg := mysql.Config{
		User:                 cfg.DBUser,
		Passwd:               cfg.DBPass,
		Net:                  "tcp",
		Addr:                 cfg.DBHost,
		DBName:               cfg.DBName,
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	var db *sql.DB
	var err error
	for i := 0; i < 30; i++ {
		db, err = sql.Open("mysql", mysqlCfg.FormatDSN())
		if err == nil {
			err = db.Ping()
			if err == nil {
				break
			}
		}
		slog.Info("Waiting for database...", "attempt", i+1)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// Migrate runs auto-migrations to ensure all required tables and columns exist.
// It returns an error as soon as a statement fails for a reason other than "the
// schema is already in that state": a database that could not be brought to the
// expected shape (missing ALTER privilege, lock timeout, full disk…) must abort
// the startup instead of serving 500s later on.
func Migrate(db *sql.DB) error {
	coreTables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS apps (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			description TEXT,
			external_url VARCHAR(255) NOT NULL,
			icon_url VARCHAR(255),
			category VARCHAR(50) DEFAULT 'General',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS vm_cache (
			vmid INT PRIMARY KEY,
			name VARCHAR(255),
			ip_address VARCHAR(45),
			vm_type VARCHAR(10),
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			key_type VARCHAR(20) DEFAULT 'RSA',
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			fingerprint VARCHAR(100),
			associated_vms TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS soar_config (
			id INT PRIMARY KEY DEFAULT 1,
			alert_status BOOLEAN DEFAULT TRUE,
			alert_ssh BOOLEAN DEFAULT TRUE,
			alert_sudo BOOLEAN DEFAULT TRUE,
			alert_fim BOOLEAN DEFAULT TRUE,
			alert_packages BOOLEAN DEFAULT TRUE
		)`,
		`CREATE TABLE IF NOT EXISTS soar_state (
			k VARCHAR(64) PRIMARY KEY,
			v TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS soar_alert_dedup (
			alert_key VARCHAR(191) PRIMARY KEY,
			seen_at BIGINT NOT NULL,
			INDEX idx_seen_at (seen_at)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT,
			username VARCHAR(255),
			action VARCHAR(255),
			details TEXT,
			ip_address VARCHAR(255),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_created_at (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_host_keys (
			ip VARCHAR(255) PRIMARY KEY,
			host_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS metrics_history (
			id INT AUTO_INCREMENT PRIMARY KEY,
			cpu INT NOT NULL,
			ram INT NOT NULL,
			storage INT NOT NULL,
			recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_recorded_at (recorded_at)
		)`,
		`CREATE TABLE IF NOT EXISTS favorites (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			item_type VARCHAR(20) NOT NULL,
			item_id VARCHAR(50) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uk_fav (user_id, item_type, item_id)
		)`,
		`CREATE TABLE IF NOT EXISTS ansible_schedules (
			id INT AUTO_INCREMENT PRIMARY KEY,
			playbook VARCHAR(255) NOT NULL,
			vmid INT NOT NULL,
			key_id INT NOT NULL,
			interval_minutes INT NOT NULL,
			remote_user VARCHAR(50) NOT NULL DEFAULT 'root',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			next_run DATETIME NOT NULL,
			last_run DATETIME NULL,
			last_status VARCHAR(20) DEFAULT 'pending',
			last_output TEXT,
			created_by VARCHAR(50),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS backup_targets (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			target_type VARCHAR(10) NOT NULL DEFAULT 'qemu',
			source_ref VARCHAR(50) NOT NULL,
			storage VARCHAR(100) NOT NULL DEFAULT 'local',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			rpo_hours INT NOT NULL DEFAULT 24,
			schedule_cron VARCHAR(100) NOT NULL DEFAULT '',
			retention_count INT NOT NULL DEFAULT 3,
			healthcheck_type VARCHAR(20) NOT NULL DEFAULT 'none',
			healthcheck_target VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			-- One row per VMID, whatever its type: the same source_ref typed 'qemu'
			-- by hand and rediscovered as 'lxc' must collide instead of creating a
			-- second target that double-counts in the KPIs (migration 3 moves
			-- pre-existing databases from the old (target_type, source_ref) key).
			UNIQUE KEY uk_target_source (source_ref)
		)`,
		`CREATE TABLE IF NOT EXISTS backup_runs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			target_id INT NOT NULL,
			backup_type VARCHAR(20) NOT NULL DEFAULT 'vzdump',
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			started_at DATETIME NULL,
			completed_at DATETIME NULL,
			size_bytes BIGINT NOT NULL DEFAULT 0,
			archive_path VARCHAR(512) NOT NULL DEFAULT '',
			checksum VARCHAR(128) NOT NULL DEFAULT '',
			source VARCHAR(20) NOT NULL DEFAULT 'manual',
			message TEXT,
			created_by VARCHAR(50),
			upid VARCHAR(255) NOT NULL DEFAULT '',
			destination VARCHAR(20) NOT NULL DEFAULT 'local',
			remote VARCHAR(64) NOT NULL DEFAULT '',
			push_status VARCHAR(20) NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_bruns_target (target_id),
			INDEX idx_bruns_status (status),
			INDEX idx_bruns_created (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS backup_settings (
			id INT PRIMARY KEY DEFAULT 1,
			rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			rotation_hour INT NOT NULL DEFAULT 4
		)`,
		`CREATE TABLE IF NOT EXISTS restore_tests (
			id INT AUTO_INCREMENT PRIMARY KEY,
			target_id INT NOT NULL,
			run_id INT NULL,
			level VARCHAR(4) NOT NULL DEFAULT 'N1',
			verdict VARCHAR(20) NOT NULL DEFAULT 'pending',
			sandbox_vmid INT NOT NULL DEFAULT 0,
			rto_seconds INT NOT NULL DEFAULT 0,
			started_at DATETIME NULL,
			completed_at DATETIME NULL,
			logs TEXT,
			triggered_by VARCHAR(20) NOT NULL DEFAULT 'manual',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_rtests_target (target_id),
			INDEX idx_rtests_verdict (verdict),
			INDEX idx_rtests_created (created_at)
		)`,
		// connections holds per-service infrastructure credentials, configured
		// in-app (onboarding) instead of (or on top of) environment variables.
		// One row per service ('proxmox' at Jalon 1; 'wazuh'/'ai'/'discord' later
		// are simply more rows — no schema change). Only the secret column is
		// encrypted (AES-256-GCM, same key as SSH keys); url/node/token_id and the
		// non-sensitive extra_json fields stay in clear. The ABSENCE of a row is the
		// "not configured" signal — there is deliberately NO INSERT IGNORE here.
		`CREATE TABLE IF NOT EXISTS connections (
			service        VARCHAR(32)  NOT NULL PRIMARY KEY,
			enabled        TINYINT(1)   NOT NULL DEFAULT 1,
			url            VARCHAR(512) NOT NULL DEFAULT '',
			node           VARCHAR(128) NOT NULL DEFAULT '',
			token_id       VARCHAR(256) NOT NULL DEFAULT '',
			secret_enc     TEXT         NOT NULL,
			extra_json     JSON         NULL,
			configured     TINYINT(1)   NOT NULL DEFAULT 0,
			status         VARCHAR(16)  NOT NULL DEFAULT 'unknown',
			last_tested_at DATETIME     NULL,
			last_error     VARCHAR(512) NOT NULL DEFAULT '',
			source         VARCHAR(8)   NOT NULL DEFAULT 'db',
			updated_by     VARCHAR(128) NOT NULL DEFAULT '',
			updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range coreTables {
		if _, err := db.Exec(stmt); err != nil {
			slog.Error("DB create table", "error", err)
			return fmt.Errorf("create table: %w", err)
		}
	}

	// Ensure soar_config default row
	if _, err := db.Exec(`INSERT IGNORE INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages) VALUES (1, TRUE, TRUE, TRUE, TRUE, TRUE)`); err != nil {
		return fmt.Errorf("seed soar_config: %w", err)
	}

	// Ensure the single backup_settings row (id=1) always exists so the worker can
	// read rotation config at runtime without a NULL-row special case.
	if _, err := db.Exec(`INSERT IGNORE INTO backup_settings (id) VALUES (1)`); err != nil {
		return fmt.Errorf("seed backup_settings: %w", err)
	}

	if err := runVersionedMigrations(db); err != nil {
		return err
	}

	// Warn (non-fatal) if any existing schedule still targets the 'root' SSH user:
	// with PermitRootLogin=no on the fleet, those schedules fail UNREACHABLE. We do
	// NOT rewrite them blindly (no safe nominative user to pick) — the operator must
	// edit them to a non-root user, optionally enabling become (sudo) for escalation.
	var rootSchedules int
	if err := db.QueryRow("SELECT COUNT(*) FROM ansible_schedules WHERE remote_user = 'root'").Scan(&rootSchedules); err == nil && rootSchedules > 0 {
		slog.Warn("Ansible schedules still target the 'root' SSH user; these will fail if root SSH login is disabled (PermitRootLogin=no) — recreate them with a non-root user and enable 'become' for sudo escalation",
			"count", rootSchedules)
	}

	return nil
}

// baselineColumns is migration 1: the column-level changes that shipped before
// this package had any versioning. Every statement is ADDITIVE and idempotent,
// so replaying it on a database that already has them is a no-op (the server
// answers "duplicate column", which is swallowed at Debug level); that is what
// makes the first run on an existing installation safe.
var baselineColumns = []string{
	"ALTER TABLE users ADD COLUMN email VARCHAR(255) NOT NULL DEFAULT ''",
	"ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'Viewer'",
	"ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE",
	"ALTER TABLE users ADD COLUMN mfa_secret TEXT",
	"ALTER TABLE users ADD COLUMN github_url VARCHAR(500) NOT NULL DEFAULT ''",
	// session_epoch is the session-revocation counter. AuthMiddleware validates the
	// epoch carried by the cookie against this column on every request, so bumping it
	// (password change, MFA disable/reset, "déconnecter toutes mes sessions") kills
	// every cookie minted before the bump — the CookieStore itself keeps no server
	// state. ADDITIVE and idempotent: existing rows get 0, which is exactly the value
	// pre-upgrade cookies carry, so a deploy does NOT log the whole fleet out.
	"ALTER TABLE users ADD COLUMN session_epoch INT NOT NULL DEFAULT 0",
	"ALTER TABLE ssh_keys ADD COLUMN associated_vms TEXT",
	"ALTER TABLE apps ADD COLUMN health_status VARCHAR(20) NOT NULL DEFAULT 'unknown'",
	"ALTER TABLE apps ADD COLUMN health_response_ms INT NOT NULL DEFAULT 0",
	"ALTER TABLE apps ADD COLUMN health_last_check DATETIME NULL",
	"ALTER TABLE apps ADD COLUMN is_pinned BOOLEAN NOT NULL DEFAULT FALSE",
	"ALTER TABLE apps ADD COLUMN position INT NOT NULL DEFAULT 0",
	"ALTER TABLE apps MODIFY COLUMN icon_url MEDIUMTEXT",
	"ALTER TABLE backup_runs ADD COLUMN upid VARCHAR(255) NOT NULL DEFAULT ''",
	"ALTER TABLE backup_runs ADD COLUMN destination VARCHAR(20) NOT NULL DEFAULT 'local'",
	"ALTER TABLE backup_runs ADD COLUMN remote VARCHAR(64) NOT NULL DEFAULT ''",
	"ALTER TABLE backup_runs ADD COLUMN push_status VARCHAR(20) NOT NULL DEFAULT ''",
	// Vérification automatique d'intégrité après chaque sauvegarde cloud (N1).
	"ALTER TABLE backup_settings ADD COLUMN auto_verify_enabled BOOLEAN NOT NULL DEFAULT FALSE",
	// Ansible scheduler hardening (Lot C — non-root). These are ADDITIVE/SAFE and
	// idempotent: they NEVER drop the column or rewrite existing rows.
	//   - become: opt-in privilege escalation (sudo) for non-root remote users.
	//     Defaults to FALSE so existing rows keep their current behaviour.
	//   - remote_user DROP DEFAULT: kills the unsafe DEFAULT 'root' (root SSH is
	//     disabled everywhere — PermitRootLogin=no — so a new schedule must never
	//     silently fall back to 'root'). MySQL 8 syntax: ALTER COLUMN ... DROP
	//     DEFAULT. The column stays NOT NULL: the application now REQUIRES an
	//     explicit remote_user at creation, so no INSERT relies on the default.
	//     Existing 'root' rows are LEFT UNTOUCHED on purpose (see the WARN at the
	//     end of Migrate).
	//   - ADD remote_user (idempotent): a PRE-jalon prod table can pre-date this
	//     column (it only ever lived in CREATE TABLE, never as an ALTER), so the
	//     scheduler hit "Unknown column 'remote_user'". Add it BEFORE dropping its
	//     default; a Duplicate-column error (fresh install where CREATE already made
	//     it) is ignored by the loop. Legacy rows get '' and are flagged at run time
	//     (remote_user required) instead of crashing.
	"ALTER TABLE ansible_schedules ADD COLUMN remote_user VARCHAR(50) NOT NULL DEFAULT ''",
	"ALTER TABLE ansible_schedules ADD COLUMN become BOOLEAN NOT NULL DEFAULT FALSE",
	"ALTER TABLE ansible_schedules ALTER COLUMN remote_user DROP DEFAULT",
}

// legacyTargetIndex is the pre-versioning unique key of backup_targets, on
// (target_type, source_ref); targetSourceIndex is the one that replaces it.
const (
	legacyTargetIndex = "uk_target"
	targetSourceIndex = "uk_target_source"
)

// errMigrationDeferred is returned by a migration that cannot run yet because the
// data is not in a state where it would be safe (today: duplicate backup targets
// blocking a UNIQUE key). It is NOT a failure — the startup continues — but the
// version is deliberately left unrecorded so the step is retried at the next boot,
// once the operator has cleaned up.
var errMigrationDeferred = errors.New("migration deferred")

// migration is one versioned schema step. A version is applied at most once and
// then recorded in schema_migrations. An already-released version must never be
// edited: fix a mistake by adding a new, higher one.
type migration struct {
	version int
	name    string
	stmts   []string            // plain DDL, replayed idempotently
	fn      func(*sql.DB) error // used instead of stmts when the step needs logic
}

// schemaMigrations is the ordered list of versioned schema steps. Version 1 is the
// baseline: everything that existed before this table was introduced. On a database
// that predates the versioning, the baseline is replayed once (harmless, it is only
// idempotent ALTERs) and recorded, so later boots skip it entirely.
var schemaMigrations = []migration{
	{version: 1, name: "baseline_columns", stmts: baselineColumns},
	{
		version: 2,
		name:    "audit_logs_created_at_index",
		fn: func(db *sql.DB) error {
			// audit_logs is read time-ordered (and will be purged by date), which
			// is a full scan without this index once the table grows.
			return addIndexIfMissing(db, "audit_logs", "idx_created_at",
				"ALTER TABLE audit_logs ADD INDEX idx_created_at (created_at)")
		},
	},
	{
		version: 3,
		name:    "backup_targets_unique_source_ref",
		fn:      migrateBackupTargetsUniqueKey,
	},
}

// runVersionedMigrations applies every step not yet recorded in schema_migrations,
// in version order, and records each success.
func runVersionedMigrations(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INT NOT NULL PRIMARY KEY,
		name VARCHAR(191) NOT NULL,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(db)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}

	for _, m := range schemaMigrations {
		if applied[m.version] {
			slog.Debug("Schema migration already applied", "version", m.version, "name", m.name)
			continue
		}
		if err := m.apply(db); err != nil {
			if errors.Is(err, errMigrationDeferred) {
				// Not recorded on purpose: it will be retried at the next boot.
				slog.Warn("Schema migration deferred, will be retried at next startup",
					"version", m.version, "name", m.name)
				continue
			}
			slog.Error("Schema migration failed", "version", m.version, "name", m.name, "error", err)
			return fmt.Errorf("schema migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := db.Exec(`INSERT IGNORE INTO schema_migrations (version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
			return fmt.Errorf("record schema migration %d (%s): %w", m.version, m.name, err)
		}
		slog.Info("Schema migration applied", "version", m.version, "name", m.name)
	}
	return nil
}

func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// apply runs the step. Only "the schema is already in that state" errors are
// swallowed (and at Debug level, not Info): anything else is returned so the
// caller can abort the startup.
func (m migration) apply(db *sql.DB) error {
	if m.fn != nil {
		return m.fn(db)
	}
	for _, stmt := range m.stmts {
		if _, err := db.Exec(stmt); err != nil {
			if isAlreadyApplied(err) {
				slog.Debug("Schema statement already applied", "version", m.version, "sql", stmt)
				continue
			}
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// MySQL server error codes meaning "the object is already in the requested
// state". These are the only errors a migration may ignore: everything else
// (1142 missing ALTER privilege, 1205 lock timeout, 1021 disk full…) is a real
// failure. We match on the code and never on the message text, which is
// localised and changes between server versions.
const (
	erTableExists        = 1050 // ER_TABLE_EXISTS_ERROR
	erDupFieldName       = 1060 // ER_DUP_FIELDNAME — column already there
	erDupKeyName         = 1061 // ER_DUP_KEYNAME — index already there
	erCantDropFieldOrKey = 1091 // ER_CANT_DROP_FIELD_OR_KEY — dropping something absent
)

func isAlreadyApplied(err error) bool {
	var myErr *mysql.MySQLError
	if !errors.As(err, &myErr) {
		return false
	}
	switch myErr.Number {
	case erTableExists, erDupFieldName, erDupKeyName, erCantDropFieldOrKey:
		return true
	}
	return false
}

// indexExists asks information_schema whether an index is present on a table of
// the current database — a positive check, as opposed to guessing from the text
// of an error.
func indexExists(db *sql.DB, table, index string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.statistics
		WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`, table, index).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func addIndexIfMissing(db *sql.DB, table, index, stmt string) error {
	exists, err := indexExists(db, table, index)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := db.Exec(stmt); err != nil && !isAlreadyApplied(err) {
		return fmt.Errorf("%s: %w", stmt, err)
	}
	return nil
}

// migrateBackupTargetsUniqueKey moves backup_targets from the old unique key on
// (target_type, source_ref) to a unique key on source_ref alone: a VMID is a
// single machine, so typing it 'qemu' by hand and rediscovering it as 'lxc' used
// to create two rows that double-count in the KPIs.
//
// The step is potentially destructive (a UNIQUE key on an already-duplicated
// column fails, and MySQL offers to fix that by deleting rows), so it never
// deletes anything: if duplicates exist, it logs the offending VMIDs, leaves the
// legacy key in place and defers itself. The operator merges or removes the
// duplicate targets, and the next startup applies the key.
func migrateBackupTargetsUniqueKey(db *sql.DB) error {
	newIdx, err := indexExists(db, "backup_targets", targetSourceIndex)
	if err != nil {
		return err
	}
	oldIdx, err := indexExists(db, "backup_targets", legacyTargetIndex)
	if err != nil {
		return err
	}

	var duplicates []string
	if !newIdx {
		if duplicates, err = duplicateSourceRefs(db); err != nil {
			return err
		}
	}

	stmts, deferred := uniqueTargetPlan(newIdx, oldIdx, duplicates)
	if deferred {
		slog.Warn("backup_targets holds several targets for the same VMID — the unique key cannot be created without losing a row; merge or delete the duplicates by hand, they are counted twice in the backup KPIs",
			"vmids", strings.Join(duplicates, ", "))
		return errMigrationDeferred
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil && !isAlreadyApplied(err) {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// uniqueTargetPlan decides, from the state of the two indexes and the duplicates
// found, which statements bring backup_targets to its target shape. Kept pure so
// the decision (especially "refuse rather than lose a row") is unit-testable
// without a server.
func uniqueTargetPlan(newIndexExists, legacyIndexExists bool, duplicates []string) (stmts []string, deferred bool) {
	dropLegacy := "ALTER TABLE backup_targets DROP INDEX " + legacyTargetIndex
	if newIndexExists {
		// Fresh install (CREATE TABLE already declares it) or interrupted run:
		// only the legacy key may be left to clean up.
		if legacyIndexExists {
			return []string{dropLegacy}, false
		}
		return nil, false
	}
	if len(duplicates) > 0 {
		return nil, true
	}
	stmts = []string{"ALTER TABLE backup_targets ADD UNIQUE KEY " + targetSourceIndex + " (source_ref)"}
	if legacyIndexExists {
		// Dropped only once the new key is in place, so the table is never left
		// without a uniqueness guarantee.
		stmts = append(stmts, dropLegacy)
	}
	return stmts, false
}

// duplicateSourceRefs returns the source_ref values carried by more than one
// backup target.
func duplicateSourceRefs(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT source_ref FROM backup_targets
		GROUP BY source_ref HAVING COUNT(*) > 1 ORDER BY source_ref`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}
