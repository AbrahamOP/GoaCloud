package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// isAlreadyApplied is what tells "this migration was already applied" apart from
// "this migration failed". Getting it wrong is how a broken schema used to boot
// successfully, so the classification is pinned here.
func TestIsAlreadyApplied(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"duplicate column", &mysql.MySQLError{Number: erDupFieldName, Message: "Duplicate column name 'email'"}, true},
		{"duplicate key", &mysql.MySQLError{Number: erDupKeyName, Message: "Duplicate key name 'uk_target_source'"}, true},
		{"table exists", &mysql.MySQLError{Number: erTableExists, Message: "Table 'users' already exists"}, true},
		{"drop of an absent key", &mysql.MySQLError{Number: erCantDropFieldOrKey, Message: "Can't DROP 'uk_target'"}, true},
		{"wrapped duplicate column", fmt.Errorf("ALTER…: %w", &mysql.MySQLError{Number: erDupFieldName}), true},

		// The whole point: these must NOT be swallowed.
		{"missing ALTER privilege", &mysql.MySQLError{Number: 1142, Message: "ALTER command denied to user 'goacore'"}, false},
		{"lock wait timeout", &mysql.MySQLError{Number: 1205, Message: "Lock wait timeout exceeded"}, false},
		{"disk full", &mysql.MySQLError{Number: 1021, Message: "Disk full"}, false},
		{"unknown table", &mysql.MySQLError{Number: 1146, Message: "Table 'goacore.apps' doesn't exist"}, false},
		{"connection lost", errors.New("invalid connection"), false},
		// The old code keyed on the substring "exists", which swallowed this one.
		{"missing column mentioning exists", errors.New("Unknown column 'exists' in 'field list'"), false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlreadyApplied(tc.err); got != tc.want {
				t.Fatalf("isAlreadyApplied(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// The migration list is an append-only ledger: duplicate or unordered versions
// would silently skip a step (or replay one) on a customer database.
func TestSchemaMigrationsAreWellFormed(t *testing.T) {
	seen := make(map[int]bool)
	last := 0
	for _, m := range schemaMigrations {
		if m.version <= 0 {
			t.Fatalf("migration %q: version must be >= 1, got %d", m.name, m.version)
		}
		if seen[m.version] {
			t.Fatalf("version %d is used twice", m.version)
		}
		seen[m.version] = true
		if m.version <= last {
			t.Fatalf("migration %d (%s) is out of order (previous was %d)", m.version, m.name, last)
		}
		last = m.version
		if m.name == "" {
			t.Fatalf("migration %d has no name", m.version)
		}
		if (len(m.stmts) == 0) == (m.fn == nil) {
			t.Fatalf("migration %d (%s) must carry either stmts or fn, not both/neither", m.version, m.name)
		}
	}
}

// Auto-migration runs unattended at startup: nothing in the baseline may destroy
// data. Guards against a careless append to the list.
func TestBaselineColumnsAreAdditive(t *testing.T) {
	forbidden := []string{"DROP COLUMN", "DROP TABLE", "DROP INDEX", "TRUNCATE", "DELETE FROM"}
	for _, stmt := range baselineColumns {
		upper := strings.ToUpper(stmt)
		for _, bad := range forbidden {
			if strings.Contains(upper, bad) {
				t.Fatalf("destructive statement in the baseline: %q contains %q", stmt, bad)
			}
		}
	}
}

func TestUniqueTargetPlan(t *testing.T) {
	tests := []struct {
		name         string
		newIdx       bool
		legacyIdx    bool
		duplicates   []string
		wantStmts    []string
		wantDeferred bool
	}{
		{
			name:      "legacy database without duplicates: new key added, old one dropped",
			legacyIdx: true,
			wantStmts: []string{
				"ALTER TABLE backup_targets ADD UNIQUE KEY uk_target_source (source_ref)",
				"ALTER TABLE backup_targets DROP INDEX uk_target",
			},
		},
		{
			name:      "no index at all: only the new key is created",
			wantStmts: []string{"ALTER TABLE backup_targets ADD UNIQUE KEY uk_target_source (source_ref)"},
		},
		{
			name:         "duplicate VMIDs: deferred, nothing is executed",
			legacyIdx:    true,
			duplicates:   []string{"110", "113"},
			wantDeferred: true,
		},
		{
			name:      "fresh install: nothing to do",
			newIdx:    true,
			wantStmts: nil,
		},
		{
			name:      "interrupted run: the leftover legacy key is dropped",
			newIdx:    true,
			legacyIdx: true,
			wantStmts: []string{"ALTER TABLE backup_targets DROP INDEX uk_target"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmts, deferred := uniqueTargetPlan(tc.newIdx, tc.legacyIdx, tc.duplicates)
			if deferred != tc.wantDeferred {
				t.Fatalf("deferred = %v, want %v", deferred, tc.wantDeferred)
			}
			if deferred && len(stmts) != 0 {
				t.Fatalf("a deferred migration must execute nothing, got %v", stmts)
			}
			if len(stmts) != len(tc.wantStmts) {
				t.Fatalf("stmts = %v, want %v", stmts, tc.wantStmts)
			}
			for i := range stmts {
				if stmts[i] != tc.wantStmts[i] {
					t.Fatalf("stmts[%d] = %q, want %q", i, stmts[i], tc.wantStmts[i])
				}
			}
			// The new key must always be in place before the old one is dropped.
			for i, s := range stmts {
				if strings.Contains(s, "DROP INDEX "+legacyTargetIndex) && i == 0 && !tc.newIdx {
					t.Fatalf("legacy key dropped before the new one exists: %v", stmts)
				}
			}
		})
	}
}

// --- Integration (real MySQL) --------------------------------------------------
//
// Skipped unless GOACORE_TEST_DSN points at a THROWAWAY database: these tests
// create, alter and drop the application tables. Same convention as the SOAR
// persistence tests (SOAR_TEST_DSN).

func integrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("GOACORE_TEST_DSN")
	if dsn == "" {
		t.Skip("GOACORE_TEST_DSN not set — MySQL integration test skipped")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	dropAllTables(t, db)
	t.Cleanup(func() { dropAllTables(t, db) })
	return db
}

func dropAllTables(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	for _, name := range tables {
		if _, err := db.Exec("DROP TABLE IF EXISTS `" + name + "`"); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
	}
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// A fresh installation must end up fully versioned, and a second run must be a
// pure no-op (no replay, no error).
func TestMigrateFreshThenIdempotent(t *testing.T) {
	db := integrationDB(t)

	if err := Migrate(db); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	for _, m := range schemaMigrations {
		if countRows(t, db, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version) != 1 {
			t.Fatalf("migration %d (%s) not recorded", m.version, m.name)
		}
	}
	if ok, err := indexExists(db, "audit_logs", "idx_created_at"); err != nil || !ok {
		t.Fatalf("idx_created_at missing on audit_logs (err=%v)", err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM schema_migrations`); n != len(schemaMigrations) {
		t.Fatalf("schema_migrations holds %d rows, want %d", n, len(schemaMigrations))
	}
}

// Upgrade path of an existing customer database: pre-versioning schema, legacy
// unique key, and two targets for the same VMID. Migrate must not lose a row, must
// leave the offending migration unrecorded, and must apply it once the operator
// has deduplicated.
func TestMigrateLegacyDatabaseWithDuplicateTargets(t *testing.T) {
	db := integrationDB(t)

	// A database as it was before this package had versioning: old unique key,
	// and columns that the baseline will have to add.
	legacy := []string{
		`CREATE TABLE backup_targets (
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
			UNIQUE KEY uk_target (target_type, source_ref)
		)`,
		`CREATE TABLE users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO backup_targets (name, target_type, source_ref) VALUES ('CT110 (manual)', 'qemu', '110')`,
		`INSERT INTO backup_targets (name, target_type, source_ref) VALUES ('CT110 (discovered)', 'lxc', '110')`,
	}
	for _, q := range legacy {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("legacy schema %q: %v", q, err)
		}
	}

	// Startup must succeed: a duplicate is an operator problem, not a reason to
	// refuse to boot.
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate on legacy database: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM backup_targets`); n != 2 {
		t.Fatalf("Migrate lost data: %d rows left, want 2", n)
	}
	if countRows(t, db, `SELECT COUNT(*) FROM schema_migrations WHERE version = 1`) != 1 {
		t.Fatal("the baseline should have been applied and recorded")
	}
	if countRows(t, db, `SELECT COUNT(*) FROM schema_migrations WHERE version = 3`) != 0 {
		t.Fatal("the deferred migration must NOT be recorded, otherwise it is never retried")
	}
	if ok, _ := indexExists(db, "backup_targets", legacyTargetIndex); !ok {
		t.Fatal("the legacy key must stay in place as long as the new one cannot be created")
	}
	// The baseline was replayed on an existing table: additive columns are there.
	if countRows(t, db, `SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'session_epoch'`) != 1 {
		t.Fatal("baseline column users.session_epoch missing")
	}

	// The operator deduplicates, the next startup finishes the job.
	if _, err := db.Exec(`DELETE FROM backup_targets WHERE name = 'CT110 (discovered)'`); err != nil {
		t.Fatalf("dedup: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate after dedup: %v", err)
	}
	if countRows(t, db, `SELECT COUNT(*) FROM schema_migrations WHERE version = 3`) != 1 {
		t.Fatal("migration 3 should have been applied after dedup")
	}
	if ok, _ := indexExists(db, "backup_targets", targetSourceIndex); !ok {
		t.Fatal("unique key on source_ref missing")
	}
	if ok, _ := indexExists(db, "backup_targets", legacyTargetIndex); ok {
		t.Fatal("legacy key uk_target should have been dropped")
	}

	// The constraint now actually blocks the double-count.
	if _, err := db.Exec(`INSERT INTO backup_targets (name, target_type, source_ref) VALUES ('CT110 again', 'lxc', '110')`); err == nil {
		t.Fatal("the same VMID could be inserted twice despite the unique key")
	}
}
