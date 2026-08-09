package services

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Rotation des archives : tests de non-régression du seul endroit de GoaCore qui
// DÉTRUIT une donnée du client.
//
// L'ancien code purgeait dès qu'une sauvegarde réussissait, en lisant un
// retention_count qui vaut 3 par défaut dans le schéma déjà déployé et que les
// cibles auto-découvertes n'ont jamais renseigné : sur un parc existant, un clic
// sur « Sauvegarder » supprimait rétroactivement des archives que personne
// n'avait condamnées (y compris celles d'un job vzdump natif du client).
//
// Comme le reste du dépôt (cf. authfakedb_test.go, router_rbac_test.go), on se
// donne un mini-pilote database/sql en mémoire plutôt qu'une dépendance externe.
// ─────────────────────────────────────────────────────────────────────────────

// retFixture est la ligne backup_targets vue par le faux pilote, plus le journal
// des requêtes effectivement émises.
type retFixture struct {
	mu      sync.Mutex
	enabled bool
	count   int64
	// missingColumn simule une base dont la migration retention_enabled n'a pas
	// encore tourné : la requête échoue.
	missingColumn bool
	queries       []string
}

func (f *retFixture) record(q string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
}

func (f *retFixture) executed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

var (
	retFixturesMu sync.Mutex
	retFixtures   = map[string]*retFixture{}
	retRegOnce    sync.Once
)

type retDriver struct{}

func (retDriver) Open(dsn string) (driver.Conn, error) {
	retFixturesMu.Lock()
	defer retFixturesMu.Unlock()
	f, ok := retFixtures[dsn]
	if !ok {
		return nil, errors.New("unknown fixture")
	}
	return retConn{f: f}, nil
}

type retConn struct{ f *retFixture }

func (c retConn) Prepare(q string) (driver.Stmt, error) {
	return retStmt{f: c.f, query: strings.ToLower(strings.Join(strings.Fields(q), " "))}, nil
}
func (retConn) Close() error              { return nil }
func (retConn) Begin() (driver.Tx, error) { return nil, io.EOF }

type retStmt struct {
	f     *retFixture
	query string
}

func (retStmt) Close() error  { return nil }
func (retStmt) NumInput() int { return -1 }

func (s retStmt) Exec([]driver.Value) (driver.Result, error) {
	s.f.record(s.query)
	return driver.RowsAffected(1), nil
}

func (s retStmt) Query([]driver.Value) (driver.Rows, error) {
	s.f.record(s.query)
	if strings.Contains(s.query, "select retention_enabled, retention_count from backup_targets") {
		if s.f.missingColumn {
			return nil, errors.New("Error 1054: Unknown column 'retention_enabled' in 'field list'")
		}
		s.f.mu.Lock()
		enabled, count := s.f.enabled, s.f.count
		s.f.mu.Unlock()
		return &retRows{
			cols: []string{"retention_enabled", "retention_count"},
			vals: [][]driver.Value{{enabled, count}},
		}, nil
	}
	return &retRows{}, nil
}

type retRows struct {
	cols []string
	vals [][]driver.Value
	pos  int
}

func (r *retRows) Columns() []string { return r.cols }
func (r *retRows) Close() error      { return nil }
func (r *retRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.pos])
	r.pos++
	return nil
}

// openRetentionDB donne un *sql.DB adossé à la fixture fournie.
func openRetentionDB(t *testing.T, dsn string, f *retFixture) *sql.DB {
	t.Helper()
	retRegOnce.Do(func() { sql.Register("retentionfake", retDriver{}) })
	retFixturesMu.Lock()
	retFixtures[dsn] = f
	retFixturesMu.Unlock()
	db, err := sql.Open("retentionfake", dsn)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		retFixturesMu.Lock()
		delete(retFixtures, dsn)
		retFixturesMu.Unlock()
	})
	return db
}

// TestShouldApplyRetention fixe l'invariant « on ne supprime rien tant qu'on n'a pas
// une archive LOCALE fraîche de plus ». destination=remote pousse hors site puis
// supprime la copie locale : la sauvegarde ne laisse donc aucune archive locale et ne
// peut servir de caution à une purge.
func TestShouldApplyRetention(t *testing.T) {
	cases := []struct {
		name        string
		destination string
		archive     string
		want        bool
	}{
		{"local avec archive fraîche", DestinationLocal, "local:backup/vzdump-qemu-105.zst", true},
		{"both conserve la copie locale", DestinationBoth, "local:backup/vzdump-qemu-105.zst", true},
		{"remote supprime la copie locale", DestinationRemote, "local:backup/vzdump-qemu-105.zst", false},
		{"remote sans archive", DestinationRemote, "", false},
		{"local sans archive retrouvée", DestinationLocal, "", false},
		{"local archive vide (espaces)", DestinationLocal, "   ", false},
		{"both sans archive retrouvée", DestinationBoth, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldApplyRetention(tc.destination, tc.archive); got != tc.want {
				t.Fatalf("shouldApplyRetention(%q, %q) = %v, attendu %v",
					tc.destination, tc.archive, got, tc.want)
			}
		})
	}
}

// TestRetentionSettingFor : le compteur ne vaut QUE si l'interrupteur est armé, et
// toute anomalie se lit « rotation désactivée » (jamais « ne rien garder »).
func TestRetentionSettingFor(t *testing.T) {
	cases := []struct {
		name    string
		fixture *retFixture
		want    retentionSetting
	}{
		{
			name:    "installation existante : compteur hérité du défaut, interrupteur au repos",
			fixture: &retFixture{enabled: false, count: 3},
			want:    retentionSetting{},
		},
		{
			name:    "activation délibérée",
			fixture: &retFixture{enabled: true, count: 5},
			want:    retentionSetting{Enabled: true, Keep: 5},
		},
		{
			name:    "activée mais compteur nul : on ne supprime rien",
			fixture: &retFixture{enabled: true, count: 0},
			want:    retentionSetting{},
		},
		{
			name:    "migration pas encore passée : colonne absente",
			fixture: &retFixture{missingColumn: true},
			want:    retentionSetting{},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openRetentionDB(t, tc.name+string(rune('a'+i)), tc.fixture)
			s := &BackupService{db: db}
			if got := s.retentionSettingFor(7); got != tc.want {
				t.Fatalf("retentionSettingFor = %+v, attendu %+v", got, tc.want)
			}
		})
	}
}

// TestApplyRetention_ExistingInstallDeletesNothing est LE test du défaut : sur une
// installation existante (retention_count = 3 hérité du schéma, interrupteur jamais
// armé), une sauvegarde réussie ne doit provoquer AUCUNE suppression.
//
// Le service est volontairement construit sans client Proxmox ni store de config :
// atteindre le listage ou la suppression d'archives ferait paniquer le test. Une
// exécution silencieuse prouve que la rotation n'a jamais démarré.
func TestApplyRetention_ExistingInstallDeletesNothing(t *testing.T) {
	f := &retFixture{enabled: false, count: 3}
	db := openRetentionDB(t, "existing-install", f)
	s := &BackupService{db: db}

	s.applyRetention(7, 105, "local", DestinationLocal, "local:backup/vzdump-qemu-105.zst", "alice")

	for _, q := range f.executed() {
		if strings.Contains(q, "delete") || strings.Contains(q, "insert into audit_logs") {
			t.Fatalf("aucune suppression ne devait avoir lieu, requête émise : %s", q)
		}
	}
}

// TestApplyRetention_RemoteDestinationNeverPurges : pour destination=remote, la copie
// locale vient d'être supprimée par rclone. La purge locale ne doit pas se déclencher
// sur la foi d'une sauvegarde qui n'a laissé aucune archive locale — même si
// l'exploitant a armé la rotation.
func TestApplyRetention_RemoteDestinationNeverPurges(t *testing.T) {
	f := &retFixture{enabled: true, count: 3}
	db := openRetentionDB(t, "remote-destination", f)
	s := &BackupService{db: db}

	// Rotation armée + Proxmox absent : si la purge démarrait, le test paniquerait.
	s.applyRetention(7, 105, "local", DestinationRemote, "gdrive:backups/vzdump-qemu-105.zst", "alice")

	for _, q := range f.executed() {
		if strings.Contains(q, "select retention_enabled") {
			t.Fatal("le réglage ne devrait même pas être lu : la sauvegarde n'a laissé aucune archive locale")
		}
	}
}

// TestUpdateTargetRetention : l'activation est un geste explicite et validé.
func TestUpdateTargetRetention(t *testing.T) {
	f := &retFixture{}
	db := openRetentionDB(t, "update-retention", f)
	s := &BackupService{db: db}

	if err := s.UpdateTargetRetention(0, true, 3); err == nil {
		t.Error("un identifiant de cible invalide doit être refusé")
	}
	if err := s.UpdateTargetRetention(7, true, 0); err == nil {
		t.Error("activer la rotation en ne gardant aucune archive doit être refusé")
	}
	if err := s.UpdateTargetRetention(7, false, -1); err == nil {
		t.Error("un compteur négatif doit être refusé")
	}
	if err := s.UpdateTargetRetention(7, true, 3); err != nil {
		t.Fatalf("activation légitime refusée : %v", err)
	}

	var wrote bool
	for _, q := range f.executed() {
		if strings.Contains(q, "update backup_targets set retention_enabled") {
			wrote = true
		}
	}
	if !wrote {
		t.Fatalf("l'activation n'a écrit aucun interrupteur, requêtes : %v", f.executed())
	}
}

// TestUpdateTargetSettingsNeverArmsRetention : le bouton « Sauvegarder » de la fiche
// d'une cible règle le compteur mais ne doit JAMAIS armer la rotation — sinon on
// retombe sur une purge destructive d'un clic, sans confirmation.
func TestUpdateTargetSettingsNeverArmsRetention(t *testing.T) {
	f := &retFixture{}
	db := openRetentionDB(t, "update-settings", f)
	s := &BackupService{db: db}

	if err := s.UpdateTargetSettings(7, "port", "22", 3); err != nil {
		t.Fatalf("UpdateTargetSettings: %v", err)
	}
	for _, q := range f.executed() {
		if strings.Contains(q, "retention_enabled") {
			t.Fatalf("UpdateTargetSettings ne doit pas toucher à l'interrupteur : %s", q)
		}
	}
}
