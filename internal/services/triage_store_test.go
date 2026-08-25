package services

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

// Ces tests exercent le store de triage contre une vraie base MySQL, même
// convention que soar_persistence_test.go côté workers : skippés sans
// SOAR_TEST_DSN, table jetable recréée au schéma identique à Migrate.
func triageTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SOAR_TEST_DSN")
	if dsn == "" {
		t.Skip("SOAR_TEST_DSN non défini — test d'intégration MySQL skippé")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	for _, q := range []string{
		`DROP TABLE IF EXISTS soar_triage`,
		`CREATE TABLE soar_triage (
			fingerprint CHAR(64) PRIMARY KEY,
			status ENUM('open','by_design','false_positive','investigating','resolved') NOT NULL DEFAULT 'open',
			rule_id VARCHAR(32) NOT NULL DEFAULT '',
			agent_name VARCHAR(191) NOT NULL DEFAULT '',
			title VARCHAR(191) NOT NULL DEFAULT '',
			sample_alert JSON NULL,
			count_suppressed INT NOT NULL DEFAULT 0,
			suppressed_since_digest INT NOT NULL DEFAULT 0,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			decided_at DATETIME NULL,
			decided_by VARCHAR(191) NOT NULL DEFAULT '',
			decided_by_id VARCHAR(32) NOT NULL DEFAULT '',
			INDEX idx_triage_status (status)
		)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("schema %q: %v", q, err)
		}
	}
	return db
}

// TestTriageStoreLifecycle : RecordSeen crée en « open », un verdict le
// remplace, une récidive rouvre « resolved » (régression) mais préserve
// « investigating » (déjà pris en charge) — le cœur du triage apprenant.
func TestTriageStoreLifecycle(t *testing.T) {
	db := triageTestDB(t)
	defer db.Close()
	s := NewTriageStore(db)

	if err := s.RecordSeen(testFP, "5710", "srv", "SSH", []byte(`{"rule":{"id":"5710"}}`)); err != nil {
		t.Fatalf("RecordSeen: %v", err)
	}
	if st, _, err := s.Decision(testFP); err != nil || st != TriageOpen {
		t.Fatalf("statut après création = (%q, %v), attendu open", st, err)
	}

	if err := s.SetDecision(testFP, TriageInvestigating, "abraham", "1234567890"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}
	if err := s.RecordSeen(testFP, "5710", "srv", "SSH", nil); err != nil {
		t.Fatalf("RecordSeen (récidive): %v", err)
	}
	if st, _, _ := s.Decision(testFP); st != TriageInvestigating {
		t.Fatalf("une récidive a écrasé « investigating » (statut %q)", st)
	}
	// Le sample déjà stocké ne doit pas être effacé par une récidive sans sample.
	var sample sql.NullString
	if err := db.QueryRow("SELECT sample_alert FROM soar_triage WHERE fingerprint = ?", testFP).Scan(&sample); err != nil {
		t.Fatalf("lecture sample: %v", err)
	}
	if !sample.Valid || sample.String == "" {
		t.Fatal("le sample a été effacé par une récidive sans sample (COALESCE cassé)")
	}

	if err := s.SetDecision(testFP, TriageResolved, "abraham", "1234567890"); err != nil {
		t.Fatalf("SetDecision resolved: %v", err)
	}
	if err := s.RecordSeen(testFP, "5710", "srv", "SSH", nil); err != nil {
		t.Fatalf("RecordSeen (récidive post-résolution): %v", err)
	}
	if st, _, _ := s.Decision(testFP); st != TriageOpen {
		t.Fatalf("une récidive après résolution doit rouvrir (statut %q)", st)
	}
}

// TestTriageStoreDecisionUpsert : un verdict sur une empreinte SANS row (base
// dev reset, vieux message Discord aux boutons encore actifs) crée la row au
// lieu d'échouer — le clic de l'opérateur ne doit jamais se perdre.
func TestTriageStoreDecisionUpsert(t *testing.T) {
	db := triageTestDB(t)
	defer db.Close()
	s := NewTriageStore(db)

	if err := s.SetDecision(testFP, TriageByDesign, "abraham", "1234567890"); err != nil {
		t.Fatalf("SetDecision sur row absente: %v", err)
	}
	st, by, err := s.Decision(testFP)
	if err != nil || st != TriageByDesign || by != "abraham" {
		t.Fatalf("Decision = (%q, %q, %v), attendu (by_design, abraham)", st, by, err)
	}
	// L'ID Discord immuable est la traçabilité réelle (le username se change).
	var byID string
	if err := db.QueryRow("SELECT decided_by_id FROM soar_triage WHERE fingerprint = ?", testFP).Scan(&byID); err != nil || byID != "1234567890" {
		t.Fatalf("decided_by_id = (%q, %v), attendu 1234567890", byID, err)
	}
	if err := s.SetDecision(testFP, "sudo_rm_rf", "x", "1"); err == nil {
		t.Fatal("verdict invalide accepté")
	}
}

// TestTriageStoreDigestCounters : les compteurs de suppression alimentent le
// digest, et le reset SOUSTRAIT ce qui a été rapporté — une suppression arrivée
// entre la lecture et le reset survit pour le digest suivant (jamais de perte).
func TestTriageStoreDigestCounters(t *testing.T) {
	db := triageTestDB(t)
	defer db.Close()
	s := NewTriageStore(db)

	if err := s.SetDecision(testFP, TriageByDesign, "abraham", "1234567890"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := s.RecordSuppressed(testFP); err != nil {
			t.Fatalf("RecordSuppressed: %v", err)
		}
	}

	rows, err := s.DigestRows()
	if err != nil {
		t.Fatalf("DigestRows: %v", err)
	}
	if len(rows) != 1 || rows[0].SinceDigest != 2 || rows[0].TotalSuppressed != 2 {
		t.Fatalf("digest inattendu: %+v", rows)
	}
	if rows[0].Status != TriageByDesign {
		t.Fatalf("statut digest %q", rows[0].Status)
	}

	// Suppression concurrente entre la lecture du digest et le reset.
	if err := s.RecordSuppressed(testFP); err != nil {
		t.Fatalf("RecordSuppressed concurrent: %v", err)
	}
	if err := s.ResetDigestCounts(rows); err != nil {
		t.Fatalf("ResetDigestCounts: %v", err)
	}
	var since, total int
	if err := db.QueryRow("SELECT suppressed_since_digest, count_suppressed FROM soar_triage WHERE fingerprint = ?", testFP).
		Scan(&since, &total); err != nil {
		t.Fatalf("lecture compteurs: %v", err)
	}
	if since != 1 {
		t.Fatalf("suppressed_since_digest = %d après reset, attendu 1 (la suppression concurrente doit survivre)", since)
	}
	if total != 3 {
		t.Fatalf("count_suppressed = %d, attendu 3 (le total vie-entière ne se reset jamais)", total)
	}
	// Plus rien à rapporter sauf la concurrente.
	rows, _ = s.DigestRows()
	if len(rows) != 1 || rows[0].SinceDigest != 1 {
		t.Fatalf("digest suivant inattendu: %+v", rows)
	}
}

// TestTriageStoreNilSafe : le worker tourne en tests avec db=nil — chaque
// lecture dégrade en « aucun classement » et chaque écriture best-effort en
// no-op, sans panic. Seul SetDecision (clic opérateur) doit remonter une erreur.
func TestTriageStoreNilSafe(t *testing.T) {
	for name, s := range map[string]*TriageStore{"store nil": nil, "db nil": NewTriageStore(nil)} {
		t.Run(name, func(t *testing.T) {
			if st, by, err := s.Decision(testFP); err != nil || st != "" || by != "" {
				t.Fatalf("Decision = (%q, %q, %v)", st, by, err)
			}
			if err := s.RecordSeen(testFP, "r", "a", "t", nil); err != nil {
				t.Fatalf("RecordSeen: %v", err)
			}
			if err := s.RecordSuppressed(testFP); err != nil {
				t.Fatalf("RecordSuppressed: %v", err)
			}
			if rows, err := s.DigestRows(); err != nil || rows != nil {
				t.Fatalf("DigestRows = (%v, %v)", rows, err)
			}
			if err := s.ResetDigestCounts(nil); err != nil {
				t.Fatalf("ResetDigestCounts: %v", err)
			}
			if err := s.SetDecision(testFP, TriageByDesign, "x", "1"); err == nil {
				t.Fatal("SetDecision sans DB doit échouer (le clic doit être signalé perdu)")
			}
		})
	}
}
