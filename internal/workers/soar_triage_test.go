package workers

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"goacore/internal/models"
	"goacore/internal/services"
)

// Ces tests couvrent l'intégration du triage apprenant dans le worker SOAR :
// suppression AVANT post des empreintes classées « bruit », comptage pour le
// digest hebdo, et innocuité totale sans base (db=nil, store nil).

// TestTriageSuppressesAlertNilStore : sans store (tests, boot sans DB), aucune
// suppression — le comportement pré-triage, fail-open.
func TestTriageSuppressesAlertNilStore(t *testing.T) {
	if triageSuppressesAlert(nil, "deadbeef") {
		t.Fatal("un store nil supprime des alertes")
	}
	if triageSuppressesAlert(services.NewTriageStore(nil), "deadbeef") {
		t.Fatal("un store sans DB supprime des alertes")
	}
}

// TestMaybeSendTriageDigestNilSafe : le digest ne doit jamais faire tomber le
// tick — db nil, store nil, discord nil, tout dégrade en no-op.
func TestMaybeSendTriageDigestNilSafe(t *testing.T) {
	maybeSendTriageDigest(nil, nil, nil)
	maybeSendTriageDigest(nil, services.NewTriageStore(nil), nil)
}

// triageWorkerDB étend le harnais MySQL du worker avec la table soar_triage
// (schéma identique à Migrate), en plus de soar_state/soar_alert_dedup.
func triageWorkerDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testDB(t)
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

// stubAlert reconstruit l'alerte servie par stubIndexer (soar_cursor_test.go)
// pour calculer son empreinte de triage côté test.
func stubAlert() services.WazuhAlert {
	var a services.WazuhAlert
	a.Rule.ID = "5710"
	a.Rule.Description = "sshd auth failed"
	a.Agent.ID = "001"
	a.Agent.Name = "srv"
	return a
}

// TestCheckSoarEventsTriageSuppression : une empreinte classée « by design »
// éteint le post (aucun fan-out) mais JAMAIS en silence — chaque occurrence est
// comptée pour le digest et dedupée pour ne pas être retraitée au tick suivant.
func TestCheckSoarEventsTriageSuppression(t *testing.T) {
	db := triageWorkerDB(t)
	defer db.Close()
	triage := services.NewTriageStore(db)

	fp := services.TriageFingerprint(stubAlert())
	if err := triage.SetDecision(fp, services.TriageByDesign, "abraham", "1234567890"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}

	indexer, _ := stubIndexer(t, 3)
	cfg := &models.SoarConfigState{Loaded: true, Config: models.SoarConfig{AlertSSH: true}}
	cursor := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	checkSoarEvents(
		context.Background(),
		db,
		&services.WazuhClient{},
		indexer,
		nil, nil, // IA et Discord absents : une suppression n'en a pas besoin
		cfg,
		triage,
		&sync.Map{}, &sync.Map{},
		&cursor,
	)

	var since, total int
	if err := db.QueryRow(
		"SELECT suppressed_since_digest, count_suppressed FROM soar_triage WHERE fingerprint = ?", fp).
		Scan(&since, &total); err != nil {
		t.Fatalf("lecture compteurs: %v", err)
	}
	if since != 3 || total != 3 {
		t.Fatalf("compteurs (%d, %d), attendu (3, 3) — chaque occurrence supprimée doit être comptée", since, total)
	}
	var dedup int
	if err := db.QueryRow("SELECT COUNT(*) FROM soar_alert_dedup").Scan(&dedup); err != nil {
		t.Fatalf("lecture dedup: %v", err)
	}
	if dedup != 3 {
		t.Fatalf("%d clés dedup persistées, attendu 3 — une alerte supprimée ne doit pas être retraitée au tick suivant", dedup)
	}
}

// TestCheckSoarEventsTriageRecordsOpen : une alerte NON classée part sur Discord
// (ici : échec propre, bot nil) et sa row d'empreinte est upsertée en « open »
// avec un sample — la matière du classement futur et de la phase 2 (similarité).
func TestCheckSoarEventsTriageRecordsOpen(t *testing.T) {
	db := triageWorkerDB(t)
	defer db.Close()
	triage := services.NewTriageStore(db)

	indexer, _ := stubIndexer(t, 2)
	cfg := &models.SoarConfigState{Loaded: true, Config: models.SoarConfig{AlertSSH: true}}
	cursor := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	checkSoarEvents(
		context.Background(),
		db,
		&services.WazuhClient{},
		indexer,
		nil, nil,
		cfg,
		triage,
		&sync.Map{}, &sync.Map{},
		&cursor,
	)

	fp := services.TriageFingerprint(stubAlert())
	var status, ruleID, agentName string
	var sample []byte
	if err := db.QueryRow(
		"SELECT status, rule_id, agent_name, sample_alert FROM soar_triage WHERE fingerprint = ?", fp).
		Scan(&status, &ruleID, &agentName, &sample); err != nil {
		t.Fatalf("row d'empreinte absente après une alerte postée: %v", err)
	}
	if status != services.TriageOpen || ruleID != "5710" || agentName != "srv" {
		t.Fatalf("row (%q, %q, %q), attendu (open, 5710, srv)", status, ruleID, agentName)
	}
	if len(sample) == 0 {
		t.Fatal("sample_alert vide — la phase 2 (similarité) n'aura pas de matière")
	}
}

// TestMaybeSendTriageDigestAnchor verrouille la machine à états de l'ancre :
// premier passage = ancrage sans envoi ; période écoulée sans suppression =
// avance silencieuse ; période écoulée AVEC suppressions mais Discord absent =
// l'ancre n'avance PAS (le digest sera retenté, jamais perdu).
func TestMaybeSendTriageDigestAnchor(t *testing.T) {
	db := triageWorkerDB(t)
	defer db.Close()
	triage := services.NewTriageStore(db)

	// 1. Premier passage : ancre posée, rien envoyé.
	maybeSendTriageDigest(db, triage, nil)
	anchor, err := loadSoarState(db, triageDigestStateKey)
	if err != nil || anchor == "" {
		t.Fatalf("ancre absente après le premier passage (%q, %v)", anchor, err)
	}

	// 2. Période écoulée, aucune suppression : l'ancre avance sans envoi.
	old := time.Now().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	if err := saveSoarState(db, triageDigestStateKey, old); err != nil {
		t.Fatalf("saveSoarState: %v", err)
	}
	maybeSendTriageDigest(db, triage, nil)
	anchor, _ = loadSoarState(db, triageDigestStateKey)
	if anchor == old {
		t.Fatal("période écoulée sans suppression : l'ancre doit avancer (sinon relecture à chaque tick)")
	}

	// 3. Période écoulée AVEC suppressions, Discord indisponible : l'ancre reste.
	if err := saveSoarState(db, triageDigestStateKey, old); err != nil {
		t.Fatalf("saveSoarState: %v", err)
	}
	fp := services.TriageFingerprint(stubAlert())
	if err := triage.SetDecision(fp, services.TriageByDesign, "abraham", "1234567890"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}
	if err := triage.RecordSuppressed(fp); err != nil {
		t.Fatalf("RecordSuppressed: %v", err)
	}
	maybeSendTriageDigest(db, triage, nil)
	anchor, _ = loadSoarState(db, triageDigestStateKey)
	if anchor != old {
		t.Fatal("Discord indisponible : l'ancre a avancé, le digest de suppressions est perdu")
	}
}
