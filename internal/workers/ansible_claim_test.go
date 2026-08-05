package workers

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Pilote database/sql minimal, en mémoire, pour la réservation des tâches Ansible.
//
// La régression visée est concrète : sans claim atomique, un playbook de 8 minutes
// était resélectionné à chaque tick de 60 s et 8 ansible-playbook finissaient par
// tourner en parallèle sur la même machine (incident de saturation disque en prod).
// On rejoue donc la course : N réservations simultanées de la MÊME tâche ne doivent
// en laisser passer qu'une.
//
// Comme pour les tests d'authentification (handlers/authfakedb_test.go), le faux
// pilote est construit sur database/sql/driver plutôt que sur une dépendance externe.
// Il applique la clause WHERE de claimSchedule sous mutex — ce que MySQL fait par
// verrou de ligne. Ce que le test valide côté Go : la condition envoyée à la base est
// bien exclusive, et RowsAffected = 0 fait renoncer l'appelant.
// ─────────────────────────────────────────────────────────────────────────────

type schedRow struct {
	enabled    bool
	nextRun    time.Time
	lastRun    time.Time
	hasLastRun bool
	lastStatus string
}

type schedFakeDB struct {
	mu   sync.Mutex
	rows map[int64]*schedRow
}

var (
	schedFakeMu    sync.Mutex
	schedFakeStore = map[string]*schedFakeDB{}
	schedFakeSeq   atomic.Int64
)

// newSchedFakeDB enregistre un magasin isolé et renvoie le *sql.DB qui le sert.
func newSchedFakeDB(t *testing.T, rows map[int64]*schedRow) (*sql.DB, *schedFakeDB) {
	t.Helper()
	store := &schedFakeDB{rows: rows}
	name := fmt.Sprintf("sched-%d", schedFakeSeq.Add(1))

	schedFakeMu.Lock()
	schedFakeStore[name] = store
	schedFakeMu.Unlock()

	db, err := sql.Open("ansiblesched-fake", name)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, store
}

func (f *schedFakeDB) row(id int64) schedRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.rows[id]
}

func (f *schedFakeDB) exec(query string, args []driver.Value) (driver.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	// claimSchedule
	case strings.Contains(query, "SET last_status = ?, last_run = ?, next_run = ?"):
		if len(args) != 7 {
			return nil, fmt.Errorf("claim: 7 paramètres attendus, %d reçus", len(args))
		}
		var (
			status      = args[0].(string)
			lastRun     = args[1].(time.Time)
			nextRun     = args[2].(time.Time)
			id          = args[3].(int64)
			now         = args[4].(time.Time)
			runningTag  = args[5].(string)
			staleBefore = args[6].(time.Time)
		)
		row, ok := f.rows[id]
		if !ok || !row.enabled || row.nextRun.After(now) {
			return schedFakeResult(0), nil
		}
		// (last_status <> 'running' OR last_run IS NULL OR last_run < staleBefore)
		free := row.lastStatus != runningTag || !row.hasLastRun || row.lastRun.Before(staleBefore)
		if !free {
			return schedFakeResult(0), nil
		}
		row.lastStatus = status
		row.lastRun = lastRun
		row.hasLastRun = true
		row.nextRun = nextRun
		return schedFakeResult(1), nil

	// recoverOrphanSchedules
	case strings.Contains(query, "SET last_status = 'error', last_output = ?"):
		runningTag := args[1].(string)
		var n int64
		for _, row := range f.rows {
			if row.lastStatus == runningTag {
				row.lastStatus = "error"
				n++
			}
		}
		return schedFakeResult(n), nil
	}
	return nil, fmt.Errorf("requête inattendue : %s", query)
}

type schedFakeResult int64

func (r schedFakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r schedFakeResult) RowsAffected() (int64, error) { return int64(r), nil }

type schedFakeDriver struct{}

func (schedFakeDriver) Open(name string) (driver.Conn, error) {
	schedFakeMu.Lock()
	defer schedFakeMu.Unlock()
	store, ok := schedFakeStore[name]
	if !ok {
		return nil, fmt.Errorf("magasin de test inconnu : %s", name)
	}
	return &schedFakeConn{store: store}, nil
}

type schedFakeConn struct{ store *schedFakeDB }

func (c *schedFakeConn) Prepare(query string) (driver.Stmt, error) {
	return &schedFakeStmt{store: c.store, query: query}, nil
}
func (c *schedFakeConn) Close() error              { return nil }
func (c *schedFakeConn) Begin() (driver.Tx, error) { return nil, driver.ErrSkip }

type schedFakeStmt struct {
	store *schedFakeDB
	query string
}

func (s *schedFakeStmt) Close() error  { return nil }
func (s *schedFakeStmt) NumInput() int { return -1 }
func (s *schedFakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.store.exec(s.query, args)
}
func (s *schedFakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, io.EOF
}

func init() {
	sql.Register("ansiblesched-fake", schedFakeDriver{})
}

// dueRow construit une tâche due, jamais exécutée.
func dueRow() *schedRow {
	return &schedRow{enabled: true, nextRun: time.Now().Add(-time.Minute), lastStatus: "success"}
}

// Le cœur du correctif : une seule des réservations concurrentes gagne.
func TestClaimScheduleIsExclusiveUnderConcurrency(t *testing.T) {
	db, store := newSchedFakeDB(t, map[int64]*schedRow{7: dueRow()})

	const racers = 16
	var (
		wg   sync.WaitGroup
		won  atomic.Int64
		errs = make(chan error, racers)
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claimed, err := claimSchedule(db, 7, 60, time.Hour)
			if err != nil {
				errs <- err
				return
			}
			if claimed {
				won.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("claimSchedule: %v", err)
	}

	if got := won.Load(); got != 1 {
		t.Fatalf("%d réservations gagnantes, 1 attendue (playbooks concurrents sur la même machine)", got)
	}
	row := store.row(7)
	if row.lastStatus != statusRunning {
		t.Errorf("statut = %q, attendu %q", row.lastStatus, statusRunning)
	}
	if !row.nextRun.After(time.Now()) {
		t.Errorf("next_run doit être repoussé dès la réservation, obtenu %v", row.nextRun)
	}
}

// Une tâche encore en vol n'est pas reprise, même redevenue due.
func TestClaimScheduleSkipsRunningSchedule(t *testing.T) {
	row := dueRow()
	row.lastStatus = statusRunning
	row.lastRun = time.Now().Add(-2 * time.Minute)
	row.hasLastRun = true
	db, _ := newSchedFakeDB(t, map[int64]*schedRow{3: row})

	claimed, err := claimSchedule(db, 3, 1, time.Hour)
	if err != nil {
		t.Fatalf("claimSchedule: %v", err)
	}
	if claimed {
		t.Fatal("une tâche 'running' sous bail ne doit pas être relancée")
	}
}

// …mais une tâche dont le bail a expiré (process disparu) est reprise, sinon la
// planification resterait bloquée pour toujours.
func TestClaimScheduleReclaimsExpiredLease(t *testing.T) {
	row := dueRow()
	row.lastStatus = statusRunning
	row.lastRun = time.Now().Add(-3 * time.Hour)
	row.hasLastRun = true
	db, _ := newSchedFakeDB(t, map[int64]*schedRow{4: row})

	claimed, err := claimSchedule(db, 4, 60, time.Hour)
	if err != nil {
		t.Fatalf("claimSchedule: %v", err)
	}
	if !claimed {
		t.Fatal("une tâche orpheline au-delà du bail doit être reprise")
	}
}

// Une tâche désactivée ou pas encore due n'est jamais réservée.
func TestClaimScheduleIgnoresNotDueOrDisabled(t *testing.T) {
	notDue := dueRow()
	notDue.nextRun = time.Now().Add(time.Hour)
	disabled := dueRow()
	disabled.enabled = false
	db, _ := newSchedFakeDB(t, map[int64]*schedRow{1: notDue, 2: disabled})

	for _, id := range []int{1, 2} {
		claimed, err := claimSchedule(db, id, 10, time.Hour)
		if err != nil {
			t.Fatalf("claimSchedule(%d): %v", id, err)
		}
		if claimed {
			t.Fatalf("la tâche %d ne devait pas être réservée", id)
		}
	}
}

// Au démarrage, les exécutions coupées net repartent d'un statut propre.
func TestRecoverOrphanSchedulesResetsRunningRows(t *testing.T) {
	running := dueRow()
	running.lastStatus = statusRunning
	ok := dueRow()
	db, store := newSchedFakeDB(t, map[int64]*schedRow{1: running, 2: ok})

	recoverOrphanSchedules(db)

	if got := store.row(1).lastStatus; got != "error" {
		t.Errorf("tâche orpheline : statut = %q, attendu \"error\"", got)
	}
	if got := store.row(2).lastStatus; got != "success" {
		t.Errorf("tâche saine modifiée à tort : statut = %q", got)
	}
}
