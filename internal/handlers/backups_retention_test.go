package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"goacore/internal/services"
)

// ─────────────────────────────────────────────────────────────────────────────
// Câblage de l'interrupteur de rétention (POST /api/backups/target-settings).
//
// La rotation des archives est passée en opt-in explicite (retention_enabled,
// faux par défaut, migration qui laisse tout l'existant désactivé). Le handler
// n'envoyait que retention_count : l'exploitant réglait « conserver N archives »,
// l'interface confirmait l'enregistrement, et rien ne se passait jamais.
// ─────────────────────────────────────────────────────────────────────────────

const retentionTestSessionSecret = "backup-retention-test-session-secret-0123"

// postTargetSettings joue la requête en tant qu'administrateur et rend la réponse
// ainsi que la base factice, pour inspecter ce qui a réellement été écrit.
func postTargetSettings(t *testing.T, jsonBody string) (*httptest.ResponseRecorder, *authFakeDB) {
	t.Helper()
	db, fake := newAuthFakeDB(t)
	fake.addUser(&authFakeUser{id: 1, role: "Admin"}, "admin")

	store := sessions.NewCookieStore([]byte(retentionTestSessionSecret))
	h := &Handler{
		DB:           db,
		SessionStore: store,
		Backup:       services.NewBackupService(db, nil, nil, nil),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/backups/target-settings", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	sess, _ := store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = "admin"
	sess.Values["role"] = "Admin"
	seed := httptest.NewRecorder()
	if err := sess.Save(req, seed); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range seed.Result().Cookies() {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	h.HandleBackupTargetSettings(rec, req)
	return rec, fake
}

// retentionExec renvoie l'unique écriture de retention_enabled, ou échoue.
func retentionExec(t *testing.T, fake *authFakeDB) authFakeExec {
	t.Helper()
	execs := fake.execsMatching("update backup_targets set retention_enabled")
	if len(execs) != 1 {
		t.Fatalf("attendu 1 écriture de retention_enabled, obtenu %d", len(execs))
	}
	return execs[0]
}

// TestTargetSettingsArmsRetention : la case cochée doit atteindre la base. Sans
// ce chemin, UpdateTargetRetention n'est appelé par personne et l'interrupteur
// reste à faux pour toujours.
func TestTargetSettingsArmsRetention(t *testing.T) {
	rec, fake := postTargetSettings(t,
		`{"target_id":7,"healthcheck_type":"none","healthcheck_target":"","retention_count":3,"retention_enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d (corps %q), attendu 200", rec.Code, rec.Body.String())
	}

	exec := retentionExec(t, fake)
	if got := fmt.Sprint(exec.args[0]); got != "true" && got != "1" {
		t.Errorf("retention_enabled écrit à %q, attendu vrai", got)
	}
	if got := fmt.Sprint(exec.args[1]); got != "3" {
		t.Errorf("retention_count écrit à %q, attendu 3", got)
	}
	if got := fmt.Sprint(exec.args[2]); got != "7" {
		t.Errorf("cible visée %q, attendue 7", got)
	}
}

// TestTargetSettingsDisarmsRetention : décocher est un geste non destructif, il
// passe sans confirmation — mais il doit bien désarmer.
func TestTargetSettingsDisarmsRetention(t *testing.T) {
	rec, fake := postTargetSettings(t,
		`{"target_id":7,"healthcheck_type":"none","healthcheck_target":"","retention_count":3,"retention_enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d (corps %q), attendu 200", rec.Code, rec.Body.String())
	}
	exec := retentionExec(t, fake)
	if got := fmt.Sprint(exec.args[0]); got != "false" && got != "0" {
		t.Errorf("retention_enabled écrit à %q, attendu faux", got)
	}
}

// TestTargetSettingsDefaultsToDisarmed : un client qui ne connaît pas le champ
// (formulaire ancien, script tiers) ne doit pas armer une purge par omission.
func TestTargetSettingsDefaultsToDisarmed(t *testing.T) {
	rec, fake := postTargetSettings(t,
		`{"target_id":7,"healthcheck_type":"none","healthcheck_target":"","retention_count":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d (corps %q), attendu 200", rec.Code, rec.Body.String())
	}
	exec := retentionExec(t, fake)
	if got := fmt.Sprint(exec.args[0]); got != "false" && got != "0" {
		t.Errorf("retention_enabled écrit à %q en l'absence du champ, attendu faux", got)
	}
}

// TestTargetSettingsRejectsArmingWithZeroKept : « activer la rotation en gardant
// 0 archive » n'est pas une rétention, c'est un effacement. Le service le refuse ;
// le handler doit rendre un 400 explicite plutôt qu'un « enregistré » mensonger.
func TestTargetSettingsRejectsArmingWithZeroKept(t *testing.T) {
	rec, fake := postTargetSettings(t,
		`{"target_id":7,"healthcheck_type":"none","healthcheck_target":"","retention_count":0,"retention_enabled":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("statut %d (corps %q), attendu 400", rec.Code, rec.Body.String())
	}
	if len(fake.execsMatching("update backup_targets set retention_enabled")) != 0 {
		t.Error("une écriture de retention_enabled a eu lieu malgré le refus")
	}
	if !strings.Contains(rec.Body.String(), "au moins 1 archive") {
		t.Errorf("message d'erreur peu exploitable : %q", rec.Body.String())
	}
}

// TestTargetSettingsRetentionIsAdminOnly : la garde en profondeur du handler doit
// tenir même si le routeur venait à changer.
func TestTargetSettingsRetentionIsAdminOnly(t *testing.T) {
	db, fake := newAuthFakeDB(t)
	fake.addUser(&authFakeUser{id: 2, role: "Viewer"}, "viewer")

	store := sessions.NewCookieStore([]byte(retentionTestSessionSecret))
	h := &Handler{DB: db, SessionStore: store, Backup: services.NewBackupService(db, nil, nil, nil)}

	req := httptest.NewRequest(http.MethodPost, "/api/backups/target-settings",
		strings.NewReader(`{"target_id":7,"retention_count":3,"retention_enabled":true}`))
	sess, _ := store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = "viewer"
	sess.Values["role"] = "Viewer"
	seed := httptest.NewRecorder()
	if err := sess.Save(req, seed); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range seed.Result().Cookies() {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	h.HandleBackupTargetSettings(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("statut %d, attendu 403 pour un rôle Viewer", rec.Code)
	}
	if len(fake.execsMatching("update backup_targets")) != 0 {
		t.Error("une écriture a eu lieu pour un utilisateur non administrateur")
	}
}
