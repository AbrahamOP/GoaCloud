package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"goacore/internal/config"
	"goacore/internal/services"
)

// Ces tests couvrent le parcours d'amorçage TOFU exposé par les trois routes
// /api/ssh/host-keys/*. Le chemin réseau (poignée de main SSH réelle) est déjà
// couvert côté services ; ce qui est vérifié ici, c'est le contrat HTTP : qui a le
// droit d'appeler, ce qui est refusé AVANT toute écriture, et ce que la suppression
// laisse dans le journal d'audit.

// hostKeyRig monte un Handler minimal branché sur la fausse base : seuls la session,
// le rôle et le magasin ssh_host_keys sont sollicités par ces routes.
type hostKeyRig struct {
	h     *Handler
	fake  *authFakeDB
	store *sessions.CookieStore
}

func newHostKeyRig(t *testing.T) *hostKeyRig {
	t.Helper()
	db, fake := newAuthFakeDB(t)
	store := sessions.NewCookieStore([]byte(authTestSessionSecret))
	store.Options = &sessions.Options{Path: "/", MaxAge: 86400, HttpOnly: true, SameSite: http.SameSiteStrictMode}

	h := &Handler{
		DB:           db,
		SessionStore: store,
		Config:       &config.Config{SessionSecret: authTestSessionSecret},
		SSHService:   services.NewSSHService(db, DeriveSSHEncKey(authTestSessionSecret), "", "", "", "", false),
	}
	return &hostKeyRig{h: h, fake: fake, store: store}
}

// user seeds a user with the given role and returns its session cookie.
func (rig *hostKeyRig) user(t *testing.T, username, role string) *http.Cookie {
	t.Helper()
	rig.fake.addUser(&authFakeUser{id: 1, role: role}, username)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := rig.store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = username
	rec := httptest.NewRecorder()
	if err := sess.Save(req, rec); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goacloud-session" {
			return c
		}
	}
	t.Fatal("no session cookie produced")
	return nil
}

func (rig *hostKeyRig) do(t *testing.T, handler http.HandlerFunc, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.77:40000"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestHostKeyRoutesAreAdminOnly : défense en profondeur. Le groupe AdminOnly du
// routeur barre déjà un Viewer, mais chaque handler re-vérifie le rôle — épingler
// (ou désépingler) l'identité d'un hôte engage tous les accès SSH ultérieurs.
func TestHostKeyRoutesAreAdminOnly(t *testing.T) {
	rig := newHostKeyRig(t)
	cookie := rig.user(t, "viewer", "Viewer")

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
	}{
		{"scan", rig.h.HandleSSHHostKeyScan, http.MethodPost, "/api/ssh/host-keys/scan"},
		{"pin", rig.h.HandleSSHHostKeyPin, http.MethodPost, "/api/ssh/host-keys/pin"},
		{"delete", rig.h.HandleSSHHostKeyDelete, http.MethodDelete, "/api/ssh/host-keys"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := rig.do(t, tc.handler, tc.method, tc.path, `{"ip":"192.0.2.10","fingerprint":"SHA256:x"}`, cookie)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("Viewer sur %s %s : code %d, attendu 403", tc.method, tc.path, rec.Code)
			}
			if execs := rig.fake.execsMatching("ssh_host_keys"); len(execs) != 0 {
				t.Fatalf("un Viewer refusé a tout de même touché ssh_host_keys : %v", execs)
			}
		})
	}
}

// TestHostKeyRequestValidation : tout ce qui est refusé l'est AVANT la moindre
// écriture. Le magasin est indexé par IP littérale — accepter un nom d'hôte ferait
// dépendre l'identité épinglée d'une résolution DNS que GoaCore ne contrôle pas.
func TestHostKeyRequestValidation(t *testing.T) {
	rig := newHostKeyRig(t)
	cookie := rig.user(t, "admin", "Admin")

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"scan : corps illisible", rig.h.HandleSSHHostKeyScan, http.MethodPost, `{`},
		{"scan : IP absente", rig.h.HandleSSHHostKeyScan, http.MethodPost, `{}`},
		{"scan : nom d'hôte refusé", rig.h.HandleSSHHostKeyScan, http.MethodPost, `{"ip":"proxmox.local"}`},
		{"pin : IP invalide", rig.h.HandleSSHHostKeyPin, http.MethodPost, `{"ip":"999.1.1.1","fingerprint":"SHA256:x"}`},
		{"pin : empreinte absente", rig.h.HandleSSHHostKeyPin, http.MethodPost, `{"ip":"192.0.2.10"}`},
		{"pin : empreinte vide", rig.h.HandleSSHHostKeyPin, http.MethodPost, `{"ip":"192.0.2.10","fingerprint":"   "}`},
		{"delete : IP absente", rig.h.HandleSSHHostKeyDelete, http.MethodDelete, `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := rig.do(t, tc.handler, tc.method, "/api/ssh/host-keys", tc.body, cookie)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code %d, attendu 400 (corps %s)", rec.Code, tc.body)
			}
			var resp hostKeyResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("réponse non JSON : %q", rec.Body.String())
			}
			if resp.Error == "" {
				t.Fatal("réponse 400 sans message d'erreur exploitable par l'UI")
			}
			if execs := rig.fake.execsMatching("ssh_host_keys"); len(execs) != 0 {
				t.Fatalf("écriture dans ssh_host_keys malgré un refus : %v", execs)
			}
		})
	}
}

// TestHostKeyMethodGuards : chaque route n'accepte que son verbe. Un GET sur le pin
// serait déclenchable par une simple balise <img>.
func TestHostKeyMethodGuards(t *testing.T) {
	rig := newHostKeyRig(t)
	cookie := rig.user(t, "admin", "Admin")

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{"scan en GET", rig.h.HandleSSHHostKeyScan, http.MethodGet},
		{"pin en GET", rig.h.HandleSSHHostKeyPin, http.MethodGet},
		{"delete en POST", rig.h.HandleSSHHostKeyDelete, http.MethodPost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := rig.do(t, tc.handler, tc.method, "/api/ssh/host-keys", `{"ip":"192.0.2.10"}`, cookie)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("code %d, attendu 405", rec.Code)
			}
		})
	}
}

// TestHostKeyDeleteUnpinsAndAudits : la suppression est l'UNIQUE sortie d'un
// ErrHostKeyMismatch (hôte réinstallé). Elle doit effacer la ligne épinglée et
// laisser une trace : désépingler rouvre la fenêtre TOFU pour cet hôte.
func TestHostKeyDeleteUnpinsAndAudits(t *testing.T) {
	rig := newHostKeyRig(t)
	cookie := rig.user(t, "admin", "Admin")

	rec := rig.do(t, rig.h.HandleSSHHostKeyDelete, http.MethodDelete, "/api/ssh/host-keys", `{"ip":"192.0.2.10"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d, attendu 200 : %s", rec.Code, rec.Body.String())
	}
	var resp hostKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("réponse non JSON : %q", rec.Body.String())
	}
	if resp.Status != "deleted" || resp.IP != "192.0.2.10" {
		t.Fatalf("réponse = %+v, attendu status=deleted ip=192.0.2.10", resp)
	}

	dels := rig.fake.execsMatching("delete from ssh_host_keys")
	if len(dels) != 1 {
		t.Fatalf("%d suppressions dans ssh_host_keys, attendu 1", len(dels))
	}
	if got := dels[0].args[0]; got != "192.0.2.10" {
		t.Fatalf("suppression ciblant %v, attendu 192.0.2.10", got)
	}

	// LogAudit est appelé dans une goroutine : on lui laisse le temps d'écrire.
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries := rig.fake.execsMatching("insert into audit_logs")
		if len(entries) > 0 {
			details := entries[0].args
			if !strings.Contains(fmt.Sprintf("%v", details), "192.0.2.10") {
				t.Fatalf("entrée d'audit sans l'IP désépinglée : %v", details)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("aucune entrée d'audit pour une suppression de clé hôte épinglée")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
