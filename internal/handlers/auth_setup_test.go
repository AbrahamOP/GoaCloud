package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// setupPost drives one POST /setup through the real handler.
func (rig *authRig) setupPost(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.200:33333"
	rec := httptest.NewRecorder()
	rig.h.HandleSetup(rec, req)
	return rec
}

// TestSetup_CreatesFirstAdminOnce: the first-install path still works, and once an
// account exists /setup can no longer create a second one. The check and the INSERT
// now share a transaction with a locking read, so two simultaneous POSTs cannot
// both slip past a stale "no user yet" count.
func TestSetup_CreatesFirstAdminOnce(t *testing.T) {
	rig := newAuthRig(t)

	form := url.Values{"username": {"root"}, "password": {"install-me-please"}, "confirm_password": {"install-me-please"}}
	rec := rig.setupPost(t, form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("first setup: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?setup=success" {
		t.Fatalf("first setup: redirect to %q, want /login?setup=success", loc)
	}
	if u, ok := rig.fake.user("root"); !ok || u.role != "Admin" {
		t.Fatalf("first setup: admin account not created (%+v)", u)
	}

	// A second attempt (different name) is refused: the instance is already set up.
	second := url.Values{"username": {"intruder"}, "password": {"install-me-please"}, "confirm_password": {"install-me-please"}}
	rec = rig.setupPost(t, second)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("second setup: got %d → %q, want 303 → /login", rec.Code, rec.Header().Get("Location"))
	}
	if _, ok := rig.fake.user("intruder"); ok {
		t.Fatal("a second admin account was created through /setup")
	}
}

// TestSetup_SecondAdminRefused pins the OTHER half of createFirstAdmin: once a row
// exists, the transaction bails out before the INSERT and reports "not created".
//
// NOTE on scope: the genuinely CONCURRENT guarantee — two POSTs in flight at the
// same instant — comes from the InnoDB locking read (SELECT ... FOR UPDATE inside
// the transaction) and can only be observed against a real MySQL. A fake driver
// that serialised the transactions for us would be proving its own behaviour, not
// the handler's, so we assert the deterministic half here and leave the locking to
// the database it is written for.
func TestSetup_SecondAdminRefused(t *testing.T) {
	rig := newAuthRig(t)

	created, err := rig.h.createFirstAdmin("first", authTestHash(t, "install-me-please"))
	if err != nil || !created {
		t.Fatalf("first admin: created=%v err=%v, want created", created, err)
	}
	created, err = rig.h.createFirstAdmin("second", authTestHash(t, "install-me-please"))
	if err != nil {
		t.Fatalf("second admin: unexpected error %v", err)
	}
	if created {
		t.Fatal("a second admin was created — the emptiness check inside the transaction did not hold")
	}
	if n := len(rig.fake.execsMatching("insert into users")); n != 1 {
		t.Fatalf("%d INSERTs reached the database, want 1", n)
	}
}

// TestSetup_RateLimited: /setup is public by necessity (no account exists yet), so
// a blocked IP is turned away before anything is created. The block is driven
// straight through the limiter here — see TestSetup_FormTyposDoNotLockOut for WHY
// a mistyped form is no longer what puts an IP there.
func TestSetup_RateLimited(t *testing.T) {
	rig := newAuthRig(t)

	const installerIP = "198.51.100.200" // the peer address setupPost dials from
	for i := 0; i < 5; i++ {
		rig.h.RateLimiter.RecordFailure(installerIP)
	}

	good := url.Values{"username": {"root"}, "password": {"install-me-please"}, "confirm_password": {"install-me-please"}}
	if rec := rig.setupPost(t, good); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked IP with a valid form: status %d, want 429", rec.Code)
	}
	if _, ok := rig.fake.user("root"); ok {
		t.Fatal("an account was created while the IP was blocked")
	}
}

// TestSetup_FormTyposDoNotLockOut is the regression test for "the first install
// locks itself out": every rejected FORM (empty field, short password, mismatched
// confirmation) used to count as a rate-limiting failure, so five typos blocked the
// operator's own IP for 15 minutes — on a brand-new instance with no account to
// recover from and no other way in. Only abuse is charged now; a typo is free.
func TestSetup_FormTyposDoNotLockOut(t *testing.T) {
	rig := newAuthRig(t)

	typos := []url.Values{
		{"username": {""}, "password": {""}, "confirm_password": {""}},
		{"username": {"root"}, "password": {"short"}, "confirm_password": {"short"}},
		{"username": {"root"}, "password": {"install-me-please"}, "confirm_password": {"mismatch"}},
	}
	for round := 0; round < 3; round++ {
		for i, form := range typos {
			if rec := rig.setupPost(t, form); rec.Code != http.StatusOK {
				t.Fatalf("round %d typo %d: status %d, want 200 (form re-rendered with an error)", round, i, rec.Code)
			}
		}
	}

	// Nine mistyped forms later, the install must still be possible.
	good := url.Values{"username": {"root"}, "password": {"install-me-please"}, "confirm_password": {"install-me-please"}}
	rec := rig.setupPost(t, good)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("install after typos: status %d, want 303 — form errors must not block the first install", rec.Code)
	}
	if _, ok := rig.fake.user("root"); !ok {
		t.Fatal("the admin account was not created after the corrected form")
	}
}
