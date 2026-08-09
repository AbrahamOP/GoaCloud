package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// ─────────────────────────────────────────────────────────────────────────────
// Enrolment hardening (/api/mfa/setup → /api/mfa/verify).
//
// Hardening /api/mfa/disable alone was worthless: a hijacked session that cannot
// REMOVE the second factor could still REPLACE it by re-posting /api/mfa/verify
// with a secret of its own — no proof, no epoch bump. These tests pin the two
// properties that close it: the committed secret comes from server-side state, and
// replacing a LIVE factor demands the same proof as removing it.
// ─────────────────────────────────────────────────────────────────────────────

// startEnrolment drives GET /api/mfa/setup and returns the candidate secret plus
// the session cookie that now carries the (encrypted) enrolment state.
func (rig *authRig) startEnrolment(t *testing.T, cookie *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/mfa/setup", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	rig.h.HandleSetupMFA(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup MFA: status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("setup MFA: bad JSON: %v", err)
	}
	if body.Secret == "" {
		t.Fatal("setup MFA: no candidate secret returned")
	}
	updated := cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goacloud-session" && c.Value != "" && c.MaxAge >= 0 {
			updated = c
		}
	}
	if updated == cookie {
		t.Fatal("setup MFA did not persist the enrolment state in the session")
	}
	return body.Secret, updated
}

// sessionOf decodes a session cookie the way the store does on the next request.
func (rig *authRig) sessionOf(t *testing.T, cookie *http.Cookie) map[interface{}]interface{} {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	sess, _ := rig.store.Get(req, "goacloud-session")
	return sess.Values
}

// reissuedSessionCookie returns the session cookie a response re-issued, if any.
func reissuedSessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goacloud-session" && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

// TestVerifyMFA_IgnoresClientSuppliedSecret is the regression test for the bypass:
// /api/mfa/verify used to enrol whatever secret the request body carried. Now the
// only secret it can commit is the one THIS server minted for THIS session, so a
// body-supplied secret without a started enrolment enrols nothing.
func TestVerifyMFA_IgnoresClientSuppliedSecret(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "bob")
	cookie := rig.authSessionCookie(t, "bob")

	attacker, err := totp.Generate(totp.GenerateOpts{Issuer: "GoaCore", AccountName: "bob"})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	body := `{"code":"` + totpCode(t, attacker.Secret()) + `","secret":"` + attacker.Secret() + `"}`

	rec := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", body, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — a body-supplied secret must not be enrollable", rec.Code)
	}
	if u, _ := rig.fake.user("bob"); u.mfaEnabled {
		t.Fatal("a secret chosen by the caller was enrolled")
	}
}

// TestVerifyMFA_FirstEnrolment: the legitimate path still works end-to-end, from
// the server-side candidate secret, and does NOT sign the user out.
func TestVerifyMFA_FirstEnrolment(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "bob")

	secret, cookie := rig.startEnrolment(t, rig.authSessionCookie(t, "bob"))
	rec := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", `{"code":"`+totpCode(t, secret)+`"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	u, _ := rig.fake.user("bob")
	if !u.mfaEnabled {
		t.Fatal("MFA is not enabled after a valid enrolment")
	}
	stored, ok := u.mfaSecret.(string)
	if !ok {
		t.Fatalf("stored MFA secret is %T, want the encrypted string", u.mfaSecret)
	}
	if stored == secret {
		t.Fatal("the MFA secret was stored in the clear")
	}
	if dec, err := rig.h.SSHService.DecryptData(stored); err != nil || dec != secret {
		t.Fatalf("stored secret does not decrypt to the candidate one (err=%v)", err)
	}
	// A first enrolment changes no credential: no need to evict the other devices.
	if u.sessionEpoch != 0 {
		t.Fatalf("session_epoch = %d, want 0 — a first enrolment must not sign anyone out", u.sessionEpoch)
	}
}

// TestVerifyMFA_EnrolmentStateIsConsumed: once committed, the pending secret is
// gone from the session — a replayed verify finds nothing to commit.
func TestVerifyMFA_EnrolmentStateIsConsumed(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "bob")

	secret, cookie := rig.startEnrolment(t, rig.authSessionCookie(t, "bob"))
	rec := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", `{"code":"`+totpCode(t, secret)+`"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("first commit: status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	next := reissuedSessionCookie(rec)
	if next == nil {
		t.Fatal("the response did not re-issue the session cookie that carried the enrolment state")
	}
	if _, pending := rig.sessionOf(t, next)[sessionMFAEnrollSecret]; pending {
		t.Fatal("the enrolment state survived the commit — it must be consumed")
	}
}

// TestVerifyMFA_ReenrolmentRequiresReauthentication is the core of the fix: with
// 2FA already live, replacing the factor demands the same proof as disabling it.
// Without this, hardening /api/mfa/disable only pushed the attacker one endpoint
// to the left.
func TestVerifyMFA_ReenrolmentRequiresReauthentication(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	current := rig.addMFAUser(t, "alice", authTestHash(t, password))
	before, _ := rig.fake.user("alice")

	cases := []struct {
		name     string
		proof    string // extra JSON fields carrying the (in)valid proof
		wantCode int
	}{
		{"no proof", ``, http.StatusBadRequest},
		{"wrong password", `,"password":"nope"`, http.StatusUnauthorized},
		{"wrong current code", `,"current_code":"000000"`, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret, cookie := rig.startEnrolment(t, rig.authSessionCookie(t, "alice"))
			body := `{"code":"` + totpCode(t, secret) + `"` + tc.proof + `}`
			rec := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", body, cookie)
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
			u, _ := rig.fake.user("alice")
			if u.mfaSecret != before.mfaSecret {
				t.Fatal("the second factor was replaced without a valid re-authentication")
			}
			if u.sessionEpoch != 0 {
				t.Fatalf("session_epoch = %d, want 0 — a refused re-enrolment changes nothing", u.sessionEpoch)
			}
		})
	}

	// The legitimate re-enrolment: proof of a current factor, new secret committed,
	// every OTHER session revoked and the current one re-stamped.
	secret, cookie := rig.startEnrolment(t, rig.authSessionCookie(t, "alice"))
	body := `{"code":"` + totpCode(t, secret) + `","current_code":"` + totpCode(t, current) + `"}`
	rec := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid re-enrolment: status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	u, _ := rig.fake.user("alice")
	stored, _ := u.mfaSecret.(string)
	if dec, err := rig.h.SSHService.DecryptData(stored); err != nil || dec != secret {
		t.Fatalf("the new factor was not committed (err=%v)", err)
	}
	if u.sessionEpoch != 1 {
		t.Fatalf("session_epoch = %d, want 1 — replacing the second factor must revoke the other sessions", u.sessionEpoch)
	}
	reissued := reissuedSessionCookie(rec)
	if reissued == nil {
		t.Fatal("no re-issued cookie — the user would be signed out by their own re-enrolment")
	}
	if epoch, _ := rig.sessionOf(t, reissued)[sessionEpochKey].(int); epoch != 1 {
		t.Fatalf("re-issued cookie carries epoch %d, want 1", epoch)
	}
}

// TestVerifyMFA_ExpiredEnrolmentRejected: the candidate secret is not a permanent
// standing offer — past its TTL the user restarts the configuration.
func TestVerifyMFA_ExpiredEnrolmentRejected(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "bob")
	secret, cookie := rig.startEnrolment(t, rig.authSessionCookie(t, "bob"))

	// Rewind the expiry stored in the cookie to just past the TTL.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	sess, _ := rig.store.Get(req, "goacloud-session")
	sess.Values[sessionMFAEnrollExp] = time.Now().Add(-time.Second).Unix()
	rec := httptest.NewRecorder()
	if err := sess.Save(req, rec); err != nil {
		t.Fatalf("re-save session: %v", err)
	}
	expired := reissuedSessionCookie(rec)
	if expired == nil {
		t.Fatal("could not re-save the session cookie")
	}

	out := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", `{"code":"`+totpCode(t, secret)+`"}`, expired)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for an expired enrolment", out.Code)
	}
	if u, _ := rig.fake.user("bob"); u.mfaEnabled {
		t.Fatal("an expired candidate secret was still enrolled")
	}
}

// TestDisableMFA_KeepsTheActingSessionAlive: the epoch bump evicts the OTHER
// devices, but the browser that just proved a factor must not be thrown out
// without explanation — its cookie is re-stamped with the new epoch.
func TestDisableMFA_KeepsTheActingSessionAlive(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	rig.addMFAUser(t, "alice", authTestHash(t, password))

	rec := rig.postJSON(t, rig.h.HandleDisableMFA, "/api/mfa/disable",
		`{"password":"`+password+`"}`, rig.authSessionCookie(t, "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	reissued := reissuedSessionCookie(rec)
	if reissued == nil {
		t.Fatal("no re-issued cookie — disabling 2FA would silently sign the user out")
	}
	values := rig.sessionOf(t, reissued)
	if auth, _ := values["authenticated"].(bool); !auth {
		t.Fatal("the re-issued session is not authenticated")
	}
	if epoch, _ := values[sessionEpochKey].(int); epoch != 1 {
		t.Fatalf("re-issued cookie carries epoch %d, want 1 (the epoch in force after the bump)", epoch)
	}
}

// TestUpdateProfile_RotatesSessionsOnPasswordChange is the end-to-end proof that
// the revocation is actually WIRED: RotateSessionAfterCredentialChange existed but
// nothing in production called it, so a password change left every previously
// issued cookie — including a stolen one — valid for its full 24 hours.
func TestUpdateProfile_RotatesSessionsOnPasswordChange(t *testing.T) {
	rig := newAuthRig(t)
	const oldPassword = "old-password-1234"
	const newPassword = "new-password-5678"
	rig.fake.addUser(&authFakeUser{
		id: 1, passwordHash: authTestHash(t, oldPassword), sessionEpoch: 2, role: "Admin",
	}, "bob")

	form := url.Values{
		"old_password":     {oldPassword},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	}
	rec := rig.postForm(t, rig.h.HandleUpdateProfile, "/api/profile/update", form.Encode(), rig.authSessionCookie(t, "bob"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/profile?success=true" {
		t.Fatalf("redirect to %q, want /profile?success=true", loc)
	}

	u, _ := rig.fake.user("bob")
	if bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(newPassword)) != nil {
		t.Fatal("the new password hash was not written")
	}
	if u.sessionEpoch != 3 {
		t.Fatalf("session_epoch = %d, want 3 — a password change must revoke every existing session", u.sessionEpoch)
	}

	reissued := reissuedSessionCookie(rec)
	if reissued == nil {
		t.Fatal("no re-issued cookie — the user would be signed out by their own password change")
	}
	values := rig.sessionOf(t, reissued)
	if user, _ := values["username"].(string); user != "bob" {
		t.Fatalf("re-issued session username = %q, want bob", user)
	}
	if auth, _ := values["authenticated"].(bool); !auth {
		t.Fatal("the re-issued session is not authenticated")
	}
	if epoch, _ := values[sessionEpochKey].(int); epoch != 3 {
		t.Fatalf("re-issued cookie carries epoch %d, want 3 (the new epoch)", epoch)
	}
}
