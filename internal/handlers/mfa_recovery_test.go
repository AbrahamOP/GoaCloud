package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"goacore/internal/services"
)

// authSessionCookie mints a signed, authenticated session cookie for username,
// using the rig's own CookieStore — indistinguishable from a real logged-in user.
func (rig *authRig) authSessionCookie(t *testing.T, username string) *http.Cookie {
	t.Helper()
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

func (rig *authRig) postJSON(t *testing.T, handler http.HandlerFunc, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.77:40000"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestDisableMFA_RequiresReauthentication is the regression test for "a hijacked
// session can strip the second factor": /api/mfa/disable used to trust the cookie
// alone, so an attacker who stole a session could turn MFA off and re-enrol it on
// their own device. Proof of ONE factor (password or current TOTP) is now required.
func TestDisableMFA_RequiresReauthentication(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	rig.addMFAUser(t, "alice", authTestHash(t, password))
	cookie := rig.authSessionCookie(t, "alice")

	cases := []struct {
		name     string
		body     string
		wantCode int
	}{
		{"empty body", ``, http.StatusBadRequest},
		{"no proof", `{}`, http.StatusBadRequest},
		{"wrong password", `{"password":"nope"}`, http.StatusUnauthorized},
		{"wrong code", `{"code":"000000"}`, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := rig.postJSON(t, rig.h.HandleDisableMFA, "/api/mfa/disable", tc.body, cookie)
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d", rec.Code, tc.wantCode)
			}
			u, _ := rig.fake.user("alice")
			if !u.mfaEnabled {
				t.Fatal("MFA was disabled without a valid re-authentication")
			}
		})
	}
}

// TestDisableMFA_WithPasswordRevokesSessions: the legitimate path works AND every
// existing session is revoked — which evicts the session an attacker would be
// riding if they had also learnt the password.
func TestDisableMFA_WithPasswordRevokesSessions(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	rig.addMFAUser(t, "alice", authTestHash(t, password))
	cookie := rig.authSessionCookie(t, "alice")

	rec := rig.postJSON(t, rig.h.HandleDisableMFA, "/api/mfa/disable", `{"password":"`+password+`"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	u, _ := rig.fake.user("alice")
	if u.mfaEnabled {
		t.Fatal("MFA is still enabled after a valid disable")
	}
	if u.sessionEpoch != 1 {
		t.Fatalf("session_epoch = %d, want 1 — disabling MFA must revoke existing sessions", u.sessionEpoch)
	}
}

// TestDisableMFA_WithTOTPCode: the second accepted proof is a current TOTP code,
// for users who reach the page without wanting to retype their password.
func TestDisableMFA_WithTOTPCode(t *testing.T) {
	rig := newAuthRig(t)
	secret := rig.addMFAUser(t, "alice", authTestHash(t, "correct horse battery"))
	cookie := rig.authSessionCookie(t, "alice")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec := rig.postJSON(t, rig.h.HandleDisableMFA, "/api/mfa/disable", `{"code":"`+code+`"}`, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if u, _ := rig.fake.user("alice"); u.mfaEnabled {
		t.Fatal("MFA is still enabled after a valid TOTP-proved disable")
	}
}

// TestAdminResetUserMFA is the escape hatch for a lost authenticator (or a rotated
// SESSION_SECRET, which leaves every stored TOTP secret undecipherable): an Admin
// can clear a user's second factor instead of the account being locked out for good.
func TestAdminResetUserMFA(t *testing.T) {
	rig := newAuthRig(t)
	rig.addMFAUser(t, "alice", authTestHash(t, "correct horse battery"))
	rig.fake.addUser(&authFakeUser{id: 42, passwordHash: authTestHash(t, "admin-password"), role: "Admin"}, "root")

	rec := rig.postForm(t, rig.h.HandleResetUserMFA, "/api/users/mfa/reset", "user_id=1", rig.authSessionCookie(t, "root"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303: %s", rec.Code, rec.Body.String())
	}
	u, _ := rig.fake.user("alice")
	if u.mfaEnabled {
		t.Fatal("the target user still has MFA enabled after an admin reset")
	}
	if u.sessionEpoch != 1 {
		t.Fatalf("session_epoch = %d, want 1 — a reset must also revoke the target's sessions", u.sessionEpoch)
	}
}

// TestAdminResetUserMFA_ViewerForbidden: the reset is an admin lever, never a
// self-service one — a Viewer must not be able to strip anyone's second factor.
func TestAdminResetUserMFA_ViewerForbidden(t *testing.T) {
	rig := newAuthRig(t)
	rig.addMFAUser(t, "alice", authTestHash(t, "correct horse battery"))
	rig.fake.addUser(&authFakeUser{id: 9, passwordHash: authTestHash(t, "viewer-password"), role: "Viewer"}, "eve")

	rec := rig.postForm(t, rig.h.HandleResetUserMFA, "/api/users/mfa/reset", "user_id=1", rig.authSessionCookie(t, "eve"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if u, _ := rig.fake.user("alice"); !u.mfaEnabled {
		t.Fatal("a Viewer reset another user's MFA")
	}
}

// TestLogoutAll revokes every session of the caller, including the current cookie.
func TestLogoutAll(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "bob")

	rec := rig.postForm(t, rig.h.HandleLogoutAll, "/api/profile/logout-all", "", rig.authSessionCookie(t, "bob"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", rec.Code)
	}
	if u, _ := rig.fake.user("bob"); u.sessionEpoch != 1 {
		t.Fatalf("session_epoch = %d, want 1 — every previously issued cookie must be revoked", u.sessionEpoch)
	}
	// The current cookie is cleared too.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goacloud-session" && (c.Value == "" || c.MaxAge < 0) {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the current session cookie should be cleared by a logout-all")
	}
}

// TestRotateSessionAfterCredentialChange: the helper a credential change calls —
// every previously issued cookie is revoked, and the caller's own session is
// re-issued with the new epoch so the device that changed the password stays in.
func TestRotateSessionAfterCredentialChange(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), sessionEpoch: 4, role: "Admin"}, "bob")

	req := httptest.NewRequest(http.MethodPost, "/api/profile/update", nil)
	req.AddCookie(rig.authSessionCookie(t, "bob"))
	rec := httptest.NewRecorder()
	if err := rig.h.RotateSessionAfterCredentialChange(rec, req, "bob"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if u, _ := rig.fake.user("bob"); u.sessionEpoch != 5 {
		t.Fatalf("session_epoch = %d, want 5", u.sessionEpoch)
	}
	// The response carries a re-issued cookie stamped with the new epoch.
	for _, c := range rec.Result().Cookies() {
		if c.Name != "goacloud-session" || c.Value == "" || c.MaxAge < 0 {
			continue
		}
		probe := httptest.NewRequest(http.MethodGet, "/", nil)
		probe.AddCookie(c)
		sess, _ := rig.store.Get(probe, "goacloud-session")
		if epoch, _ := sess.Values[sessionEpochKey].(int); epoch != 5 {
			t.Fatalf("re-issued cookie carries epoch %d, want 5", epoch)
		}
		return
	}
	t.Fatal("no re-issued session cookie — the caller would be logged out by their own password change")
}

func (rig *authRig) postForm(t *testing.T, handler http.HandlerFunc, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.77:40000"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// keep the imports honest if a refactor drops a usage
var (
	_ = sessions.NewCookieStore
	_ = services.LogAudit
)
