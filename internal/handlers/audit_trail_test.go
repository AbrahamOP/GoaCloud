package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// ─────────────────────────────────────────────────────────────────────────────
// Explicit audit entries on the privileged handlers.
//
// The AuditTrail middleware is the net under the Admin-only group, but the
// handlers that carry business context (which guest, which key, which factor)
// write their own entry. These tests pin the MFA pair — the only privileged
// handlers the in-process fake DB can drive end to end — plus the invariant that
// binds them all: a secret must never travel into the trail.
//
// The trail is written from a goroutine (`go services.LogAudit`), hence the poll.
// ─────────────────────────────────────────────────────────────────────────────

// auditEntriesOf returns the audit_logs inserts recorded so far.
func auditEntriesOf(fake *authFakeDB) []authFakeExec {
	return fake.execsMatching("insert into audit_logs")
}

// waitForAuditAction waits for an audit_logs insert carrying the given action and
// returns it (args: user_id, username, action, details, ip_address).
func waitForAuditAction(t *testing.T, fake *authFakeDB, action string) authFakeExec {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, e := range auditEntriesOf(fake) {
			if len(e.args) >= 3 && fmt.Sprint(e.args[2]) == action {
				return e
			}
		}
		if time.Now().After(deadline) {
			var seen []string
			for _, e := range auditEntriesOf(fake) {
				if len(e.args) >= 3 {
					seen = append(seen, fmt.Sprint(e.args[2]))
				}
			}
			t.Fatalf("no audit entry with action %q (recorded: %v)", action, seen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertNoAuditLeak fails if needle appears anywhere in the recorded audit entries.
func assertNoAuditLeak(t *testing.T, fake *authFakeDB, needle, what string) {
	t.Helper()
	for _, e := range auditEntriesOf(fake) {
		for _, arg := range e.args {
			if strings.Contains(fmt.Sprint(arg), needle) {
				t.Fatalf("%s leaked into the audit trail: %v", what, arg)
			}
		}
	}
}

// TestAudit_MFAEnableIsRecorded: enrolling a second factor is a change of the
// account's security posture — it must be traceable, and the TOTP secret must not
// be traced with it.
func TestAudit_MFAEnableIsRecorded(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "alice")

	// The candidate secret is minted server-side by /api/mfa/setup and committed by
	// /api/mfa/verify, which only ever receives the 6-digit code.
	secret, cookie := rig.startEnrolment(t, rig.authSessionCookie(t, "alice"))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	body := fmt.Sprintf(`{"code":%q}`, code)
	if rec := rig.postJSON(t, rig.h.HandleVerifyMFA, "/api/mfa/verify", body, cookie); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	e := waitForAuditAction(t, rig.fake, "MFAEnable")
	if got := fmt.Sprint(e.args[1]); got != "alice" {
		t.Errorf("actor = %q, want %q", got, "alice")
	}
	assertNoAuditLeak(t, rig.fake, secret, "the TOTP secret")
	assertNoAuditLeak(t, rig.fake, code, "the TOTP code")
}

// TestAudit_MFADisableRefusedIsRecorded: a failed attempt to strip the second
// factor is the signature of a hijacked session. It used to leave nothing behind
// but an app log; it now leaves a row — without the credential that was tried.
func TestAudit_MFADisableRefusedIsRecorded(t *testing.T) {
	rig := newAuthRig(t)
	rig.addMFAUser(t, "alice", authTestHash(t, "correct horse battery"))

	const attempted = "wrong-password-attempt"
	rec := rig.postJSON(t, rig.h.HandleDisableMFA, "/api/mfa/disable",
		`{"password":"`+attempted+`"}`, rig.authSessionCookie(t, "alice"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}

	e := waitForAuditAction(t, rig.fake, "MFADisableRefused")
	if got := fmt.Sprint(e.args[1]); got != "alice" {
		t.Errorf("actor = %q, want %q", got, "alice")
	}
	assertNoAuditLeak(t, rig.fake, attempted, "the attempted password")
}

// TestAudit_MFADisableIsRecorded: the legitimate disable keeps its entry (the
// only privileged action that was already traced before this change).
func TestAudit_MFADisableIsRecorded(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	rig.addMFAUser(t, "alice", authTestHash(t, password))

	rec := rig.postJSON(t, rig.h.HandleDisableMFA, "/api/mfa/disable",
		`{"password":"`+password+`"}`, rig.authSessionCookie(t, "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	waitForAuditAction(t, rig.fake, "MFADisable")
	assertNoAuditLeak(t, rig.fake, password, "the password")
}
