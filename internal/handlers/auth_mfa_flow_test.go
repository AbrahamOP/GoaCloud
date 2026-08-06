package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"goacore/internal/config"
	"goacore/internal/middleware"
	"goacore/internal/services"
	"golang.org/x/crypto/bcrypt"
)

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end HTTP test of the TWO-STEP MFA login.
//
// This is the coverage gap that let a total MFA outage ship: mfa_roundtrip_test.go
// proves the crypto (encrypt → decrypt → validate) but never drives the two HTTP
// round-trips, so nobody noticed the second POST was submitting an EMPTY password
// (the MFA step re-posted the password from a hidden field the handler never
// filled). Every MFA account was locked out, and each attempt burned a slot in the
// 5-strike rate limiter.
//
// The rig below behaves like a browser: it runs the REAL handler with the REAL
// login.html template, keeps a cookie jar between requests, and re-posts ONLY the
// fields the served form actually contains.
// ─────────────────────────────────────────────────────────────────────────────

const authTestSessionSecret = "auth-flow-test-session-secret-0123456789"

type authRig struct {
	h     *Handler
	fake  *authFakeDB
	store *sessions.CookieStore
	jar   map[string]*http.Cookie
}

func newAuthRig(t *testing.T) *authRig {
	t.Helper()
	db, fake := newAuthFakeDB(t)
	store := sessions.NewCookieStore([]byte(authTestSessionSecret))
	store.Options = &sessions.Options{Path: "/", MaxAge: 86400, HttpOnly: true, SameSite: http.SameSiteStrictMode}

	h := &Handler{
		DB:           db,
		Templates:    loadSettingsTemplates(t), // the real assets/templates/*.html set
		SessionStore: store,
		Config:       &config.Config{SessionSecret: authTestSessionSecret},
		RateLimiter:  middleware.NewRateLimiter(),
		SSHService:   services.NewSSHService(nil, DeriveSSHEncKey(authTestSessionSecret), "", "", "", "", false),
		Registry:     services.NewServiceRegistry(false), // no Discord bot → notifications are no-ops
	}
	return &authRig{h: h, fake: fake, store: store, jar: map[string]*http.Cookie{}}
}

// addMFAUser seeds a user whose TOTP secret is stored the way HandleVerifyMFA
// stores it (encrypted with the SSH service key) and returns the plaintext secret.
func (rig *authRig) addMFAUser(t *testing.T, username, passwordHash string) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "GoaCore", AccountName: username})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	enc, err := rig.h.SSHService.EncryptData(key.Secret())
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	rig.fake.addUser(&authFakeUser{
		id: 1, passwordHash: passwordHash, mfaEnabled: true, mfaSecret: enc, role: "Admin",
	}, username)
	return key.Secret()
}

// post drives one request through the handler with the current cookie jar, then
// updates the jar from the response exactly like a browser would (a Set-Cookie
// with an empty value / negative MaxAge deletes the cookie).
func (rig *authRig) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.77:40000"
	for _, c := range rig.jar {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	rig.h.HandleLogin(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Value == "" || c.MaxAge < 0 {
			delete(rig.jar, c.Name)
			continue
		}
		rig.jar[c.Name] = c
	}
	return rec
}

// session decodes the session currently held in the jar.
func (rig *authRig) session(t *testing.T) *sessions.Session {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rig.jar {
		req.AddCookie(c)
	}
	sess, _ := rig.store.Get(req, "goacloud-session")
	return sess
}

func (rig *authRig) isAuthenticated(t *testing.T) bool {
	t.Helper()
	auth, _ := rig.session(t).Values["authenticated"].(bool)
	return auth
}

// TestLoginMFA_TwoStepFlow is the regression test for the "no MFA account can log
// in" outage: password step, then code step, then an authenticated session.
func TestLoginMFA_TwoStepFlow(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	secret := rig.addMFAUser(t, "alice", authTestHash(t, password))

	// ── Step 1: credentials ──────────────────────────────────────────────────
	rec := rig.post(t, url.Values{"username": {"alice"}, "password": {password}})
	if rec.Code != http.StatusOK {
		t.Fatalf("step 1: status %d, want 200 (the MFA form)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="mfa_code"`) {
		t.Fatal("step 1: the MFA form was not rendered")
	}
	if strings.Contains(body, `name="password"`) {
		t.Fatal("step 1: the MFA step still carries a password field — the password must never travel back to the browser")
	}
	if strings.Contains(body, password) {
		t.Fatal("step 1: the cleartext password appears in the served HTML")
	}
	if rig.isAuthenticated(t) {
		t.Fatal("step 1: the session is authenticated BEFORE the TOTP code was verified")
	}

	// ── Step 2: TOTP code only, exactly what the served form posts ───────────
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec = rig.post(t, url.Values{"mfa_code": {code}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("step 2: status %d (%s), want 303 — a valid MFA login must succeed",
			rec.Code, strings.TrimSpace(firstLine(rec.Body.String())))
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("step 2: redirect to %q, want /", loc)
	}

	sess := rig.session(t)
	if auth, _ := sess.Values["authenticated"].(bool); !auth {
		t.Fatal("step 2: session is not authenticated after a valid code")
	}
	if user, _ := sess.Values["username"].(string); user != "alice" {
		t.Fatalf("step 2: session username = %q, want alice", user)
	}
	if _, pending := sess.Values[sessionMFAPendingUser]; pending {
		t.Fatal("step 2: the pre-auth state survived the login — it must be consumed")
	}
}

// TestLoginMFA_WrongCodeIsRejected: the code step is a real gate, and a failure is
// counted by the rate limiter (but the pending state survives so the user can retry).
func TestLoginMFA_WrongCodeIsRejected(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	secret := rig.addMFAUser(t, "alice", authTestHash(t, password))

	rig.post(t, url.Values{"username": {"alice"}, "password": {password}})

	valid, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec := rig.post(t, url.Values{"mfa_code": {firstInvalidCode(t, valid, secret)}})
	if rec.Code != http.StatusOK {
		t.Fatalf("wrong code: status %d, want 200 (form re-rendered with an error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Code MFA invalide") {
		t.Error("wrong code: the error message is missing")
	}
	if rig.isAuthenticated(t) {
		t.Fatal("wrong code: the session was authenticated anyway")
	}

	// The retry still works with a good code — the pending state is not burned.
	rec = rig.post(t, url.Values{"mfa_code": {valid}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("retry with a valid code: status %d, want 303", rec.Code)
	}
}

// TestLoginMFA_FailedCredentialStepBurnsPendingState: a half-finished login must
// not outlive the step that opened it. Left in place, the "password already
// verified" marker stayed redeemable for its whole 5-minute TTL — a bare TOTP code
// could then complete a login the browser had just failed to start again.
func TestLoginMFA_FailedCredentialStepBurnsPendingState(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	secret := rig.addMFAUser(t, "alice", authTestHash(t, password))

	rig.post(t, url.Values{"username": {"alice"}, "password": {password}})
	if _, pending := rig.session(t).Values[sessionMFAPendingUser]; !pending {
		t.Fatal("step 1 did not open a pre-auth state")
	}

	rig.post(t, url.Values{"username": {"alice"}, "password": {"wrong"}})
	if _, pending := rig.session(t).Values[sessionMFAPendingUser]; pending {
		t.Fatal("the pre-auth state survived a FAILED credentials step")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rig.post(t, url.Values{"mfa_code": {code}})
	if rig.isAuthenticated(t) {
		t.Fatal("a code alone finished a login whose password step had just failed")
	}
}

// TestLoginMFA_ExhaustedAttemptsBurnPendingState: retries are allowed inside the
// window, but once the limiter blocks the IP the failure is definitive and the
// half-login is consumed rather than left redeemable until its TTL expires.
func TestLoginMFA_ExhaustedAttemptsBurnPendingState(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	secret := rig.addMFAUser(t, "alice", authTestHash(t, password))

	rig.post(t, url.Values{"username": {"alice"}, "password": {password}})

	valid, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	wrong := firstInvalidCode(t, valid, secret)
	for i := 0; i < 5; i++ {
		if rec := rig.post(t, url.Values{"mfa_code": {wrong}}); rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status %d, want 200", i+1, rec.Code)
		}
	}
	if _, pending := rig.session(t).Values[sessionMFAPendingUser]; pending {
		t.Fatal("the pre-auth state survived the last allowed attempt — it stays replayable for the rest of its TTL")
	}
}

// TestLoginMFA_CodeWithoutPendingStateRejected: knowing (or brute-forcing) a code
// is useless without having passed the password step first — the identity lives
// only in the server-side pre-auth state.
func TestLoginMFA_CodeWithoutPendingStateRejected(t *testing.T) {
	rig := newAuthRig(t)
	secret := rig.addMFAUser(t, "alice", authTestHash(t, "correct horse battery"))

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	rec := rig.post(t, url.Values{"mfa_code": {code}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (login form with an error)", rec.Code)
	}
	if rig.isAuthenticated(t) {
		t.Fatal("a TOTP code alone authenticated a session without the password step")
	}
}

// TestLoginMFA_PendingStateExpires: the pre-auth state is short-lived. Past its
// TTL the user starts over instead of holding a permanently redeemable half-login.
func TestLoginMFA_PendingStateExpires(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	secret := rig.addMFAUser(t, "alice", authTestHash(t, password))

	rig.post(t, url.Values{"username": {"alice"}, "password": {password}})

	// Rewind the expiry stored in the cookie to just past the TTL.
	sess := rig.session(t)
	sess.Values[sessionMFAPendingExp] = time.Now().Add(-time.Second).Unix()
	rec := httptest.NewRecorder()
	if err := sess.Save(httptest.NewRequest(http.MethodGet, "/", nil), rec); err != nil {
		t.Fatalf("re-save session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		rig.jar[c.Name] = c
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	out := rig.post(t, url.Values{"mfa_code": {code}})
	if out.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (login form with an error)", out.Code)
	}
	if !strings.Contains(out.Body.String(), "expirée") {
		t.Error("the expired pre-auth state should be reported to the user")
	}
	if rig.isAuthenticated(t) {
		t.Fatal("an expired pre-auth state still produced an authenticated session")
	}
}

// TestLogin_NoMFA_StampsRevocationEpoch: the plain login path still works and the
// session carries the user's current revocation epoch, which AuthMiddleware
// re-checks on every request (session revocation).
func TestLogin_NoMFA_StampsRevocationEpoch(t *testing.T) {
	rig := newAuthRig(t)
	const password = "correct horse battery"
	rig.fake.addUser(&authFakeUser{
		id: 7, passwordHash: authTestHash(t, password), sessionEpoch: 3, role: "Admin",
	}, "bob")

	rec := rig.post(t, url.Values{"username": {"bob"}, "password": {password}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303", rec.Code)
	}
	sess := rig.session(t)
	if auth, _ := sess.Values["authenticated"].(bool); !auth {
		t.Fatal("session is not authenticated after a valid password")
	}
	if epoch, _ := sess.Values[sessionEpochKey].(int); epoch != 3 {
		t.Fatalf("session epoch = %d, want 3 (the value in force at login)", epoch)
	}
}

// TestLogin_WrongPasswordDoesNotStartMFAChallenge: a bad password must not open a
// pre-auth state (that would turn the MFA step into a password oracle).
func TestLogin_WrongPasswordDoesNotStartMFAChallenge(t *testing.T) {
	rig := newAuthRig(t)
	rig.addMFAUser(t, "alice", authTestHash(t, "correct horse battery"))

	rec := rig.post(t, url.Values{"username": {"alice"}, "password": {"wrong"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Identifiants invalides") {
		t.Error("expected the generic invalid-credentials message")
	}
	if _, pending := rig.session(t).Values[sessionMFAPendingUser]; pending {
		t.Fatal("a wrong password opened an MFA pre-auth state")
	}
}

// TestLogin_RateLimitBlocksAfterFiveFailures: the limiter is wired on /login and
// the peer address is the key (no forged header can escape it — see the middleware
// tests). Five wrong passwords then get a 429.
func TestLogin_RateLimitBlocksAfterFiveFailures(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "correct horse battery"), role: "Admin"}, "bob")

	for i := 0; i < 5; i++ {
		if rec := rig.post(t, url.Values{"username": {"bob"}, "password": {"nope"}}); rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status %d, want 200", i+1, rec.Code)
		}
	}
	if rec := rig.post(t, url.Values{"username": {"bob"}, "password": {"nope"}}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: status %d, want 429", rec.Code)
	}
}

// TestLoginForm_PasswordManagerFriendly pins the form finishings: the browser and
// password managers need the autocomplete hints and a focusable reveal button, and
// the old "clear the field on first focus" script (which wiped autofilled values)
// must stay gone. The absence of "<no value>" also proves every key the template
// reads is present in the data map — that placeholder is what the clearing script
// was hiding.
func TestLoginForm_PasswordManagerFriendly(t *testing.T) {
	rig := newAuthRig(t)
	rig.fake.addUser(&authFakeUser{id: 1, passwordHash: authTestHash(t, "pw"), role: "Admin"}, "bob")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	rig.h.HandleLogin(rec, req)

	body := rec.Body.String()
	for _, want := range []string{`autocomplete="username"`, `autocomplete="current-password"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login form is missing %s", want)
		}
	}
	for _, unwanted := range []string{`tabindex="-1"`, "js-clear-on-focus", "<no value>"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("login form still contains %q", unwanted)
		}
	}
}

// authTestHash bcrypts a password (MinCost: these tests hash a lot and only the
// compare semantics matter here — the production cost is pinned by
// auth_antienum_test.go).
func authTestHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
