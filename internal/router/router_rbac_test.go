package router

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
	"goacore/internal/config"
	"goacore/internal/handlers"
	appMiddleware "goacore/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fake in-process database/sql driver.
//
// The RBAC barrier (AuthMiddleware → AdminOnly → RequireAdmin) reads the role
// from the DB, NOT from the session: each runs `SELECT role FROM users WHERE
// username = ?`, and AuthMiddleware also runs `SELECT COUNT(*) FROM users`. To
// exercise the real router/middleware without a live MySQL — and WITHOUT adding
// any external dependency (no sqlmock) — we register a tiny driver built only on
// the stdlib `database/sql/driver`. It answers exactly those two queries from an
// in-memory role table, so the role a request "is" is whatever we seed here.
// ─────────────────────────────────────────────────────────────────────────────

// roleTable maps username → role for the fake driver. Guarded by a mutex because
// database/sql may dial connections from its own goroutines.
var (
	roleMu    sync.RWMutex
	roleTable = map[string]string{}
)

func setRole(username, role string) {
	roleMu.Lock()
	defer roleMu.Unlock()
	roleTable[username] = role
}

func lookupRole(username string) (string, bool) {
	roleMu.RLock()
	defer roleMu.RUnlock()
	r, ok := roleTable[username]
	return r, ok
}

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }

type fakeConn struct{}

func (fakeConn) Prepare(query string) (driver.Stmt, error) { return fakeStmt{query: query}, nil }
func (fakeConn) Close() error                              { return nil }
func (fakeConn) Begin() (driver.Tx, error)                 { return nil, fmt.Errorf("no tx") }

type fakeStmt struct{ query string }

func (s fakeStmt) Close() error  { return nil }
func (s fakeStmt) NumInput() int { return -1 } // let database/sql skip arg-count checks

// execLog records the statements the router's middleware/handlers write, so a test
// can assert on what actually landed in the database (the audit trail, in practice).
var (
	execMu  sync.Mutex
	execLog []fakeExec
)

type fakeExec struct {
	query string
	args  []driver.Value
}

// execsContaining returns the recorded statements whose (normalised) text contains
// fragment.
func execsContaining(fragment string) []fakeExec {
	execMu.Lock()
	defer execMu.Unlock()
	var out []fakeExec
	for _, e := range execLog {
		if strings.Contains(e.query, fragment) {
			out = append(out, e)
		}
	}
	return out
}

func resetExecLog() {
	execMu.Lock()
	defer execMu.Unlock()
	execLog = nil
}

func (s fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	execMu.Lock()
	execLog = append(execLog, fakeExec{query: normalize(s.query), args: args})
	execMu.Unlock()
	return driver.RowsAffected(0), nil
}

func (s fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	q := normalize(s.query)
	switch {
	case strings.Contains(q, "select count(*) from users"):
		// AuthMiddleware: a nonzero count means "users exist" → don't redirect to /setup.
		return &fakeRows{cols: []string{"count"}, vals: [][]driver.Value{{int64(2)}}}, nil
	case strings.Contains(q, "select role from users where username"):
		username := ""
		if len(args) > 0 {
			if s, ok := args[0].(string); ok {
				username = s
			}
		}
		if role, ok := lookupRole(username); ok {
			return &fakeRows{cols: []string{"role"}, vals: [][]driver.Value{{role}}}, nil
		}
		// Unknown user → no rows, which Scan surfaces as sql.ErrNoRows. This is the
		// "user was deleted" path AuthMiddleware/AdminOnly treat as access-denied.
		return &fakeRows{cols: []string{"role"}, vals: nil}, nil
	default:
		// Any other query the real handlers might issue: return empty rows rather
		// than erroring, so an Admin request that slips past RBAC into a handler
		// fails on missing services (→ Recoverer 500), never on the DB layer — the
		// RBAC assertions below only care that it is NOT 403/login-redirect.
		return &fakeRows{cols: []string{}, vals: nil}, nil
	}
}

func normalize(q string) string {
	return strings.ToLower(strings.Join(strings.Fields(q), " "))
}

type fakeRows struct {
	cols []string
	vals [][]driver.Value
	pos  int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.pos])
	r.pos++
	return nil
}

var registerOnce sync.Once

func openFakeDB(t *testing.T) *sql.DB {
	t.Helper()
	registerOnce.Do(func() { sql.Register("rbacfake", fakeDriver{}) })
	db, err := sql.Open("rbacfake", "rbac")
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	return db
}

// ─────────────────────────────────────────────────────────────────────────────
// Test rig: the REAL router.New, wired with a minimal handler and the fake DB.
// ─────────────────────────────────────────────────────────────────────────────

const testSessionKey = "00000000000000000000000000000000" // 32 bytes, deterministic

func newTestStore() *sessions.CookieStore {
	return sessions.NewCookieStore([]byte(testSessionKey))
}

// newTestRouter builds the production router with a handler whose only populated
// fields are the ones the RBAC middleware and the router wiring touch. Proxmox is
// marked configured so the OnboardingGate is a no-op and never masks the RBAC
// result with a 303/409 of its own.
func newTestRouter(t *testing.T, store *sessions.CookieStore, db *sql.DB) http.Handler {
	t.Helper()
	cfg := &config.Config{
		// Non-empty triplet ⇒ ProxmoxConfigured() == true ⇒ gate is a no-op.
		ProxmoxURL:         "https://proxmox.example.test:8006",
		ProxmoxNode:        "node",
		ProxmoxTokenID:     "id",
		ProxmoxTokenSecret: "secret",
	}
	h := &handlers.Handler{
		DB:           db,
		SessionStore: store,
		Config:       cfg,
		ConfigStore:  config.NewConfigStore(cfg, nil),
	}
	if !h.ConfigStore.ProxmoxConfigured() {
		t.Fatal("test setup: ConfigStore should report Proxmox configured")
	}
	return New(h, store, db, false)
}

// sessionCookie produces a signed session cookie for the given username carrying
// authenticated=true and a known CSRF token, using the SAME CookieStore/key the
// router uses — so the request is indistinguishable from a real logged-in user.
func sessionCookie(t *testing.T, store *sessions.CookieStore, username, csrfToken string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	// store.New on a request with no existing cookie yields a fresh session.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = username
	sess.Values["csrf_token"] = csrfToken
	if err := sess.Save(req, rec); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goacloud-session" {
			return c
		}
	}
	t.Fatal("no goacloud-session cookie produced")
	return nil
}

type route struct {
	method string
	path   string
}

// The sensitive routes are split into two groups by WHO actually enforces the 403 for a
// Viewer — so the test's guarantee is honest about its scope. The split was derived by
// reading each handler: a route is "router-only" iff its handler does NOT itself call
// middleware.RequireAdmin; it is "defense-in-depth" iff the handler ALSO re-checks
// RequireAdmin inline. (Both groups are wired inside the AdminOnly router group in
// router.go — that is not in question. What differs is what a green test PROVES.)
//
// routerOnlyDefended: the ONLY admin barrier for these is the AdminOnly router group.
// Their handlers contain no inline RequireAdmin, so if any of these were moved out of the
// AdminOnly group (into the authenticated/Viewer group), a Viewer would reach the handler
// and get a non-403 — turning the Viewer test RED. For THESE the assertion is a true
// "router guarantee": move it out of AdminOnly ⇒ test fails.
//
// These are the highest-value targets: a root SSH shell on guests, the SSH key manager,
// Ansible/playbook execution, Proxmox VM control (power/snapshots/console/create), the
// users/audit pages, and the onboarding pages that write infra credentials — all reachable
// by a Viewer the instant the router gate is removed, with nothing behind it.
var routerOnlyDefended = []route{
	// Root SSH shell on guests — the single worst Viewer→shell-root escalation.
	{http.MethodGet, "/console"},
	{http.MethodGet, "/api/ssh/ws"},

	// SSH key manager pages/endpoints served by HandleSSHManager (no inline check).
	{http.MethodGet, "/ssh"},
	{http.MethodPost, "/ssh"},
	{http.MethodGet, "/api/ssh/generate"},
	{http.MethodPost, "/api/ssh/generate"},

	// Ansible landing page (HandleAnsible — no inline check).
	{http.MethodGet, "/ansible"},

	// Proxmox state-changing / sensitive actions (power, snapshots, console, create) —
	// none of these handlers re-check the role, so the router group is their sole gate.
	{http.MethodPost, "/api/proxmox/guest/power"},
	{http.MethodPost, "/api/proxmox/snapshots"},
	{http.MethodDelete, "/api/proxmox/snapshots"},
	{http.MethodPost, "/api/proxmox/snapshots/rollback"},
	{http.MethodGet, "/api/proxmox/console"},
	{http.MethodPost, "/api/proxmox/guest/create"},

	// Onboarding pages with no inline RequireAdmin in the page handler.
	{http.MethodGet, "/onboarding/proxmox"},
	{http.MethodGet, "/onboarding/connexions"},

	// Paramètres hub — Admin-only sections whose GET handler has NO inline RequireAdmin,
	// so the AdminOnly router group is their SOLE barrier: move any of these into the
	// authenticated group and a Viewer reaches the (services/users/proxmox) configuration
	// surface, flipping this test red. NB: /parametres/sauvegarde is deliberately NOT here
	// — its handler (HandleOnboardingChannel) re-checks RequireAdmin inline, so it belongs
	// to defenseInDepth (same handler as /onboarding/canal).
	{http.MethodGet, "/parametres/services"},
	{http.MethodGet, "/parametres/utilisateurs"},
	{http.MethodGet, "/parametres/proxmox"},

	// SOAR outbound tests (HandleDiscordTest / HandleAITest — no inline check).
	{http.MethodPost, "/api/soar/discord/test"},
	{http.MethodPost, "/api/soar/ai/test"},

	// Backups page + user/audit pages (page handlers, no inline check).
	{http.MethodGet, "/backups"},
	{http.MethodGet, "/users"},
	{http.MethodGet, "/audit-logs"},

	// Applications catalogue MUTATIONS. The `apps` table is GLOBAL (no user_id), so
	// each of these rewrites what EVERY user sees — and none of the handlers checks a
	// role, which is precisely why they must never leave the AdminOnly group: a Viewer
	// could otherwise wipe the catalogue, or repoint the "Proxmox" tile at a
	// credential-harvesting page. /api/apps/pin is in this list for the same reason:
	// `UPDATE apps SET is_pinned` has no per-user dimension, so a "favourite" is a
	// change to everyone's dashboard. Move it back to the authenticated group only
	// once pins get their own (user_id, app_id) table.
	{http.MethodGet, "/add"},
	{http.MethodPost, "/add"},
	{http.MethodPost, "/api/apps/pin"},
	{http.MethodPost, "/api/apps/update"},
	{http.MethodPost, "/api/apps/reorder"},
	{http.MethodDelete, "/api/apps/delete"},
}

// defenseInDepth: these handlers ALSO call middleware.RequireAdmin inline. The AdminOnly
// router group AND the inline check each independently return 403 to a Viewer. So a green
// Viewer test here proves "the router gate OR the inline RequireAdmin denied the Viewer" —
// NOT specifically the router gate. Moving one of these out of AdminOnly would NOT turn the
// test red (the handler's own RequireAdmin still 403s). That is acceptable defence in depth,
// but the test must not over-claim a router guarantee for them.
var defenseInDepth = []route{
	// SSH deploy/delete (HandleSSHDeploy / HandleSSHDelete re-check inline).
	{http.MethodPost, "/api/ssh/deploy"},
	{http.MethodDelete, "/api/ssh/delete"},

	// Ansible execution + playbook + schedules (all re-check inline).
	{http.MethodPost, "/api/ansible/run"},
	{http.MethodPost, "/api/ansible/upload"},
	{http.MethodPut, "/api/ansible/playbook"},
	{http.MethodPost, "/api/ansible/schedules"},
	{http.MethodDelete, "/api/ansible/schedules"},
	{http.MethodPost, "/api/ansible/schedules/toggle"},

	// Onboarding write/test/delete APIs (each re-checks inline).
	{http.MethodPost, "/onboarding/proxmox"},
	{http.MethodPost, "/api/onboarding/proxmox/test"},
	{http.MethodPost, "/api/onboarding/proxmox/import-env"},
	{http.MethodPost, "/api/onboarding/proxmox/delete"},
	{http.MethodPost, "/onboarding/wazuh"},
	{http.MethodPost, "/api/onboarding/wazuh/test"},
	{http.MethodPost, "/onboarding/ai"},
	{http.MethodPost, "/api/onboarding/ai/delete"},
	{http.MethodPost, "/onboarding/discord"},
	{http.MethodGet, "/onboarding/canal"},
	// /parametres/sauvegarde is the hub alias of /onboarding/canal — SAME handler
	// (HandleOnboardingChannel), which re-checks RequireAdmin inline ⇒ defence in depth.
	{http.MethodGet, "/parametres/sauvegarde"},
	{http.MethodPost, "/api/onboarding/canal/provision"},
	{http.MethodGet, "/api/onboarding/canal/installer.sh"},
	{http.MethodGet, "/api/onboarding/canal/helper.sh"},
	{http.MethodPost, "/api/onboarding/canal/delete"},

	// Backups create/test/settings (each re-checks inline).
	{http.MethodPost, "/api/backups/create"},
	{http.MethodPost, "/api/backups/test"},
	{http.MethodPost, "/api/backups/settings"},
	{http.MethodPost, "/api/backups/target-settings"},
	{http.MethodGet, "/api/backups/available-guests"},
	{http.MethodPost, "/api/backups/targets"},

	// SOAR config write (HandleSoarConfig re-checks inline on its POST arm).
	{http.MethodPost, "/api/soar/config"},

	// User management writes (add/delete/update/reset-mfa re-check inline).
	{http.MethodPost, "/api/users/add"},
	{http.MethodPost, "/api/users/delete"},
	{http.MethodPost, "/api/users/update"},
	// Disables another account's second factor and revokes its sessions — as
	// privileged as a password reset, hence the same gate.
	{http.MethodPost, "/api/users/reset-mfa"},
}

// sensitiveRoutes is the union of both groups: every route below MUST 403 a Viewer,
// regardless of which layer enforces it. The Admin / unauthenticated tests iterate this
// union; the Viewer test runs both groups but documents the per-group guarantee.
var sensitiveRoutes = append(append([]route{}, routerOnlyDefended...), defenseInDepth...)

const csrfTok = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func doRequest(t *testing.T, router http.Handler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	// Satisfy the global CSRF middleware on state-changing methods. The token here
	// MATCHES the one baked into the session cookie, so a CSRF rejection can never
	// be what masks the RBAC result we are actually asserting on.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.Header.Set("X-CSRF-Token", csrfTok)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestRBAC_ViewerDeniedOnSensitiveRoutes is the core invariant: every sensitive route
// rejects a logged-in Viewer with 403 and never lets the request reach its handler.
//
// It runs in two sub-groups whose guarantees differ — and the assertions are honest
// about that difference:
//
//   - routerOnly: the AdminOnly router group is the SOLE admin barrier (these handlers
//     have no inline RequireAdmin). For these, a 403 proves the ROUTER gate is doing the
//     work: move the route out of the AdminOnly group and a Viewer reaches the handler,
//     turning this test RED. This is a genuine router guarantee.
//
//   - defenseInDepth: the handler ALSO calls RequireAdmin inline, so a 403 here proves
//     only that "the router gate OR the inline RequireAdmin" denied the Viewer — not the
//     router gate specifically. Moving such a route out of AdminOnly would NOT turn this
//     test red (the inline check still 403s). The test still asserts the Viewer is denied
//     (the property we care about), it just does not claim to pin the router layer for it.
func TestRBAC_ViewerDeniedOnSensitiveRoutes(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("viewer", "Viewer")
	cookie := sessionCookie(t, store, "viewer", csrfTok)

	// routerOnly: a 403 here is a ROUTER guarantee — moving the route out of AdminOnly
	// makes a Viewer reach the (unguarded) handler, flipping this assertion to a failure.
	t.Run("routerOnly", func(t *testing.T) {
		for _, rt := range routerOnlyDefended {
			rt := rt
			t.Run(rt.method+" "+rt.path, func(t *testing.T) {
				rr := doRequest(t, router, rt.method, rt.path, cookie)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("Viewer on %s %s: got %d, want 403 — handler has no inline RequireAdmin, so this means the AdminOnly router gate is missing (Viewer reached the handler)",
						rt.method, rt.path, rr.Code)
				}
			})
		}
	})

	// defenseInDepth: a 403 here proves the router gate OR the handler's inline
	// RequireAdmin denied the Viewer — defence in depth, not a router-specific guarantee.
	t.Run("defenseInDepth", func(t *testing.T) {
		for _, rt := range defenseInDepth {
			rt := rt
			t.Run(rt.method+" "+rt.path, func(t *testing.T) {
				rr := doRequest(t, router, rt.method, rt.path, cookie)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("Viewer on %s %s: got %d, want 403 — neither the AdminOnly router gate NOR the inline RequireAdmin blocked the Viewer",
						rt.method, rt.path, rr.Code)
				}
			})
		}
	})
}

// TestRBAC_AdminPassesRBACOnSensitiveRoutes proves the routes are genuinely gated
// by the ROLE and not blanket-blocked: an Admin clears AuthMiddleware+AdminOnly on
// every sensitive route. We assert the response is NOT 403 and NOT a redirect to
// /login — i.e. RBAC let the request through to the handler (which may then 500 on
// the intentionally-nil services; that still proves the barrier opened for Admin).
// Without this counterpart, a middleware that 403'd EVERYONE would falsely satisfy
// the Viewer test, so this guards against an over-broad (and useless) gate.
func TestRBAC_AdminPassesRBACOnSensitiveRoutes(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("admin", "Admin")
	cookie := sessionCookie(t, store, "admin", csrfTok)

	for _, rt := range sensitiveRoutes {
		rt := rt
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rr := doRequest(t, router, rt.method, rt.path, cookie)
			if rr.Code == http.StatusForbidden {
				t.Fatalf("Admin on %s %s: got 403 — RBAC wrongly blocks an Admin (route not gated by ROLE)",
					rt.method, rt.path)
			}
			if rr.Code == http.StatusSeeOther {
				if loc := rr.Header().Get("Location"); loc == "/login" {
					t.Fatalf("Admin on %s %s: redirected to /login — Admin treated as unauthenticated",
						rt.method, rt.path)
				}
			}
		})
	}
}

// TestRBAC_UnauthenticatedRedirectedToLogin: an anonymous request to a sensitive route
// is blocked before reaching the handler. The blocking LAYER depends on the method, and
// the assertion is honest about that:
//
//   - GET (safe method): CSRF validation is skipped, so the request flows into
//     AuthMiddleware, which bounces the anonymous caller with 303→/login (or /setup when
//     no users exist). For GETs this test genuinely pins the AUTH redirect.
//
//   - POST/PUT/DELETE (state-changing): the global CSRF middleware runs BEFORE
//     AuthMiddleware. With no session cookie it mints a fresh token, our request carries a
//     non-matching header token, and CSRF returns 403 — so the request is rejected by CSRF
//     before auth is ever consulted. For these the "blocked" outcome is the CSRF 403, NOT
//     the auth redirect; both mean the handler never ran, which is what we assert.
//
// We therefore require GETs to redirect to /login (or /setup) and accept either a redirect
// or a CSRF 403 for non-GET methods.
func TestRBAC_UnauthenticatedRedirectedToLogin(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	isSafe := func(m string) bool { return m == http.MethodGet || m == http.MethodHead }

	for _, rt := range sensitiveRoutes {
		rt := rt
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rr := doRequest(t, router, rt.method, rt.path, nil)
			if rr.Code == http.StatusSeeOther {
				if loc := rr.Header().Get("Location"); loc != "/login" && loc != "/setup" {
					t.Fatalf("anon on %s %s: 303 to %q, want /login or /setup", rt.method, rt.path, loc)
				}
				return
			}
			if rr.Code == http.StatusForbidden {
				// A 403 is the CSRF block that fires before auth on state-changing methods.
				// For a safe GET, CSRF is skipped, so a 403 would mean something else blocked
				// it (or auth failed to redirect) — that is not the expected auth bounce.
				if isSafe(rt.method) {
					t.Fatalf("anon GET %s: got 403 (CSRF is skipped for safe methods) — expected a 303→/login auth redirect", rt.path)
				}
				return // CSRF block on a state-changing anon request — handler not reached.
			}
			t.Fatalf("anon on %s %s: got %d, expected to be blocked before the handler (303→/login for GET, 303 or CSRF 403 for non-GET)",
				rt.method, rt.path, rr.Code)
		})
	}
}

// TestRBAC_AdminOnlyMiddlewareDirect exercises the AdminOnly middleware in
// isolation (independent of the router wiring) to pin its contract: Admin → next
// runs; Viewer/empty/unknown → 403 and next NEVER runs.
func TestRBAC_AdminOnlyMiddlewareDirect(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)

	setRole("amid", "Admin")
	setRole("vmid", "Viewer")

	cases := []struct {
		name     string
		username string
		wantNext bool
		wantCode int
	}{
		{"admin passes", "amid", true, http.StatusOK},
		{"viewer blocked", "vmid", false, http.StatusForbidden},
		{"unknown user blocked", "ghost", false, http.StatusForbidden},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var nextRan bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextRan = true
				w.WriteHeader(http.StatusOK)
			})
			mw := appMiddleware.AdminOnly(store, db, next)

			cookie := sessionCookie(t, store, tc.username, csrfTok)
			req := httptest.NewRequest(http.MethodGet, "/api/users/add", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			mw.ServeHTTP(rr, req)

			if nextRan != tc.wantNext {
				t.Fatalf("%s: nextRan=%v want %v", tc.name, nextRan, tc.wantNext)
			}
			if rr.Code != tc.wantCode {
				t.Fatalf("%s: code=%d want %d", tc.name, rr.Code, tc.wantCode)
			}
		})
	}
}

// TestRBAC_RequireAdminInline pins the inline RequireAdmin helper used by handlers
// that double-check the role: it returns true only for Admin and writes 403+false
// for a Viewer or an unknown user. A regression that made it return true for a
// Viewer would silently re-open every handler relying on it.
func TestRBAC_RequireAdminInline(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)

	setRole("ra_admin", "Admin")
	setRole("ra_viewer", "Viewer")

	cases := []struct {
		name     string
		username string
		want     bool
		wantCode int
	}{
		{"admin", "ra_admin", true, http.StatusOK}, // no body written ⇒ recorder stays 200
		{"viewer", "ra_viewer", false, http.StatusForbidden},
		{"unknown", "ra_ghost", false, http.StatusForbidden},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cookie := sessionCookie(t, store, tc.username, csrfTok)
			req := httptest.NewRequest(http.MethodPost, "/api/users/add", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()

			got := appMiddleware.RequireAdmin(rr, req, store, db)
			if got != tc.want {
				t.Fatalf("%s: RequireAdmin=%v want %v", tc.name, got, tc.want)
			}
			if rr.Code != tc.wantCode {
				t.Fatalf("%s: code=%d want %d", tc.name, rr.Code, tc.wantCode)
			}
		})
	}
}

// TestRBAC_ViewerCanReachReadOnlySurface is the negative control for the Viewer
// test: a Viewer is NOT blanket-403'd — read-only routes in the authenticated
// group stay reachable (no 403). This ensures the Viewer-denial test above is
// detecting the ROLE gate specifically, not a global lockout. We only check the
// routes are not 403/login; the handlers may 500 on nil services.
func TestRBAC_ViewerCanReachReadOnlySurface(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("ro_viewer", "Viewer")
	cookie := sessionCookie(t, store, "ro_viewer", csrfTok)

	// Representative routes in the authenticated (non-admin) group a Viewer MUST be able
	// to reach: /api/me, plus the self-service Paramètres sections (profil, securite) and
	// the hub index. None carry AdminOnly; putting one behind it by mistake would lock a
	// Viewer out of their own profile/2FA — this control catches that regression.
	selfService := []string{"/api/me", "/parametres", "/parametres/profil", "/parametres/securite"}
	for _, path := range selfService {
		rr := doRequest(t, router, http.MethodGet, path, cookie)
		if rr.Code == http.StatusForbidden {
			t.Fatalf("Viewer on GET %s: got 403 — self-service surface wrongly gated as admin-only", path)
		}
		if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == "/login" {
			t.Fatalf("Viewer on GET %s: bounced to /login — authenticated Viewer treated as anon", path)
		}
	}

	// Self-service POST mutations a Viewer MUST also reach (editing their OWN profile):
	// these are wired in the authenticated group, NOT behind AdminOnly. Mistakenly gating
	// them admin-only would lock a Viewer out of changing their own password / GitHub URL.
	// We assert only "neither 403 nor /login redirect": the handler may then 4xx/3xx on the
	// empty body or the nil-services fake DB, which still proves RBAC let the Viewer in.
	// (doRequest sets the matching X-CSRF-Token, so a CSRF rejection cannot mask the result.)
	selfServicePosts := []route{
		{http.MethodPost, "/api/profile/update"},
		{http.MethodPost, "/api/profile/github"},
	}
	for _, rt := range selfServicePosts {
		rr := doRequest(t, router, rt.method, rt.path, cookie)
		if rr.Code == http.StatusForbidden {
			t.Fatalf("Viewer on %s %s: got 403 — self-service mutation wrongly gated as admin-only", rt.method, rt.path)
		}
		if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == "/login" {
			t.Fatalf("Viewer on %s %s: bounced to /login — authenticated Viewer treated as anon", rt.method, rt.path)
		}
	}
}

// TestRouter_PublicRoutesNeedNoSession pins the routes that MUST answer without a
// session cookie. Each is public for a concrete reason, and each would be broken —
// silently, in a way only production shows — by being tucked into an auth group:
//
//   - /healthz, /readyz: a Docker HEALTHCHECK, Traefik or an orchestrator probes
//     them with no cookie. Behind AuthMiddleware they would answer 303 → /login,
//     which most probes read as "alive", making the health check meaningless.
//   - /canal/installer.sh: the admin runs the curl from a Proxmox root shell that
//     has no session. Behind the gate, curl -L follows the 303 to /login and gets
//     the login PAGE with a 200 — so `curl -f` never trips, the HTML lands in the
//     script file, and `sudo bash` runs it. Authentication is a single-use token.
//
// The assertion is deliberately "not an auth bounce" rather than a status code:
// the installer route legitimately answers 403 to a token-less request.
func TestRouter_PublicRoutesNeedNoSession(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	for _, path := range []string{"/healthz", "/readyz", "/canal/installer.sh"} {
		path := path
		t.Run(path, func(t *testing.T) {
			rr := doRequest(t, router, http.MethodGet, path, nil)
			if rr.Code == http.StatusSeeOther {
				t.Fatalf("anon GET %s: 303 to %q — the route is behind an auth group and no probe/curl can use it",
					path, rr.Header().Get("Location"))
			}
			if rr.Code == http.StatusNotFound {
				t.Fatalf("anon GET %s: 404 — the route is not registered", path)
			}
		})
	}
}

// TestRouter_ProbesReportHealthy checks the probes are wired to the real handlers
// (not merely registered): with a working DB they answer 200 and the agreed body.
func TestRouter_ProbesReportHealthy(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	for _, tc := range []struct{ path, want string }{{"/healthz", `"status":"ok"`}, {"/readyz", `"status":"ready"`}} {
		rr := doRequest(t, router, http.MethodGet, tc.path, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d, want 200", tc.path, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), tc.want) {
			t.Fatalf("GET %s: body %q does not contain %s", tc.path, rr.Body.String(), tc.want)
		}
	}
}

// TestRouter_LogoutAllIsSelfService: revoking every session of the CALLER acts on
// the caller's own account only, so it belongs to the authenticated group. Gating
// it admin-only would deny a Viewer the one remedy they have for a stolen cookie.
func TestRouter_LogoutAllIsSelfService(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("la_viewer", "Viewer")
	rr := doRequest(t, router, http.MethodPost, "/logout-all", sessionCookie(t, store, "la_viewer", csrfTok))

	if rr.Code == http.StatusNotFound {
		t.Fatal("POST /logout-all: 404 — the handler exists but is not routed")
	}
	if rr.Code == http.StatusForbidden {
		t.Fatal("POST /logout-all: 403 — a Viewer must be able to revoke their OWN sessions")
	}
	// Success path: the epoch is bumped and the caller is sent back to /login.
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/login" {
		t.Fatalf("POST /logout-all: got %d → %q, want 303 → /login", rr.Code, rr.Header().Get("Location"))
	}
}

// TestRouter_AuditTrailCoversTheAdminGroup proves the AuditTrail middleware is
// mounted on the Admin-only group — and mounted BEFORE AdminOnly.
//
// The order is the point. Behind AdminOnly, a Viewer probing an admin route is
// rejected before the middleware ever runs and the attempt leaves no trace at all;
// in front of it, the same attempt is recorded as a refusal. That is exactly the
// event an operator needs to see in /audit-logs.
//
// The middleware only records state-changing methods (reads are the bulk of the
// traffic and would drown the trail), and only "METHOD /path" + outcome — never the
// query string or the body, which carry TOTP codes, tokens and private keys.
func TestRouter_AuditTrailCoversTheAdminGroup(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("audit_admin", "Admin")
	setRole("audit_viewer", "Viewer")

	// A REFUSED admin attempt must be recorded (middleware in front of AdminOnly).
	resetExecLog()
	doRequest(t, router, http.MethodPost, "/api/users/add", sessionCookie(t, store, "audit_viewer", csrfTok))
	entries := execsContaining("insert into audit_logs")
	if len(entries) == 0 {
		t.Fatal("a Viewer POSTing /api/users/add left NO audit entry — AuditTrail is missing, or mounted behind AdminOnly")
	}
	// args: user_id, username, action, details, ip_address
	last := entries[len(entries)-1]
	if got := fmt.Sprint(last.args[1]); got != "audit_viewer" {
		t.Fatalf("audit entry attributed to %q, want audit_viewer", got)
	}
	if got := fmt.Sprint(last.args[2]); got != "POST /api/users/add" {
		t.Fatalf("audit action = %q, want \"POST /api/users/add\"", got)
	}
	if got := fmt.Sprint(last.args[3]); !strings.Contains(got, "403") {
		t.Fatalf("audit outcome = %q, want the 403 refusal to be visible", got)
	}

	// An ADMIN mutation is recorded too — the trail is the net under the whole group.
	resetExecLog()
	doRequest(t, router, http.MethodPost, "/api/apps/reorder", sessionCookie(t, store, "audit_admin", csrfTok))
	if len(execsContaining("insert into audit_logs")) == 0 {
		t.Fatal("an Admin POST on /api/apps/reorder left no audit entry")
	}

	// Reads are NOT recorded: /audit-logs would become unreadable within a day.
	resetExecLog()
	doRequest(t, router, http.MethodGet, "/users", sessionCookie(t, store, "audit_admin", csrfTok))
	if n := len(execsContaining("insert into audit_logs")); n != 0 {
		t.Fatalf("a GET produced %d audit entries — only state-changing methods must be recorded", n)
	}

	// A route OUTSIDE the admin group is not audited by this middleware: the
	// authenticated group carries no infra-sensitive mutation.
	resetExecLog()
	doRequest(t, router, http.MethodPost, "/api/profile/github", sessionCookie(t, store, "audit_viewer", csrfTok))
	if n := len(execsContaining("insert into audit_logs")); n != 0 {
		t.Fatalf("a self-service POST produced %d middleware audit entries — AuditTrail is mounted too widely", n)
	}
}

// TestRouter_AuditTrailRecordsNoSecret pins the invariant that makes the trail safe
// to read all day: the recorded action is the PATH only. A query string carries
// tokens and one-time codes, and /audit-logs is a page an operator leaves open.
func TestRouter_AuditTrailRecordsNoSecret(t *testing.T) {
	store := newTestStore()
	db := openFakeDB(t)
	router := newTestRouter(t, store, db)

	setRole("audit_secret", "Admin")
	resetExecLog()

	const secret = "s3cr3t-token-value"
	doRequest(t, router, http.MethodPost, "/api/users/add?token="+secret, sessionCookie(t, store, "audit_secret", csrfTok))

	entries := execsContaining("insert into audit_logs")
	if len(entries) == 0 {
		t.Fatal("no audit entry recorded")
	}
	for _, e := range entries {
		for _, arg := range e.args {
			if strings.Contains(fmt.Sprint(arg), secret) {
				t.Fatalf("the query string leaked into the audit trail: %v", arg)
			}
		}
	}
}

// ensure context import is used even if the stdlib trims it during refactors.
var _ = context.Background
