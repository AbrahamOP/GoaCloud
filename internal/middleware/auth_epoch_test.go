package middleware

import (
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
)

// ─────────────────────────────────────────────────────────────────────────────
// Session revocation (users.session_epoch).
//
// The CookieStore keeps no server-side state, so a 24h cookie stays valid for a
// full day even after the password changed — a stolen one included. AuthMiddleware
// therefore validates, on every request, the epoch baked into the cookie against
// the counter in the users row; bumping the counter retires every older cookie.
//
// The fake driver below answers the ONE statement AuthMiddleware issues, plus the
// COUNT(*) it uses to detect a fresh install — no external dependency, same
// approach as the router RBAC test.
// ─────────────────────────────────────────────────────────────────────────────

type epochUser struct {
	role  string
	epoch int64
}

var (
	epochMu    sync.RWMutex
	epochUsers = map[string]epochUser{}
)

func setEpochUser(username, role string, epoch int64) {
	epochMu.Lock()
	defer epochMu.Unlock()
	epochUsers[username] = epochUser{role: role, epoch: epoch}
}

type epochDriver struct{}

func (epochDriver) Open(string) (driver.Conn, error) { return epochConn{}, nil }

type epochConn struct{}

func (epochConn) Prepare(q string) (driver.Stmt, error) {
	return epochStmt{query: strings.ToLower(strings.Join(strings.Fields(q), " "))}, nil
}
func (epochConn) Close() error              { return nil }
func (epochConn) Begin() (driver.Tx, error) { return nil, io.EOF }

type epochStmt struct{ query string }

func (epochStmt) Close() error                               { return nil }
func (epochStmt) NumInput() int                              { return -1 }
func (epochStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(0), nil }
func (s epochStmt) Query(args []driver.Value) (driver.Rows, error) {
	switch {
	case strings.Contains(s.query, "select count(*) from users"):
		epochMu.RLock()
		n := int64(len(epochUsers))
		epochMu.RUnlock()
		return &epochRows{cols: []string{"count"}, vals: [][]driver.Value{{n}}}, nil

	case strings.Contains(s.query, "select role from users where username"):
		username, _ := args[0].(string)
		var epoch int64
		if len(args) > 1 {
			switch v := args[1].(type) {
			case int64:
				epoch = v
			}
		}
		epochMu.RLock()
		u, ok := epochUsers[username]
		epochMu.RUnlock()
		// The epoch is part of the WHERE clause: a mismatch returns NO row, which is
		// exactly how a revoked session dies.
		if !ok || u.epoch != epoch {
			return &epochRows{cols: []string{"role"}}, nil
		}
		return &epochRows{cols: []string{"role"}, vals: [][]driver.Value{{u.role}}}, nil

	default:
		return &epochRows{}, nil
	}
}

type epochRows struct {
	cols []string
	vals [][]driver.Value
	pos  int
}

func (r *epochRows) Columns() []string { return r.cols }
func (r *epochRows) Close() error      { return nil }
func (r *epochRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.pos])
	r.pos++
	return nil
}

var epochRegisterOnce sync.Once

func openEpochDB(t *testing.T) *sql.DB {
	t.Helper()
	epochRegisterOnce.Do(func() { sql.Register("epochfake", epochDriver{}) })
	db, err := sql.Open("epochfake", "epoch")
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// epochCookie mints an authenticated session cookie carrying a given epoch. When
// withEpoch is false the key is absent altogether, reproducing a cookie issued
// BEFORE the revocation counter existed.
func epochCookie(t *testing.T, store *sessions.CookieStore, username string, epoch int, withEpoch bool) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = username
	if withEpoch {
		sess.Values["session_epoch"] = epoch
	}
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

func runAuth(t *testing.T, store *sessions.CookieStore, db *sql.DB, cookie *http.Cookie) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	var nextRan bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextRan = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/applications", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	AuthMiddleware(store, db, next).ServeHTTP(rec, req)
	return rec, nextRan
}

// TestAuthMiddleware_SessionEpochRevocation: a cookie minted before the counter
// was bumped (password change, MFA disable/reset, "log out everywhere") must stop
// working immediately, while a cookie carrying the current epoch keeps working.
func TestAuthMiddleware_SessionEpochRevocation(t *testing.T) {
	store := sessions.NewCookieStore([]byte("00000000000000000000000000000000"))
	db := openEpochDB(t)
	setEpochUser("alice", "Admin", 0)

	stale := epochCookie(t, store, "alice", 0, true)

	// Before revocation the very same cookie is accepted.
	if _, ran := runAuth(t, store, db, stale); !ran {
		t.Fatal("a current-epoch cookie was rejected")
	}

	// Revoke: bump the counter, as a password change would.
	setEpochUser("alice", "Admin", 1)

	rec, ran := runAuth(t, store, db, stale)
	if ran {
		t.Fatal("a REVOKED cookie still reached the handler — session revocation is not enforced")
	}
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("revoked cookie: got %d → %q, want 303 → /login", rec.Code, rec.Header().Get("Location"))
	}

	// A cookie minted after the bump works again (the user logs back in).
	if _, ran := runAuth(t, store, db, epochCookie(t, store, "alice", 1, true)); !ran {
		t.Fatal("a freshly minted cookie was rejected after the bump")
	}
}

// TestAuthMiddleware_LegacyCookieWithoutEpoch: cookies issued before the migration
// carry no epoch. They must keep working against the default counter (0), so
// deploying the revocation feature does NOT log the whole fleet out — but they die
// like any other at the first bump.
func TestAuthMiddleware_LegacyCookieWithoutEpoch(t *testing.T) {
	store := sessions.NewCookieStore([]byte("00000000000000000000000000000000"))
	db := openEpochDB(t)
	setEpochUser("bob", "Viewer", 0)

	legacy := epochCookie(t, store, "bob", 0, false)
	if _, ran := runAuth(t, store, db, legacy); !ran {
		t.Fatal("a pre-migration cookie was rejected against the default epoch — the deploy would log everyone out")
	}

	setEpochUser("bob", "Viewer", 1)
	if _, ran := runAuth(t, store, db, legacy); ran {
		t.Fatal("a pre-migration cookie survived a revocation bump")
	}
}
