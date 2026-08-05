package handlers

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Minimal in-process database/sql driver for the login/MFA HTTP tests.
//
// The login flow is a DB conversation (read the user row, bump the revocation
// epoch, write the audit trail), so exercising it over real HTTP needs a *sql.DB.
// Like the router RBAC test, we build one on the stdlib database/sql/driver
// rather than adding an external dependency (no sqlmock): it answers exactly the
// handful of statements the auth handlers issue, from an in-memory users table.
//
// Everything is mutex-guarded because database/sql dials from its own goroutines
// and the handlers write the audit log from a goroutine (`go services.LogAudit`).
// ─────────────────────────────────────────────────────────────────────────────

type authFakeUser struct {
	id           int64
	passwordHash string
	mfaEnabled   bool
	mfaSecret    any // string, or nil for SQL NULL
	sessionEpoch int64
	role         string
}

type authFakeExec struct {
	query string
	args  []driver.Value
}

type authFakeDB struct {
	mu    sync.Mutex
	users map[string]*authFakeUser
	execs []authFakeExec
}

func (f *authFakeDB) addUser(u *authFakeUser, username string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[username] = u
}

func (f *authFakeDB) user(username string) (authFakeUser, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[username]
	if !ok {
		return authFakeUser{}, false
	}
	return *u, true
}

// execsMatching returns the recorded statements containing every given fragment
// (lowercase), so a test can assert on what the handler actually wrote.
func (f *authFakeDB) execsMatching(fragments ...string) []authFakeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []authFakeExec
	for _, e := range f.execs {
		match := true
		for _, frag := range fragments {
			if !strings.Contains(e.query, frag) {
				match = false
				break
			}
		}
		if match {
			out = append(out, e)
		}
	}
	return out
}

var (
	authFakeRegOnce sync.Once
	authFakeMu      sync.Mutex
	authFakeDBs     = map[string]*authFakeDB{}
	authFakeSeq     int
)

// newAuthFakeDB returns a *sql.DB backed by a fresh in-memory users table.
func newAuthFakeDB(t *testing.T) (*sql.DB, *authFakeDB) {
	t.Helper()
	authFakeRegOnce.Do(func() { sql.Register("authflowfake", authFakeDriver{}) })

	authFakeMu.Lock()
	authFakeSeq++
	dsn := fmt.Sprintf("authflow-%d", authFakeSeq)
	fake := &authFakeDB{users: map[string]*authFakeUser{}}
	authFakeDBs[dsn] = fake
	authFakeMu.Unlock()

	db, err := sql.Open("authflowfake", dsn)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, fake
}

func authFakeLookup(dsn string) *authFakeDB {
	authFakeMu.Lock()
	defer authFakeMu.Unlock()
	return authFakeDBs[dsn]
}

type authFakeDriver struct{}

func (authFakeDriver) Open(dsn string) (driver.Conn, error) {
	f := authFakeLookup(dsn)
	if f == nil {
		return nil, fmt.Errorf("unknown fake dsn %q", dsn)
	}
	return authFakeConn{f: f}, nil
}

type authFakeConn struct{ f *authFakeDB }

func (c authFakeConn) Prepare(query string) (driver.Stmt, error) {
	return authFakeStmt{f: c.f, query: authFakeNormalize(query)}, nil
}
func (c authFakeConn) Close() error              { return nil }
func (c authFakeConn) Begin() (driver.Tx, error) { return authFakeTx{}, nil }

type authFakeTx struct{}

func (authFakeTx) Commit() error   { return nil }
func (authFakeTx) Rollback() error { return nil }

type authFakeStmt struct {
	f     *authFakeDB
	query string
}

func (s authFakeStmt) Close() error  { return nil }
func (s authFakeStmt) NumInput() int { return -1 } // let database/sql skip arg-count checks

func (s authFakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	s.f.execs = append(s.f.execs, authFakeExec{query: s.query, args: args})

	switch {
	case strings.HasPrefix(s.query, "update users set"):
		// The last argument is the row selector: a username, or an id when the
		// statement ends with "where id = ?" (admin MFA reset).
		selector := fmt.Sprint(args[len(args)-1])
		var u *authFakeUser
		if strings.Contains(s.query, "where id = ?") {
			for _, cand := range s.f.users {
				if fmt.Sprint(cand.id) == selector {
					u = cand
					break
				}
			}
		} else {
			u = s.f.users[selector]
		}
		if u == nil {
			return driver.RowsAffected(0), nil
		}
		if strings.Contains(s.query, "session_epoch = session_epoch + 1") {
			u.sessionEpoch++
		}
		if strings.Contains(s.query, "mfa_enabled = false") {
			u.mfaEnabled = false
			u.mfaSecret = nil
		}
		return driver.RowsAffected(1), nil

	case strings.HasPrefix(s.query, "insert into users"):
		username := fmt.Sprint(args[0])
		if _, exists := s.f.users[username]; exists {
			return nil, fmt.Errorf("duplicate entry %q for key 'username'", username)
		}
		u := &authFakeUser{id: int64(len(s.f.users) + 1), passwordHash: fmt.Sprint(args[1]), role: "Viewer"}
		if len(args) > 2 {
			u.role = fmt.Sprint(args[len(args)-1])
		}
		s.f.users[username] = u
		return driver.RowsAffected(1), nil
	default:
		return driver.RowsAffected(1), nil
	}
}

func (s authFakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()

	argUser := func() string {
		if len(args) > 0 {
			if v, ok := args[0].(string); ok {
				return v
			}
		}
		return ""
	}

	switch {
	case strings.Contains(s.query, "select count(*) from users"):
		return &authFakeRows{cols: []string{"count"}, vals: [][]driver.Value{{int64(len(s.f.users))}}}, nil

	case strings.Contains(s.query, "select password_hash, mfa_enabled, mfa_secret, session_epoch from users where username"):
		u, ok := s.f.users[argUser()]
		if !ok {
			return &authFakeRows{cols: []string{"password_hash", "mfa_enabled", "mfa_secret", "session_epoch"}}, nil
		}
		return &authFakeRows{
			cols: []string{"password_hash", "mfa_enabled", "mfa_secret", "session_epoch"},
			vals: [][]driver.Value{{u.passwordHash, u.mfaEnabled, u.mfaSecret, u.sessionEpoch}},
		}, nil

	case strings.Contains(s.query, "select role from users where username"):
		u, ok := s.f.users[argUser()]
		if !ok {
			return &authFakeRows{cols: []string{"role"}}, nil
		}
		return &authFakeRows{cols: []string{"role"}, vals: [][]driver.Value{{u.role}}}, nil

	case strings.Contains(s.query, "select session_epoch from users where username"):
		u, ok := s.f.users[argUser()]
		if !ok {
			return &authFakeRows{cols: []string{"session_epoch"}}, nil
		}
		return &authFakeRows{cols: []string{"session_epoch"}, vals: [][]driver.Value{{u.sessionEpoch}}}, nil

	case strings.Contains(s.query, "select username from users where id"):
		for name, u := range s.f.users {
			if len(args) > 0 && fmt.Sprint(args[0]) == fmt.Sprint(u.id) {
				return &authFakeRows{cols: []string{"username"}, vals: [][]driver.Value{{name}}}, nil
			}
		}
		return &authFakeRows{cols: []string{"username"}}, nil

	case strings.Contains(s.query, "select id from users where username"):
		u, ok := s.f.users[argUser()]
		if !ok {
			return &authFakeRows{cols: []string{"id"}}, nil
		}
		return &authFakeRows{cols: []string{"id"}, vals: [][]driver.Value{{u.id}}}, nil

	default:
		return &authFakeRows{}, nil
	}
}

type authFakeRows struct {
	cols []string
	vals [][]driver.Value
	pos  int
}

func (r *authFakeRows) Columns() []string { return r.cols }
func (r *authFakeRows) Close() error      { return nil }
func (r *authFakeRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.pos])
	r.pos++
	return nil
}

func authFakeNormalize(q string) string {
	return strings.ToLower(strings.Join(strings.Fields(q), " "))
}
