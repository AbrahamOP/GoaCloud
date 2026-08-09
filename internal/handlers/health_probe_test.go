package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// /healthz and /readyz.
//
// These two routes are unauthenticated, so the tests pin BOTH halves of the
// contract: they answer usefully to a probe, and they answer nothing else — no
// version, no hostname, no DSN, no driver error. The liveness/readiness split is
// pinned too, because it is the whole point: /healthz must not turn a database
// outage into a container restart loop, /readyz must take the instance out of
// rotation for exactly that outage.
// ─────────────────────────────────────────────────────────────────────────────

// unreachableDB returns a *sql.DB whose driver cannot connect — the "MySQL is
// down" case, without needing a MySQL to take down.
func unreachableDB(t *testing.T) *sql.DB {
	t.Helper()
	// Force registration of the fake driver, then open an unknown DSN: its Open
	// fails, so every connection attempt — including Ping — errors.
	realDB, _ := newAuthFakeDB(t)
	realDB.Close()
	db, err := sql.Open("authflowfake", "no-such-dsn")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func probe(t *testing.T, h *Handler, handler func(http.ResponseWriter, *http.Request), path string) (*httptest.ResponseRecorder, healthResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, path, nil))

	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s returned a non-JSON body %q: %v", path, rec.Body.String(), err)
	}
	return rec, body
}

func TestHealthz_HealthyInstance(t *testing.T) {
	db, _ := newAuthFakeDB(t)
	h := &Handler{DB: db}

	rec, body := probe(t, h, h.HandleHealthz, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz on a healthy instance: got %d, want 200", rec.Code)
	}
	if body.Status != "ok" || body.Database != "ok" {
		t.Fatalf("/healthz body = %+v, want status=ok database=ok", body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store — a proxy could serve a stale \"ok\"", got)
	}
}

func TestReadyz_HealthyInstance(t *testing.T) {
	db, _ := newAuthFakeDB(t)
	h := &Handler{DB: db}

	rec, body := probe(t, h, h.HandleReadyz, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz on a healthy instance: got %d, want 200", rec.Code)
	}
	if body.Status != "ready" || body.Database != "ok" {
		t.Fatalf("/readyz body = %+v, want status=ready database=ok", body)
	}
}

// TestProbes_DatabaseDown pins the liveness/readiness split: the same outage
// keeps /healthz at 200 (restarting GoaCore does not fix MySQL) and fails
// /readyz with 503 (there is nothing useful to serve without the database).
func TestProbes_DatabaseDown(t *testing.T) {
	h := &Handler{DB: unreachableDB(t)}

	rec, body := probe(t, h, h.HandleHealthz, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz with the DB down: got %d, want 200 — a liveness probe must not trigger a restart loop", rec.Code)
	}
	if body.Status != "degraded" || body.Database != "unreachable" {
		t.Fatalf("/healthz body = %+v, want status=degraded database=unreachable", body)
	}

	rec, body = probe(t, h, h.HandleReadyz, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with the DB down: got %d, want 503 — the instance must leave the rotation", rec.Code)
	}
	if body.Status != "not ready" || body.Database != "unreachable" {
		t.Fatalf("/readyz body = %+v, want status=\"not ready\" database=unreachable", body)
	}
}

// TestProbes_NilDatabaseDoesNotPanic: the probes exist to stay up. A handle that
// was never wired must degrade, not take the route down with a 500.
func TestProbes_NilDatabaseDoesNotPanic(t *testing.T) {
	h := &Handler{}

	rec, body := probe(t, h, h.HandleHealthz, "/healthz")
	if rec.Code != http.StatusOK || body.Database != "unreachable" {
		t.Fatalf("/healthz with a nil DB: %d %+v, want 200 + database=unreachable", rec.Code, body)
	}
	rec, _ = probe(t, h, h.HandleReadyz, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with a nil DB: got %d, want 503", rec.Code)
	}
}

// TestProbes_LeakNothing is the counterpart of "unauthenticated": whatever the
// state of the instance, the payload stays the two agreed fields. A driver error
// carries the DSN (host, port, user) and must never reach an anonymous caller.
func TestProbes_LeakNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    *Handler
	}{
		{"healthy", &Handler{DB: func() *sql.DB { db, _ := newAuthFakeDB(t); return db }()}},
		{"db down", &Handler{DB: unreachableDB(t)}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range []struct {
				path string
				fn   func(http.ResponseWriter, *http.Request)
			}{{"/healthz", tc.h.HandleHealthz}, {"/readyz", tc.h.HandleReadyz}} {
				rec := httptest.NewRecorder()
				p.fn(rec, httptest.NewRequest(http.MethodGet, p.path, nil))

				var raw map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
					t.Fatalf("%s: non-JSON body %q", p.path, rec.Body.String())
				}
				for key := range raw {
					if key != "status" && key != "database" {
						t.Fatalf("%s exposes an extra field %q — the probes must stay a monitoring signal, not an inventory", p.path, key)
					}
				}
				// The fake driver's failure message contains its DSN; a generic
				// scan for it catches any future "helpful" error passthrough.
				if body := strings.ToLower(rec.Body.String()); strings.Contains(body, "dsn") || strings.Contains(body, "no-such-dsn") {
					t.Fatalf("%s leaked connection details: %s", p.path, rec.Body.String())
				}
			}
		})
	}
}
