package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
)

// ─────────────────────────────────────────────────────────────────────────────
// Audit trail on the Admin-only group.
//
// Every route behind AdminOnly opens a root shell, deploys a key, runs a playbook
// or destroys a guest. The middleware is the net that guarantees such a call
// cannot happen without leaving a row, even if a future handler forgets its own
// explicit LogAudit. These tests pin the four properties that make the trail
// trustworthy: it fires on mutations, it names the actor, it records refusals,
// and it never copies a secret out of the query string.
// ─────────────────────────────────────────────────────────────────────────────

type auditEntry struct {
	username string
	action   string
	details  string
	ip       string
}

// auditCollector is the test sink. It is mutex-guarded because a handler is free
// to be hit from several goroutines.
type auditCollector struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (c *auditCollector) sink() AuditSink {
	return func(username, action, details, ip string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.entries = append(c.entries, auditEntry{username, action, details, ip})
	}
}

func (c *auditCollector) all() []auditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]auditEntry(nil), c.entries...)
}

func (c *auditCollector) only(t *testing.T) auditEntry {
	t.Helper()
	entries := c.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want exactly 1 (%+v)", len(entries), entries)
	}
	return entries[0]
}

func auditTestStore() *sessions.CookieStore {
	return sessions.NewCookieStore([]byte("audit-test-session-key-0123456789"))
}

// runAudited drives one request through the audit middleware wrapping next, with
// an authenticated session cookie for username (empty = no cookie at all).
func runAudited(t *testing.T, c *auditCollector, username, method, target string, next http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	store := auditTestStore()
	req := httptest.NewRequest(method, target, nil)
	if username != "" {
		req.AddCookie(epochCookie(t, store, username, 0, true))
	}
	rec := httptest.NewRecorder()
	AuditTrail(store, c.sink())(next).ServeHTTP(rec, req)
	return rec
}

var auditOK = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("done"))
})

// TestAuditTrail_RecordsMutation: a POST on an admin route names the actor, the
// route and the HTTP result.
func TestAuditTrail_RecordsMutation(t *testing.T) {
	c := &auditCollector{}
	rec := runAudited(t, c, "alice", http.MethodPost, "/api/ansible/run", auditOK)

	if rec.Code != http.StatusOK {
		t.Fatalf("handler response altered: got %d, want 200", rec.Code)
	}
	e := c.only(t)
	if e.username != "alice" {
		t.Errorf("actor = %q, want %q", e.username, "alice")
	}
	if e.action != "POST /api/ansible/run" {
		t.Errorf("action = %q, want %q", e.action, "POST /api/ansible/run")
	}
	if !strings.Contains(e.details, "200") {
		t.Errorf("details = %q, want the HTTP status in it", e.details)
	}
	if e.ip == "" {
		t.Error("audit entry has no source IP")
	}
}

// TestAuditTrail_IgnoresReads: read traffic (GET/HEAD) must not drown the trail.
func TestAuditTrail_IgnoresReads(t *testing.T) {
	c := &auditCollector{}
	runAudited(t, c, "alice", http.MethodGet, "/ansible", auditOK)
	runAudited(t, c, "alice", http.MethodHead, "/ansible", auditOK)

	if entries := c.all(); len(entries) != 0 {
		t.Fatalf("reads were audited: %+v", entries)
	}
}

// TestAuditTrail_AuditsEveryMutatingMethod: DELETE (SSH key removal) and PUT
// (playbook rewrite) are as sensitive as POST and must not slip through.
func TestAuditTrail_AuditsEveryMutatingMethod(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		c := &auditCollector{}
		runAudited(t, c, "alice", method, "/api/ssh/delete", auditOK)
		e := c.only(t)
		if !strings.HasPrefix(e.action, method+" ") {
			t.Errorf("%s was not audited under its own method: action = %q", method, e.action)
		}
	}
}

// TestAuditTrail_RecordsRefusal: mounted before AdminOnly, the middleware turns a
// refused privilege escalation into a trace instead of silence.
func TestAuditTrail_RecordsRefusal(t *testing.T) {
	c := &auditCollector{}
	forbidden := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Accès refusé.", http.StatusForbidden)
	})
	rec := runAudited(t, c, "bob", http.MethodPost, "/api/ssh/deploy", forbidden)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	e := c.only(t)
	if !strings.Contains(e.details, "403") {
		t.Errorf("details = %q, want the 403 refusal recorded", e.details)
	}
	if e.username != "bob" {
		t.Errorf("actor = %q, want %q", e.username, "bob")
	}
}

// TestAuditTrail_NeverLogsQueryString: the query string carries tokens, TOTP codes
// and key material on some routes. Not one byte of it may reach the trail.
func TestAuditTrail_NeverLogsQueryString(t *testing.T) {
	const secret = "s3cr3t-token-value"
	c := &auditCollector{}
	runAudited(t, c, "alice", http.MethodDelete, "/api/ssh/delete?id=3&token="+secret, auditOK)

	e := c.only(t)
	for _, field := range []string{e.action, e.details, e.username} {
		if strings.Contains(field, secret) || strings.Contains(field, "token=") {
			t.Fatalf("the query string leaked into the audit trail: %q", field)
		}
	}
	if e.action != "DELETE /api/ssh/delete" {
		t.Errorf("action = %q, want the bare path", e.action)
	}
}

// TestAuditTrail_AnonymousActor: a request with no session is still recorded —
// under an explicit placeholder rather than an empty, silently ignorable actor.
func TestAuditTrail_AnonymousActor(t *testing.T) {
	c := &auditCollector{}
	runAudited(t, c, "", http.MethodPost, "/api/backups/test", auditOK)

	if e := c.only(t); e.username != auditAnonymous {
		t.Errorf("actor = %q, want %q", e.username, auditAnonymous)
	}
}

// TestAuditTrail_PreservesFlusher: /api/ansible/run streams its output and aborts
// with "Streaming not supported" if the wrapper hides http.Flusher.
func TestAuditTrail_PreservesFlusher(t *testing.T) {
	c := &auditCollector{}
	flushed := false
	streaming := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("chunk"))
		f.Flush()
		flushed = true
	})
	rec := runAudited(t, c, "alice", http.MethodPost, "/api/ansible/run", streaming)

	if !flushed {
		t.Fatalf("the audited handler lost http.Flusher (status %d) — playbook streaming would break", rec.Code)
	}
	if body := rec.Body.String(); body != "chunk" {
		t.Errorf("streamed body = %q, want %q", body, "chunk")
	}
}

// TestAuditTrail_AuditsPanickingHandler: a handler that blows up mid-way must not
// be a way to act without a trace. The panic itself keeps travelling to the
// Recoverer installed above.
func TestAuditTrail_AuditsPanickingHandler(t *testing.T) {
	c := &auditCollector{}
	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed by the audit middleware")
			}
		}()
		runAudited(t, c, "alice", http.MethodPost, "/api/proxmox/guest/create", boom)
	}()

	e := c.only(t)
	if !strings.Contains(e.details, "interrompue") {
		t.Errorf("details = %q, want the interrupted request recorded", e.details)
	}
}

// TestAuditTrail_NilSinkIsTransparent: a misconfigured wiring must degrade to a
// pass-through, never to a broken admin section.
func TestAuditTrail_NilSinkIsTransparent(t *testing.T) {
	store := auditTestStore()
	req := httptest.NewRequest(http.MethodPost, "/api/ssh/deploy", nil)
	rec := httptest.NewRecorder()
	AuditTrail(store, nil)(auditOK).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
