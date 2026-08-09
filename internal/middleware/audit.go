package middleware

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/sessions"
	"goacore/internal/services"
)

// maxAuditActionLen keeps the recorded action within audit_logs.action (VARCHAR(255)).
const maxAuditActionLen = 255

// auditAnonymous is the actor recorded when no session username is available
// (an unauthenticated request that still reached the audited group).
const auditAnonymous = "anonyme"

// AuditSink records one audit entry. It exists so the middleware can be wired to
// the audit_logs table in production (DBAuditSink) and to an in-memory recorder in
// tests, without the middleware knowing anything about SQL.
type AuditSink func(username, action, details, ip string)

// DBAuditSink returns the production sink: it appends to the audit_logs table.
// The write is synchronous on purpose — the sink runs once the handler has
// returned and the response is already on the wire, so the client waits for
// nothing, and the entry can never be lost with a goroutine the process outlives.
// services.LogAudit reports its own failures via slog.
func DBAuditSink(db *sql.DB) AuditSink {
	return func(username, action, details, ip string) {
		services.LogAudit(db, 0, username, action, details, ip)
	}
}

// AuditTrail records every state-changing request that crosses it: who did it,
// on which route, from which IP, and what the server answered. It is meant to be
// mounted on the Admin-only group, where every route is infra-sensitive (shell,
// keys, playbooks, restores, users).
//
// Mount it BEFORE AdminOnly so a refused privilege escalation (a Viewer poking an
// admin route) leaves a "HTTP 403" trace instead of no trace at all.
//
// Only POST/PUT/PATCH/DELETE are recorded: reads are the bulk of the traffic and
// would drown the trail. Handlers still add their own explicit entries where the
// business context matters (which guest, which key, which playbook) — the two are
// complementary, the middleware being the net nothing falls through.
//
// NOTHING but the method, the URL PATH and the status code is recorded: the query
// string and the request body routinely carry secrets (TOTP codes, API tokens,
// private keys) and must never land in a table an operator reads all day.
func AuditTrail(store *sessions.CookieStore, sink AuditSink) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if sink == nil || !isStateChanging(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			username := GetSessionUser(r, store)
			if username == "" {
				username = auditAnonymous
			}
			action := auditAction(r.Method, r.URL.Path)
			ip := RealIP(r)

			rec := &auditRecorder{ResponseWriter: w}
			// completed stays false if the handler panics: the deferred sink then
			// records the interrupted call and the panic keeps unwinding to the
			// Recoverer, which is exactly the case an attacker would hope goes unlogged.
			completed := false
			defer func() {
				sink(username, action, auditOutcome(rec.status, completed), ip)
			}()

			next.ServeHTTP(rec, r)
			completed = true
		})
	}
}

// isStateChanging reports whether a method can mutate server state.
func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// auditAction builds the "METHOD /path" label, truncated to fit the column.
func auditAction(method, path string) string {
	action := method + " " + path
	if len(action) > maxAuditActionLen {
		action = action[:maxAuditActionLen]
	}
	return action
}

// auditOutcome turns the observed status into a readable verdict for /audit-logs.
func auditOutcome(status int, completed bool) string {
	if !completed {
		return "requête interrompue (panique du handler)"
	}
	if status == 0 {
		// A handler that writes nothing still yields a 200 on the wire.
		status = http.StatusOK
	}
	switch {
	case status >= 500:
		return fmt.Sprintf("échec — HTTP %d", status)
	case status >= 400:
		return fmt.Sprintf("refusée — HTTP %d", status)
	default:
		return fmt.Sprintf("succès — HTTP %d", status)
	}
}

// auditRecorder captures the status code on its way out.
//
// It forwards the optional interfaces the audited handlers rely on: Flush (the
// Ansible run streams its output and bails out with "Streaming not supported"
// without it) and Hijack (WebSocket upgrades). Unwrap keeps http.ResponseController
// working for anything else.
type auditRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *auditRecorder) WriteHeader(code int) {
	if rec.status == 0 {
		rec.status = code
	}
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *auditRecorder) Write(b []byte) (int, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return rec.ResponseWriter.Write(b)
}

func (rec *auditRecorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rec *auditRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rec.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("audit: underlying ResponseWriter does not support hijacking")
	}
	return h.Hijack()
}

func (rec *auditRecorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }
