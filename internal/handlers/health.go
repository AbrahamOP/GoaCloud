package handlers

import (
	"context"
	"net/http"
	"time"
)

// healthProbeTimeout bounds the database ping the probes perform. It is short on
// purpose: a probe that hangs is a probe an orchestrator reads as a hard failure,
// and the whole point of /healthz is to answer FAST even when MySQL is wedged.
const healthProbeTimeout = 2 * time.Second

// healthResponse is the ENTIRE payload of /healthz and /readyz.
//
// It is deliberately two fixed vocabularies and nothing else. These routes are
// unauthenticated (a probe carries no session cookie), so anything we put here is
// readable by anyone who can reach the port: no version, no hostname, no DSN, no
// driver error text, no counts of users/apps/alerts. "Is this instance answering,
// and is its database reachable" is the whole contract — a monitoring signal, not
// an inventory endpoint.
type healthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}

// HandleHealthz is the LIVENESS probe: "is this process still able to serve?".
//
// It always answers 200 while the process is alive, and reports the database state
// in the body as INFORMATION. This asymmetry with /readyz is intentional: a
// liveness probe drives container RESTARTS, and restarting GoaCore because MySQL is
// down neither fixes MySQL nor helps anyone — it just turns a degraded instance
// into a crash-loop. Losing the database is a readiness event, not a liveness one.
func (h *Handler) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	dbOK := h.pingDatabase(r.Context())
	if !dbOK {
		status = "degraded"
	}
	writeHealth(w, http.StatusOK, healthResponse{Status: status, Database: databaseState(dbOK)})
}

// HandleReadyz is the READINESS probe: "should traffic be routed here?".
//
// Unlike /healthz it FAILS (503) when the database is unreachable, because every
// useful page of GoaCore reads the database: serving them without it produces a
// wall of 500s. A reverse proxy or an orchestrator watching /readyz takes the
// instance out of rotation until MySQL is back, then puts it in again on its own.
func (h *Handler) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	dbOK := h.pingDatabase(r.Context())
	if !dbOK {
		writeHealth(w, http.StatusServiceUnavailable, healthResponse{Status: "not ready", Database: databaseState(false)})
		return
	}
	writeHealth(w, http.StatusOK, healthResponse{Status: "ready", Database: databaseState(true)})
}

// pingDatabase reports whether the database answers within healthProbeTimeout. A
// nil handle (never wired) counts as unreachable rather than panicking a route
// whose entire job is to stay up.
func (h *Handler) pingDatabase(ctx context.Context) bool {
	if h.DB == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	return h.DB.PingContext(ctx) == nil
}

// databaseState maps the probe result onto the fixed vocabulary of the payload —
// never the underlying driver error, which routinely carries the DSN (host, port,
// user) and would hand a passer-by the shape of the internal network.
func databaseState(ok bool) string {
	if ok {
		return "ok"
	}
	return "unreachable"
}

// writeHealth emits the probe payload. no-store keeps a reverse proxy from serving
// a cached "ok" long after the instance stopped being ok.
func writeHealth(w http.ResponseWriter, status int, body healthResponse) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, body)
}

// On /metrics: deliberately NOT added.
//
// A Prometheus endpoint would have to be scrapeable, i.e. unauthenticated like the
// two probes above — but unlike them it exists to publish detail: per-route request
// counts, user and application totals, health-check outcomes per app. On a product
// meant to sit at the edge of a small company's network, that is a free map of the
// instance (how many accounts, how many machines, which admin routes see traffic)
// for anyone who can reach the port. Behind AdminOnly it would be secure and
// useless: Prometheus scrapes with no session cookie.
//
// Exposing it properly needs a scrape credential (a bearer token or mTLS) and the
// configuration surface that goes with it. That is a feature with its own design,
// not a line to slip into this router — so the observability delivered here is the
// liveness/readiness pair, and metrics stay an explicit TODO.
