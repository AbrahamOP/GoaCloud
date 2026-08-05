package middleware

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// withTrustedProxies installs a trust boundary for the duration of a test and
// restores the default (trust nobody) afterwards, so tests cannot leak state into
// each other through the package-level list.
func withTrustedProxies(t *testing.T, entries ...string) {
	t.Helper()
	if err := SetTrustedProxies(entries); err != nil {
		t.Fatalf("SetTrustedProxies(%v): %v", entries, err)
	}
	t.Cleanup(func() { _ = SetTrustedProxies(nil) })
}

// TestRealIP_UntrustedPeerHeadersIgnored is the regression test for the forged
// header bypass: GoaCore serves HTTPS itself on 8443, so with no proxy declared a
// client can put anything in X-Forwarded-For. If RealIP believed it, every login
// attempt would land in a brand-new rate-limit bucket and the 5-strike block would
// never fire. With no trusted proxy (the default), only r.RemoteAddr counts.
func TestRealIP_UntrustedPeerHeadersIgnored(t *testing.T) {
	withTrustedProxies(t) // empty list = default: trust nobody

	r := httptest.NewRequest("GET", "/login", nil)
	r.RemoteAddr = "203.0.113.50:44321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.Header.Set("X-Real-IP", "198.51.100.2")

	if got := RealIP(r); got != "203.0.113.50" {
		t.Fatalf("RealIP() = %q, want the peer address 203.0.113.50 — forged forwarding headers must be ignored", got)
	}
}

// TestRealIP_HeadersHonouredFromTrustedProxy is the counterpart: behind a declared
// reverse proxy (Traefik at 192.168.20.13), the forwarded client IP is the one to
// rate-limit on — otherwise every user of the LAN shares the proxy's single bucket.
func TestRealIP_HeadersHonouredFromTrustedProxy(t *testing.T) {
	withTrustedProxies(t, "192.168.20.13/32")

	r := httptest.NewRequest("GET", "/login", nil)
	r.RemoteAddr = "192.168.20.13:51000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")

	if got := RealIP(r); got != "198.51.100.1" {
		t.Fatalf("RealIP() = %q, want 198.51.100.1 — a trusted proxy's X-Forwarded-For must be honoured", got)
	}
}

// TestRealIP_TrustIsPerPeer proves the trust is bound to WHO connected, not to the
// header's presence: the same forged request from outside the declared block stays
// keyed on its own address, so an attacker cannot borrow the proxy's authority.
func TestRealIP_TrustIsPerPeer(t *testing.T) {
	withTrustedProxies(t, "192.168.20.0/24")

	inside := httptest.NewRequest("GET", "/login", nil)
	inside.RemoteAddr = "192.168.20.13:51000"
	inside.Header.Set("X-Forwarded-For", "198.51.100.1")

	outside := httptest.NewRequest("GET", "/login", nil)
	outside.RemoteAddr = "192.168.30.9:51000"
	outside.Header.Set("X-Forwarded-For", "198.51.100.1")

	if got := RealIP(inside); got != "198.51.100.1" {
		t.Fatalf("trusted peer: RealIP() = %q, want 198.51.100.1", got)
	}
	if got := RealIP(outside); got != "192.168.30.9" {
		t.Fatalf("untrusted peer: RealIP() = %q, want its own address 192.168.30.9", got)
	}
}

// TestSetTrustedProxies_Forms accepts CIDR blocks and bare IPs, and rejects
// anything else without installing a partial list.
func TestSetTrustedProxies_Forms(t *testing.T) {
	t.Cleanup(func() { _ = SetTrustedProxies(nil) })

	if err := SetTrustedProxies([]string{"10.0.0.0/8", " 192.0.2.7 ", "::1"}); err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
	for _, host := range []string{"10.1.2.3", "192.0.2.7", "::1"} {
		if !isTrustedProxy(host) {
			t.Errorf("%s should be trusted", host)
		}
	}
	if isTrustedProxy("192.0.2.8") {
		t.Error("192.0.2.8 must NOT be trusted (a bare IP is a single host, not a range)")
	}

	if err := SetTrustedProxies([]string{"192.168.20.13", "not-an-ip"}); err == nil {
		t.Fatal("a malformed entry must be an error")
	}
	if isTrustedProxy("192.168.20.13") {
		t.Error("a rejected list must not be installed, not even partially")
	}
}

// TestRateLimiterEvictsIdleEntries pins the eviction: entries that are no longer
// blocked and have not been seen for entryTTL are dropped. Without it the map
// grows one entry per attacking IP for the lifetime of the process — an unbounded
// leak that an attacker controls.
func TestRateLimiterEvictsIdleEntries(t *testing.T) {
	rl := NewRateLimiter()

	for i := 0; i < 500; i++ {
		rl.RecordFailure(fmt.Sprintf("198.51.100.%d", i))
	}
	if got := rl.Size(); got != 500 {
		t.Fatalf("Size() = %d, want 500 tracked entries", got)
	}

	// Nothing is evicted while the entries are fresh, even once a sweep is due.
	rl.mu.Lock()
	rl.lastSweep = time.Now().Add(-2 * sweepInterval)
	evicted := rl.sweepLocked(time.Now())
	rl.mu.Unlock()
	if evicted != 0 {
		t.Fatalf("sweep evicted %d fresh entries, want 0", evicted)
	}

	// Past the TTL they all go.
	future := time.Now().Add(entryTTL + time.Minute)
	rl.mu.Lock()
	rl.lastSweep = future.Add(-2 * sweepInterval)
	evicted = rl.sweepLocked(future)
	rl.mu.Unlock()
	if evicted != 500 {
		t.Fatalf("sweep evicted %d idle entries, want 500", evicted)
	}
	if got := rl.Size(); got != 0 {
		t.Fatalf("Size() = %d after eviction, want 0", got)
	}
}

// TestRateLimiterKeepsBlockedEntries: eviction must never release a block early —
// a blocked IP is kept until its block expires, however idle it looks.
func TestRateLimiterKeepsBlockedEntries(t *testing.T) {
	rl := NewRateLimiter()
	const ip = "203.0.113.42"

	for i := 0; i < maxFailures; i++ {
		rl.RecordFailure(ip)
	}
	if !rl.IsBlocked(ip) {
		t.Fatal("setup: ip should be blocked")
	}

	// Long idle (way past entryTTL) but the block is still running: the entry stays.
	now := time.Now()
	rl.mu.Lock()
	e := rl.entries[ip]
	e.lastSeen = now.Add(-2 * entryTTL)
	e.blockedUntil = now.Add(time.Hour)
	rl.lastSweep = now.Add(-2 * sweepInterval)
	evicted := rl.sweepLocked(now)
	rl.mu.Unlock()
	if evicted != 0 {
		t.Fatalf("sweep evicted %d blocked entries, want 0 — a block must not be forgotten early", evicted)
	}
	if !rl.IsBlocked(ip) {
		t.Fatal("ip should still be blocked after a sweep")
	}

	// Once the block has expired AND the entry is idle, it becomes collectable.
	rl.mu.Lock()
	rl.entries[ip].blockedUntil = now.Add(-time.Minute)
	rl.lastSweep = now.Add(-2 * sweepInterval)
	evicted = rl.sweepLocked(now)
	rl.mu.Unlock()
	if evicted != 1 {
		t.Fatalf("sweep evicted %d entries after the block expired, want 1", evicted)
	}
}

// TestRateLimiterSweepThrottled: the sweep is throttled to one pass per
// sweepInterval so a login burst never turns into a full map scan per attempt.
func TestRateLimiterSweepThrottled(t *testing.T) {
	rl := NewRateLimiter()
	rl.RecordFailure("198.51.100.1")

	future := time.Now().Add(entryTTL + time.Minute)
	rl.mu.Lock()
	rl.lastSweep = future // a sweep just happened
	evicted := rl.sweepLocked(future)
	rl.mu.Unlock()
	if evicted != 0 {
		t.Fatalf("sweep ran %d evictions despite being throttled, want 0", evicted)
	}
	if got := rl.Size(); got != 1 {
		t.Fatalf("Size() = %d, want the entry to survive the throttled sweep", got)
	}
}
