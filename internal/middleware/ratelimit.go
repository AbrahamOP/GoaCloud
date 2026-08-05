package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// trustedProxies holds the parsed TRUSTED_PROXIES blocks whose forwarding headers
// RealIP is allowed to believe. A nil/empty list — the default until main.go
// installs one — means NO proxy is trusted, so no header is ever believed.
var trustedProxies atomic.Pointer[[]*net.IPNet]

// SetTrustedProxies installs the list of proxy addresses whose X-Forwarded-For /
// X-Real-IP headers RealIP may trust (env TRUSTED_PROXIES — see config.Config).
// Each entry is a CIDR block ("192.168.20.13/32", "10.0.0.0/8") or a bare IP,
// which is read as a single-host block.
//
// A malformed entry is an error and NOTHING is installed: a typo must never
// silently widen or void the trust boundary. Passing an empty list clears the
// trust, which is the safe default (headers ignored, r.RemoteAddr wins).
func SetTrustedProxies(entries []string) error {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, block, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, block)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("trusted proxy %q is neither a CIDR block nor an IP address", entry)
		}
		bits := 8 * net.IPv6len
		if ip.To4() != nil {
			bits = 8 * net.IPv4len
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	trustedProxies.Store(&nets)
	return nil
}

// isTrustedProxy reports whether host (an IP without port) is one of the declared
// trusted proxies. Always false while the list is empty.
func isTrustedProxy(host string) bool {
	nets := trustedProxies.Load()
	if nets == nil || len(*nets) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, block := range *nets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// RealIP returns the client IP used to key the login rate limiter.
//
// X-Forwarded-For / X-Real-IP are honoured ONLY when the request itself comes
// from a declared trusted proxy (SetTrustedProxies / TRUSTED_PROXIES); otherwise
// the transport-level r.RemoteAddr is the single source of truth. GoaCore serves
// HTTPS itself on 8443, so anyone reaching the port could otherwise forge a new
// header value on every attempt, land in a brand-new counter each time and never
// be blocked — the rate limiter would be decorative.
func RealIP(r *http.Request) string {
	remote := remoteHost(r)
	if !isTrustedProxy(remote) {
		return remote
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For: client, proxy1, proxy2 — take the first (leftmost)
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			xff = xff[:idx]
		}
		ip := strings.TrimSpace(xff)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return remote
}

// remoteHost strips the port from r.RemoteAddr (returned as-is when it carries none).
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const (
	// maxFailures is the number of failed attempts that trips a block.
	maxFailures = 5
	// blockDuration is how long a tripped IP stays blocked.
	blockDuration = 15 * time.Minute
	// entryTTL is how long an idle entry survives before eviction. It doubles as
	// the failure-count decay: an IP that stops failing for that long starts over
	// with a clean counter, which is the behaviour a human user expects.
	entryTTL = 30 * time.Minute
	// sweepInterval bounds how often the (cheap) eviction pass runs.
	sweepInterval = time.Minute
)

// RateLimiter provides per-IP rate limiting for login attempts.
//
// Entries are evicted lazily: every insertion runs at most one sweep per
// sweepInterval, dropping entries that are neither blocked nor recently seen.
// Without it the map only ever grows — one entry per IP that ever failed a login,
// held for the lifetime of the process — which on an internet-reachable instance
// is an unbounded memory leak driven by an attacker.
type RateLimiter struct {
	mu        sync.Mutex
	entries   map[string]*rateLimitEntry
	lastSweep time.Time
}

type rateLimitEntry struct {
	count        int
	blockedUntil time.Time
	lastSeen     time.Time
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		entries:   make(map[string]*rateLimitEntry),
		lastSweep: time.Now(),
	}
}

// IsBlocked returns true if the given IP is currently blocked.
func (rl *RateLimiter) IsBlocked(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		return false
	}
	return time.Now().Before(e.blockedUntil)
}

// RecordFailure records a failed login attempt. Returns (attempt count, blocked).
func (rl *RateLimiter) RecordFailure(ip string) (int, bool) {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.sweepLocked(now)

	e, ok := rl.entries[ip]
	if !ok {
		e = &rateLimitEntry{}
		rl.entries[ip] = e
	}
	e.lastSeen = now
	e.count++
	if e.count >= maxFailures {
		e.blockedUntil = now.Add(blockDuration)
		e.count = 0
		return maxFailures, true
	}
	return e.count, false
}

// Reset clears the failure count for an IP after a successful login.
func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

// Size returns the number of tracked entries (used by the eviction test).
func (rl *RateLimiter) Size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.entries)
}

// sweepLocked evicts every entry that is no longer blocked and has not been seen
// for entryTTL, at most once per sweepInterval. The caller MUST hold rl.mu.
// It returns the number of evicted entries (for the test).
func (rl *RateLimiter) sweepLocked(now time.Time) int {
	if now.Sub(rl.lastSweep) < sweepInterval {
		return 0
	}
	rl.lastSweep = now
	evicted := 0
	for ip, e := range rl.entries {
		if now.Before(e.blockedUntil) {
			continue // still serving a block — keep it
		}
		if now.Sub(e.lastSeen) > entryTTL {
			delete(rl.entries, ip)
			evicted++
		}
	}
	return evicted
}

// BlockedMessage returns a user-facing message describing the block state.
func BlockedMessage() string {
	return "Trop de tentatives de connexion. Réessayez dans 15 minutes."
}
