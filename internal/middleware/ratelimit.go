package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RealIP extracts the client IP from X-Forwarded-For or X-Real-IP headers,
// falling back to r.RemoteAddr. Only trusts the first IP in X-Forwarded-For
// (set by the nearest trusted proxy like Traefik).
func RealIP(r *http.Request) string {
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimiter provides per-IP rate limiting for login attempts.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	count        int
	blockedUntil time.Time
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
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
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		e = &rateLimitEntry{}
		rl.entries[ip] = e
	}
	e.count++
	if e.count >= 5 {
		e.blockedUntil = time.Now().Add(15 * time.Minute)
		e.count = 0
		return 5, true
	}
	return e.count, false
}

// Reset clears the failure count for an IP after a successful login.
func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

// BlockedMessage returns a user-facing message describing the block state.
func BlockedMessage() string {
	return fmt.Sprintf("Trop de tentatives de connexion. Réessayez dans 15 minutes.")
}
