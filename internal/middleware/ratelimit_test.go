package middleware

import (
	"net/http/httptest"
	"testing"
)

// TestRealIP covers header parsing FROM A TRUSTED PROXY. The peer address
// (10.0.0.1) is declared trusted for each case, which is the only situation where
// X-Forwarded-For / X-Real-IP carry any authority. The untrusted case — the one
// that used to let an attacker forge a new identity per attempt — is pinned in
// TestRealIP_UntrustedPeerHeadersIgnored (ratelimit_trust_test.go).
func TestRealIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xRealIP    string
		remoteAddr string
		want       string
	}{
		{"xff single", "203.0.113.7", "", "10.0.0.1:1234", "203.0.113.7"},
		{"xff chain takes leftmost", "203.0.113.7, 10.0.0.1, 10.0.0.2", "", "10.0.0.1:1234", "203.0.113.7"},
		{"xff invalid falls back to x-real-ip", "not-an-ip", "198.51.100.4", "10.0.0.1:1234", "198.51.100.4"},
		{"no headers uses remoteaddr host", "", "", "10.0.0.1:5678", "10.0.0.1"},
		{"remoteaddr without port returned as-is", "", "", "10.0.0.1", "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTrustedProxies(t, "10.0.0.1/32")
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if got := RealIP(r); got != tt.want {
				t.Errorf("RealIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimiterBlocksAfterFiveFailures(t *testing.T) {
	rl := NewRateLimiter()
	const ip = "203.0.113.10"

	for i := 1; i <= 4; i++ {
		n, blocked := rl.RecordFailure(ip)
		if blocked {
			t.Fatalf("attempt %d should not block yet", i)
		}
		if n != i {
			t.Fatalf("attempt %d: count = %d, want %d", i, n, i)
		}
		if rl.IsBlocked(ip) {
			t.Fatalf("attempt %d: IsBlocked should be false", i)
		}
	}

	if _, blocked := rl.RecordFailure(ip); !blocked {
		t.Fatal("5th failure should trigger a block")
	}
	if !rl.IsBlocked(ip) {
		t.Fatal("IsBlocked should be true after 5 failures")
	}
}

func TestRateLimiterResetClearsBlock(t *testing.T) {
	rl := NewRateLimiter()
	const ip = "203.0.113.11"
	for i := 0; i < 5; i++ {
		rl.RecordFailure(ip)
	}
	if !rl.IsBlocked(ip) {
		t.Fatal("expected ip to be blocked")
	}
	rl.Reset(ip)
	if rl.IsBlocked(ip) {
		t.Fatal("Reset should clear the block")
	}
}

func TestRateLimiterIsolatesIPs(t *testing.T) {
	rl := NewRateLimiter()
	for i := 0; i < 5; i++ {
		rl.RecordFailure("203.0.113.12")
	}
	if rl.IsBlocked("203.0.113.99") {
		t.Fatal("an unrelated IP must not be blocked")
	}
}
