package workers

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// SSRF guard on the application health-checks.
//
// The worker probes an external_url that ANY user with write access to the apps
// catalogue supplied, and publishes the outcome (up/down + latency) on the
// dashboard. Without a guard that turns the server into a port scanner for the
// internal network — and, on a cloud instance, into a reader of the metadata
// service on 169.254.169.254, which hands out instance credentials.
//
// The regression these tests pin is: the never-legitimate targets stay refused,
// and the private ranges a homelab/PME app actually lives on stay reachable
// unless the operator explicitly opts out.
// ─────────────────────────────────────────────────────────────────────────────

func TestForbiddenIP_AlwaysRefusedTargets(t *testing.T) {
	// These must be refused in BOTH configurations: no legitimate monitored
	// application ever lives at one of these addresses.
	cases := []struct {
		name string
		ip   string
	}{
		{"cloud metadata service", "169.254.169.254"},
		{"IPv4 link-local", "169.254.10.1"},
		{"IPv6 link-local", "fe80::1"},
		{"IPv4 loopback", "127.0.0.1"},
		{"IPv4 loopback, non-.1", "127.9.9.9"},
		{"IPv6 loopback", "::1"},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test setup: %q is not an IP", tc.ip)
			}
			for _, blockPrivate := range []bool{false, true} {
				if reason := forbiddenIP(ip, blockPrivate); reason == "" {
					t.Fatalf("%s (%s) allowed with blockPrivate=%v — the health worker would probe it",
						tc.name, tc.ip, blockPrivate)
				}
			}
		})
	}
}

func TestForbiddenIP_PrivateRangesFollowTheSwitch(t *testing.T) {
	// The deliberate default: a homelab/PME dashboard monitors applications that
	// ARE on private addresses. Blocking them out of the box would not harden the
	// product, it would delete the feature.
	private := []string{"192.168.20.11", "10.0.0.5", "172.16.3.4", "100.64.0.1", "fd00::1"}
	for _, raw := range private {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("test setup: %q is not an IP", raw)
		}
		if reason := forbiddenIP(ip, false); reason != "" {
			t.Fatalf("%s refused by default (%s) — legitimate LAN applications would all show as down", raw, reason)
		}
		if reason := forbiddenIP(ip, true); reason == "" {
			t.Fatalf("%s still allowed with %s enabled — the opt-out does nothing", raw, blockPrivateEnv)
		}
	}

	// A public address is never affected by the switch.
	if reason := forbiddenIP(net.ParseIP("93.184.216.34"), true); reason != "" {
		t.Fatalf("public address refused (%s) — the switch must only cover private ranges", reason)
	}
}

func TestCheckHealthTarget(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"plain http on a LAN host", "http://192.168.20.11:8080/", false},
		{"https on a name", "https://grafana.goacloud.fr/", false},
		{"metadata service by IP", "http://169.254.169.254/latest/meta-data/", true},
		{"loopback by IP", "http://127.0.0.1:8443/", true},
		{"loopback with a port and path", "https://127.0.0.1:9200/_cat/indices", true},
		{"IPv6 loopback literal", "http://[::1]:8080/", true},
		{"file scheme", "file:///etc/passwd", true},
		{"gopher scheme", "gopher://192.168.20.11:70/", true},
		{"no host", "http:///relative", true},
		{"empty", "", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := checkHealthTarget(tc.url, false)
			if tc.wantErr && err == nil {
				t.Fatalf("checkHealthTarget(%q) = nil, want a refusal", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkHealthTarget(%q) = %v, want it allowed", tc.url, err)
			}
		})
	}
}

func TestAllowDialTarget(t *testing.T) {
	if err := allowDialTarget("tcp", "192.168.20.11:8080", false); err != nil {
		t.Fatalf("a LAN target must be dialable by default: %v", err)
	}
	for _, addr := range []string{"169.254.169.254:80", "127.0.0.1:8443", "[::1]:80"} {
		if err := allowDialTarget("tcp", addr, false); !errors.Is(err, errBlockedTarget) {
			t.Fatalf("allowDialTarget(%q) = %v, want errBlockedTarget", addr, err)
		}
	}
	// Non-TCP networks have no business coming out of the HTTP transport.
	if err := allowDialTarget("unix", "/var/run/docker.sock:0", false); !errors.Is(err, errBlockedTarget) {
		t.Fatalf("a non-TCP network must be refused, got %v", err)
	}
}

// TestHealthClientRefusesLoopback is the end-to-end proof: even against a REAL,
// listening, perfectly reachable server, the probing client refuses to open the
// socket because the resolved address is forbidden. The guard sits in the dialer,
// so it cannot be dodged by a hostname that resolves to a forbidden address after
// the URL was validated (DNS rebinding) — there is no second resolution to win.
func TestHealthClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Sanity check: a client WITHOUT the guard reaches the server, so a failure
	// below really is the guard and not a broken fixture.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("test setup: plain client cannot reach the fixture: %v", err)
	}
	resp.Body.Close()

	if _, err := newHealthClient(false).Get(srv.URL); err == nil {
		t.Fatalf("the health client reached %s — the loopback guard is not wired into the dialer", srv.URL)
	} else if !strings.Contains(err.Error(), errBlockedTarget.Error()) {
		t.Fatalf("request to %s failed for the wrong reason: %v", srv.URL, err)
	}
}
