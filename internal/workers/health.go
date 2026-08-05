package workers

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"
)

// blockPrivateEnv opts an operator into refusing RFC1918 / ULA / CGNAT targets.
//
// It defaults to FALSE, and that default is the whole design decision: in a homelab
// or a small company — GoaCore's target — the applications being health-checked ARE
// on private addresses (192.168.20.x here). Blocking them by default would not
// harden anything, it would delete the feature and push people to turn the check off
// entirely. The addresses that are never a legitimate target are handled separately
// and are ALWAYS refused (see forbiddenIP): loopback, link-local — which covers the
// cloud metadata service on 169.254.169.254 — the unspecified address and multicast.
const blockPrivateEnv = "HEALTHCHECK_BLOCK_PRIVATE"

// errBlockedTarget is returned by the dialer guard. It travels back through the
// http.Client as the request error, so a refused target is simply "down".
var errBlockedTarget = errors.New("health worker: target address is not allowed")

func StartHealthWorker(ctx context.Context, db *sql.DB) {
	slog.Info("Starting Health Check Worker...")
	runHealthChecks(db)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Health Worker stopped")
			return
		case <-ticker.C:
			runHealthChecks(db)
		}
	}
}

func runHealthChecks(db *sql.DB) {
	rows, err := db.Query("SELECT id, external_url FROM apps")
	if err != nil {
		slog.Error("Health worker: DB error", "error", err)
		return
	}
	defer rows.Close()

	blockPrivate := blockPrivateRanges()
	client := newHealthClient(blockPrivate)

	for rows.Next() {
		var id int
		// Named appURL, not url: the package of that name is used below.
		var appURL string
		if err := rows.Scan(&id, &appURL); err != nil {
			continue
		}

		start := time.Now()
		status := "down"
		respMs := 0

		// Refuse the obviously-forbidden targets BEFORE opening a socket, so a
		// misconfigured (or malicious) entry is named in the logs instead of just
		// showing up as one more red dot. The dialer guard below still runs — it is
		// the one that cannot be fooled by DNS.
		if err := checkHealthTarget(appURL, blockPrivate); err != nil {
			slog.Warn("Health worker: URL refused, not probed", "id", id, "error", err)
		} else {
			resp, err := client.Get(appURL)
			if err == nil {
				resp.Body.Close()
				respMs = int(time.Since(start).Milliseconds())
				if resp.StatusCode < 500 {
					status = "up"
				}
			} else {
				respMs = int(time.Since(start).Milliseconds())
			}
		}

		if _, err := db.Exec("UPDATE apps SET health_status = ?, health_response_ms = ?, health_last_check = NOW() WHERE id = ?",
			status, respMs, id); err != nil {
			slog.Error("Health worker: failed to update status", "id", id, "error", err)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("Health worker: row iteration error", "error", err)
	}
	slog.Debug("Health checks completed")
}

// newHealthClient builds the probing client.
//
// The SSRF guard lives in the dialer's Control hook rather than in a pre-flight
// lookup, because that hook runs with the address the kernel is ABOUT to connect
// to. Validating the URL and then letting net/http resolve the name again leaves a
// window where a host that answered 192.168.1.5 on the first lookup answers
// 169.254.169.254 on the second (DNS rebinding); here there is no second lookup to
// win. Redirects are not followed, so a 302 cannot smuggle a target past it either.
func newHealthClient(blockPrivate bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			return allowDialTarget(network, address, blockPrivate)
		},
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			// Health-checks probe user-supplied app URLs, which are frequently
			// self-signed in a homelab/PME setup; skipping verification here only
			// affects up/down probing, not data exchange.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}
}

// allowDialTarget is the last gate before the socket: it sees the resolved IP.
func allowDialTarget(network, address string, blockPrivate bool) error {
	// Anything that is not a TCP connection has no business here.
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("%w: network %q", errBlockedTarget, network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address %q", errBlockedTarget, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control is always handed a literal address; a name here would mean the
		// resolution happened somewhere we cannot see, so refuse rather than guess.
		return fmt.Errorf("%w: unresolved address %q", errBlockedTarget, host)
	}
	if reason := forbiddenIP(ip, blockPrivate); reason != "" {
		return fmt.Errorf("%w: %s (%s)", errBlockedTarget, ip, reason)
	}
	return nil
}

// checkHealthTarget validates the stored URL itself: the scheme, the presence of a
// host, and — when the host is an IP literal — the address.
//
// KNOWN LIMIT: for a hostname it does NOT resolve. That is on purpose. A pre-flight
// lookup here would be advisory at best (the name can resolve differently a
// millisecond later, which is exactly the rebinding trick) and would also make the
// worker do a DNS query per app per minute for no security gain. The guarantee is
// carried by allowDialTarget, which inspects the address actually being dialled;
// this function only buys a clear log line for the cases visible without the network.
func checkHealthTarget(raw string, blockPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed URL %q", raw)
	}
	// http/https only: file://, gopher://, ftp:// and friends turn a health check
	// into a local file reader or a protocol-smuggling primitive.
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (http and https only)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL %q has no host", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := forbiddenIP(ip, blockPrivate); reason != "" {
			return fmt.Errorf("address %s is not allowed (%s)", ip, reason)
		}
	}
	return nil
}

// forbiddenIP returns a human-readable reason when ip must not be probed, or "".
//
// Always refused, whatever the configuration:
//   - loopback (127.0.0.0/8, ::1) — that is GoaCore itself and every service bound
//     to localhost on the same host, none of which is an "application" to monitor;
//   - link-local (169.254.0.0/16, fe80::/10) — the cloud metadata service lives at
//     169.254.169.254 and hands out instance credentials to whoever asks;
//   - the unspecified address (0.0.0.0, ::) which the stack reads as "this host";
//   - multicast, which is not a health-checkable endpoint in any case.
//
// Refused only when blockPrivate is set: RFC1918, CGNAT (100.64.0.0/10) and IPv6
// ULA (fc00::/7) — the ranges a legitimate homelab/PME application actually sits on.
func forbiddenIP(ip net.IP, blockPrivate bool) string {
	// Normalise IPv4-mapped IPv6 (::ffff:127.0.0.1) so it cannot dodge the checks.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified():
		return "unspecified address"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsMulticast():
		// Covers link-local (224.0.0.0/24, ff02::/16) and interface-local multicast.
		return "multicast"
	}
	if blockPrivate && (ip.IsPrivate() || isCGNAT(ip)) {
		return "private range refused by " + blockPrivateEnv
	}
	return ""
}

// isCGNAT reports whether ip is in 100.64.0.0/10 (RFC 6598). net.IP.IsPrivate does
// not cover it, yet it is internal address space on many ISP-provided networks.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
}

// blockPrivateRanges reads the opt-in switch. An unset or unparsable value keeps the
// permissive default, so a typo can never silently blind the whole dashboard.
func blockPrivateRanges() bool {
	raw, ok := os.LookupEnv(blockPrivateEnv)
	if !ok || raw == "" {
		return false
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		slog.Warn("Health worker: unreadable value, keeping private ranges allowed",
			"env", blockPrivateEnv, "value", raw)
		return false
	}
	return b
}
