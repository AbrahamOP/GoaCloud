package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"goacore/internal/config"

	gossh "golang.org/x/crypto/ssh"
)

// ProxmoxChannel is the client for the "goabackup" helper that runs on the Proxmox
// host. The helper is exposed over SSH with a forced-command: the string we send via
// session.Output(op) becomes the operation, and the helper replies with a single line
// of JSON. We never run arbitrary shell here — the host side decides what each op
// maps to.
//
// Scope of the channel: it is NOT a strictly read-only access. Most ops only read
// (disk-free, ping, healthcheck, cryptcheck, rclone-remotes, rclone-about), but
// rclone-push writes off-site AND deletes the local vzdump archive it just pushed
// when the caller asks not to keep it (RclonePush keepLocal=false). Describe it as a
// forced-command channel, never as "read-only" — the UI wording must match.
//
// HostKeyCallback: the channel carries the PROOF of restorability (the cryptcheck and
// healthcheck verdicts), so a machine-in-the-middle able to answer for the Proxmox
// host forges the proof itself. The host identity is therefore verified against the
// persisted TOFU store shared with the SSH console (table ssh_host_keys): pinned on
// first contact — in practice the install-time probe — and an explicit hard failure on
// any later change. See ChannelHostKeys.
type ProxmoxChannel struct {
	host string
	user string

	// keyPEM is the in-memory OpenSSH private key (the in-app-generated ed25519 key
	// loaded from the encrypted DB row). When present it takes PRECEDENCE over keyFile:
	// the private key NEVER touches the GoaCore disk on this path. keyFile is the
	// retro-compat fallback (GOABACKUP_SSH_KEY_FILE — the HomeLab instance mounts it),
	// used only when keyPEM is empty. Exactly one of the two is the live source.
	keyPEM  []byte
	keyFile string

	// hostKeys is the TOFU store this channel verifies the Proxmox host against. nil
	// means "use the package default" (SetDefaultChannelHostKeys); when both are nil
	// run() refuses rather than dialling an unverified host.
	hostKeys ChannelHostKeys
}

// ChannelHostKeys is the persisted Trust-On-First-Use store the channel verifies the
// Proxmox host key against. The single implementation is *SSHService, whose
// SSHHostKeyCallback pins into the shared ssh_host_keys table — the very store the
// console and the key deployment already use. Sharing it is deliberate: GoaCore keeps
// ONE source of truth on host identity, so the fingerprint pinned when the admin
// installs the channel is the one every later verdict is read through.
type ChannelHostKeys interface {
	// SSHHostKeyCallback returns a callback that pins the host key on first contact
	// and refuses the connection once a pinned key changes.
	SSHHostKeyCallback(ip string) gossh.HostKeyCallback
}

// Compile-time proof that the shared SSH TOFU store satisfies the channel's needs.
var _ ChannelHostKeys = (*SSHService)(nil)

// ErrNoChannelHostKeys signals a wiring error: no TOFU store was registered, so the
// Proxmox host identity cannot be verified. Operations refuse rather than fall back to
// an unauthenticated host — a forged verdict is worse than a missing one.
var ErrNoChannelHostKeys = errors.New("no host-key store registered: cannot verify the Proxmox host identity")

var (
	defaultChannelHostKeysMu sync.RWMutex
	defaultChannelHostKeys   ChannelHostKeys
)

// SetDefaultChannelHostKeys registers the TOFU store used by every channel built
// without an explicit WithChannelHostKeys option (the boot/env channel and the
// registry's hot-reload path). Call it ONCE at startup with the *SSHService — it is
// the channel counterpart of SetDefaultHostKeyStore for Ansible.
func SetDefaultChannelHostKeys(store ChannelHostKeys) {
	defaultChannelHostKeysMu.Lock()
	defer defaultChannelHostKeysMu.Unlock()
	defaultChannelHostKeys = store
}

// channelHostKeyStore returns the registered default store (nil when none).
func channelHostKeyStore() ChannelHostKeys {
	defaultChannelHostKeysMu.RLock()
	defer defaultChannelHostKeysMu.RUnlock()
	return defaultChannelHostKeys
}

// ChannelOption configures a channel at construction time.
type ChannelOption func(*ProxmoxChannel)

// WithChannelHostKeys pins the TOFU store this channel verifies the Proxmox host
// against, overriding the package default. A nil store is ignored so callers can pass
// an optional dependency without branching.
func WithChannelHostKeys(store ChannelHostKeys) ChannelOption {
	return func(c *ProxmoxChannel) {
		if store != nil {
			c.hostKeys = store
		}
	}
}

// NewProxmoxChannel builds a channel client from config (the env/file path). It is
// always safe to build (no I/O here); operations fail with a clear error if the
// channel is not configured (missing host/key), so the restore-test feature degrades
// gracefully. This is the retro-compat constructor that keeps reading the key from
// GOABACKUP_SSH_KEY_FILE — the HomeLab instance must NOT regress.
func NewProxmoxChannel(cfg *config.Config, opts ...ChannelOption) *ProxmoxChannel {
	c := &ProxmoxChannel{}
	if cfg != nil {
		c.host = normalizeChannelHost(cfg.GoabackupSSHHost)
		c.user = cfg.GoabackupSSHUser
		c.keyFile = cfg.GoabackupSSHKeyFile
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewProxmoxChannelFromKey builds a channel client holding the private key IN MEMORY
// (the in-app-generated ed25519 key decrypted from the DB row). The PEM never lands
// on disk: run() parses it directly. user empties to "goabackup" at run time. This is
// the DB-first path; pass an empty host to publish an unconfigured (degraded) channel.
func NewProxmoxChannelFromKey(host, user string, keyPEM []byte, opts ...ChannelOption) *ProxmoxChannel {
	c := &ProxmoxChannel{
		host:   normalizeChannelHost(host),
		user:   user,
		keyPEM: keyPEM,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// normalizeChannelHost appends the default SSH port when the host carries none, so
// gossh.Dial always receives an "ip:port" target. An empty host stays empty (the
// channel reports unconfigured).
func normalizeChannelHost(host string) string {
	if host != "" && !strings.Contains(host, ":") {
		host += ":22"
	}
	return host
}

// channelHostOnly strips the SSH port from the dial target so the TOFU store is keyed
// by the BARE host — the same key the console and the key deployment pin under, so a
// host already trusted there is not re-pinned (nor silently re-trusted) here. A target
// without a port is returned unchanged.
func channelHostOnly(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}

// Configured reports whether the channel has the minimum settings to operate: a host
// plus a usable key (the in-memory PEM OR the fallback key file). The DB-first path
// (keyPEM) and the env path (keyFile) are both accepted.
func (c *ProxmoxChannel) Configured() bool {
	return c != nil && c.host != "" && (len(c.keyPEM) > 0 || c.keyFile != "")
}

// hostKeyCallback resolves the TOFU verification for this channel: the store pinned at
// construction, else the package default. First contact pins the Proxmox host key in
// ssh_host_keys (keyed by the BARE host, shared with the console); any later change is
// a hard, explicit failure.
//
// No store at all is a wiring error, NOT a licence to skip the check: the cryptcheck and
// healthcheck answers this channel carries ARE the restorability proof, so a host that
// can be impersonated is a proof that can be forged. We refuse instead.
func (c *ProxmoxChannel) hostKeyCallback() (gossh.HostKeyCallback, error) {
	store := c.hostKeys
	if store == nil {
		store = channelHostKeyStore()
	}
	if store == nil {
		return nil, fmt.Errorf("proxmox channel: %w", ErrNoChannelHostKeys)
	}
	return store.SSHHostKeyCallback(channelHostOnly(c.host)), nil
}

// run sends a single operation over a fresh SSH session and returns the raw
// stdout (expected to be one line of JSON). It is nil-safe and never panics.
func (c *ProxmoxChannel) run(op string, timeout time.Duration) (string, error) {
	if c == nil {
		return "", fmt.Errorf("proxmox channel: not configured")
	}
	if c.host == "" || (len(c.keyPEM) == 0 && c.keyFile == "") {
		return "", fmt.Errorf("proxmox channel: not configured (missing host or key)")
	}

	// Resolve the host-key verification FIRST: an unverifiable host is a refusal, and
	// there is no point reading a private key we would not be allowed to use.
	hostKeyCB, err := c.hostKeyCallback()
	if err != nil {
		return "", err
	}

	// Key source precedence: the in-memory PEM (DB-provisioned, never on disk) wins;
	// the key FILE (GOABACKUP_SSH_KEY_FILE) is the retro-compat fallback only when no
	// PEM is loaded. An empty PEM is treated as "no DB key" so the file path is tried.
	keyBytes := c.keyPEM
	if len(keyBytes) == 0 {
		fileBytes, err := os.ReadFile(c.keyFile)
		if err != nil {
			return "", fmt.Errorf("proxmox channel: read key %s: %w", c.keyFile, err)
		}
		keyBytes = fileBytes
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("proxmox channel: parse private key: %w", err)
	}

	user := c.user
	if user == "" {
		user = "goabackup"
	}

	clientCfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
		Timeout:         15 * time.Second,
	}

	client, err := gossh.Dial("tcp", c.host, clientCfg)
	if err != nil {
		return "", fmt.Errorf("proxmox channel: dial %s: %w", c.host, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("proxmox channel: new session: %w", err)
	}
	defer session.Close()

	// Enforce the per-operation timeout: if Output overruns, close the session
	// to unblock and surface a timeout error.
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, runErr := session.Output(op)
		done <- result{out: out, err: runErr}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			return "", fmt.Errorf("proxmox channel: op %q failed: %w", op, res.err)
		}
		return strings.TrimSpace(string(res.out)), nil
	case <-time.After(timeout):
		_ = session.Close()
		return "", fmt.Errorf("proxmox channel: op %q timed out after %s", op, timeout)
	}
}

// cryptRemoteFallback is the hard default rclone remote for the off-site integrity
// check when the caller passes an empty remote. It mirrors config.cryptRemoteFallback
// (kept in sync; both are "gcrypt") so the channel is self-contained without
// importing an unexported const.
const cryptRemoteFallback = "gcrypt"

// channelEnvelope is the common shell of every helper response.
type channelEnvelope struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// DiskInfo is the backend-aware result of the disk pre-flight probe. Backend is the
// detected dump-storage backend ("lvmthin" / "zfspool" / "dir" / "unknown"). The
// thin-pool ceiling guard is meaningful ONLY when Backend=="lvmthin": on every other
// backend ThinDataPct is 0 and MUST NOT be read as "0% used ⇒ always pass" — the
// universal LocalAvailBytes floor is the guard there.
type DiskInfo struct {
	Backend         string
	ThinDataPct     float64
	ThinMetaPct     float64
	LocalAvailBytes int64
	// AvailProbe is the helper's df-probe outcome: "ok" when df succeeded (LocalAvailBytes
	// is a real reading, possibly a genuine 0), "failed" when df errored (e.g. the resolved
	// dump dir does not exist) so LocalAvailBytes=0 is a BLIND probe, not a real 0. An older
	// helper omits the field → "" → treated as a blind probe only when nothing else guards.
	AvailProbe string
}

// HasThinPoolCeiling reports whether the thin-pool data ceiling guard applies to
// this reading: a usable lvmthin backend with a non-zero percentage. This is the
// single decision point that prevents an absent/0 thin_data_pct on ZFS/dir from
// being mistaken for "0% used".
func (d DiskInfo) HasThinPoolCeiling() bool {
	return d.Backend == "lvmthin" && d.ThinDataPct > 0
}

// IsBlindProbe reports whether the disk sonde gave NO usable guard at all: the
// df probe failed (AvailProbe=="failed") OR it returned 0 bytes on a backend that
// offers no thin-pool ceiling. In that state both the avail floor (skipped on a 0)
// and the thin-pool ceiling (no lvmthin reading) are inert, so a destructive restore
// would proceed with zero disk protection — which the restore engine must refuse
// rather than fail-open. This is the Go counterpart of the helper's lvs/df fail-soft:
// the helper degrades to "unknown" without aborting, and the engine turns a totally
// blind reading into a hard refusal.
func (d DiskInfo) IsBlindProbe() bool {
	// Any usable guard makes the probe non-blind: a thin-pool ceiling, or a positive
	// avail floor (a real number we can compare against minLocalAvailBytes).
	if d.HasThinPoolCeiling() || d.LocalAvailBytes > 0 {
		return false
	}
	// No ceiling AND no positive avail. Either df explicitly errored (AvailProbe=="failed",
	// so the 0 is a blind reading) or the backend simply offers nothing to guard on —
	// in both cases there is no effective disk guard, so treat it as blind.
	return true
}

// DiskFree returns the backend-aware disk pre-flight reading used as a guard before
// a destructive restore. The helper always emits a `backend` field; an older helper
// without it yields Backend=="" → the ceiling guard is skipped (HasThinPoolCeiling
// is false) and only the universal avail floor applies, which is the safe default.
func (c *ProxmoxChannel) DiskFree() (DiskInfo, error) {
	raw, err := c.run("disk-free", 30*time.Second)
	if err != nil {
		return DiskInfo{}, err
	}
	var resp struct {
		channelEnvelope
		Backend         string  `json:"backend"`
		ThinDataPct     float64 `json:"thin_data_pct"`
		ThinMetaPct     float64 `json:"thin_meta_pct"`
		LocalAvailBytes int64   `json:"local_avail_bytes"`
		AvailProbe      string  `json:"avail_probe"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return DiskInfo{}, fmt.Errorf("proxmox channel: decode disk-free %q: %w", raw, jerr)
	}
	if !resp.OK {
		return DiskInfo{}, fmt.Errorf("proxmox channel: disk-free not ok: %s", resp.Error)
	}
	return DiskInfo{
		Backend:         resp.Backend,
		ThinDataPct:     resp.ThinDataPct,
		ThinMetaPct:     resp.ThinMetaPct,
		LocalAvailBytes: resp.LocalAvailBytes,
		AvailProbe:      resp.AvailProbe,
	}, nil
}

// Cryptcheck asks the helper to verify the off-site (crypt) archive integrity for
// a VMID against a specific rclone remote. The remote is no longer hardcoded host-
// side ("gcrypt"): the engine resolves it (DB extra_json / env / hard default) and
// passes it here so a PME whose crypt remote is not named "gcrypt" is supported. An
// empty remote floors to the hard default so an old caller still works. The helper
// re-validates the remote host-side against `rclone listremotes` (the trust never
// moves app→host). Returns ok and a human-readable detail.
func (c *ProxmoxChannel) Cryptcheck(vmid int, remote string) (ok bool, detail string, err error) {
	if remote == "" {
		remote = cryptRemoteFallback
	}
	// cryptcheck can stream/verify a large archive — give it a generous timeout.
	raw, err := c.run(fmt.Sprintf("cryptcheck %d %s", vmid, remote), 200*time.Second)
	if err != nil {
		return false, "", err
	}
	var resp struct {
		channelEnvelope
		Differences int    `json:"differences"`
		Errors      int    `json:"errors"`
		Detail      string `json:"detail"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return false, "", fmt.Errorf("proxmox channel: decode cryptcheck %q: %w", raw, jerr)
	}
	detail = resp.Detail
	if detail == "" {
		detail = fmt.Sprintf("differences=%d errors=%d", resp.Differences, resp.Errors)
	}
	verified := resp.OK && resp.Differences == 0 && resp.Errors == 0
	return verified, detail, nil
}

// Healthcheck asks the helper to probe a service/port inside a (sandbox) guest.
// kind is "service" or "port"; arg is the service name / port number. The vmid
// MUST be in the sandbox range; the helper enforces it too, but we guard here.
func (c *ProxmoxChannel) Healthcheck(vmid int, gtype, kind, arg string) (ok bool, detail string, err error) {
	if !isSandboxVMID(vmid) {
		return false, "", fmt.Errorf("proxmox channel: healthcheck refused, vmid %d outside sandbox range", vmid)
	}
	op := fmt.Sprintf("healthcheck %d %s %s %s", vmid, gtype, kind, arg)
	raw, err := c.run(op, 30*time.Second)
	if err != nil {
		return false, "", err
	}
	var resp struct {
		channelEnvelope
		Detail string `json:"detail"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return false, "", fmt.Errorf("proxmox channel: decode healthcheck %q: %w", raw, jerr)
	}
	return resp.OK, resp.Detail, nil
}

// RcloneRemotes lists the rclone remotes configured on the Proxmox host. The list
// is fully dynamic — GoaCore never hardcodes remote names; the user picks among
// THEIR own remotes. Helper op: "rclone-remotes" → {"ok":true,"remotes":[...]}.
func (c *ProxmoxChannel) RcloneRemotes() ([]string, error) {
	raw, err := c.run("rclone-remotes", 30*time.Second)
	if err != nil {
		return nil, err
	}
	var resp struct {
		channelEnvelope
		Remotes []string `json:"remotes"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return nil, fmt.Errorf("proxmox channel: decode rclone-remotes %q: %w", raw, jerr)
	}
	if !resp.OK {
		return nil, fmt.Errorf("proxmox channel: rclone-remotes not ok: %s", resp.Error)
	}
	return resp.Remotes, nil
}

// RcloneAbout returns the used/free/total bytes reported by `rclone about` for a
// remote, to render its capacity in the UI. Any of the three may be 0 when the
// backend does not report it. Helper op: "rclone-about <remote>".
func (c *ProxmoxChannel) RcloneAbout(remote string) (used, free, total int64, err error) {
	if strings.TrimSpace(remote) == "" {
		return 0, 0, 0, fmt.Errorf("proxmox channel: rclone-about requires a remote")
	}
	raw, err := c.run("rclone-about "+remote, 30*time.Second)
	if err != nil {
		return 0, 0, 0, err
	}
	var resp struct {
		channelEnvelope
		Used  int64 `json:"used"`
		Free  int64 `json:"free"`
		Total int64 `json:"total"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return 0, 0, 0, fmt.Errorf("proxmox channel: decode rclone-about %q: %w", raw, jerr)
	}
	if !resp.OK {
		return 0, 0, 0, fmt.Errorf("proxmox channel: rclone-about not ok: %s", resp.Error)
	}
	return resp.Used, resp.Free, resp.Total, nil
}

// RclonePush copies the latest local vzdump archive of vmid to a remote. When
// keepLocal is false the local copy is removed after a successful push (true
// off-site destination); when true the local copy is kept (local + remote). The
// push streams a potentially large archive, so it uses a long timeout. Returns
// the archive name reported by the helper. Helper op:
// "rclone-push <vmid> <remote> <keeplocal 0|1>".
func (c *ProxmoxChannel) RclonePush(vmid int, remote string, keepLocal bool) (archive string, err error) {
	if strings.TrimSpace(remote) == "" {
		return "", fmt.Errorf("proxmox channel: rclone-push requires a remote")
	}
	keep := "0"
	if keepLocal {
		keep = "1"
	}
	op := fmt.Sprintf("rclone-push %d %s %s", vmid, remote, keep)
	// A push streams the whole archive off-site — give it a generous timeout.
	raw, err := c.run(op, 200*time.Second)
	if err != nil {
		return "", err
	}
	var resp struct {
		channelEnvelope
		Archive   string `json:"archive"`
		KeptLocal string `json:"kept_local"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return "", fmt.Errorf("proxmox channel: decode rclone-push %q: %w", raw, jerr)
	}
	if !resp.OK {
		return "", fmt.Errorf("proxmox channel: rclone-push not ok: %s", resp.Error)
	}
	return resp.Archive, nil
}

// Ping returns the lifecycle status of a sandbox guest: "running", "stopped" or
// "absent". Used to find a free sandbox slot and to confirm boot.
func (c *ProxmoxChannel) Ping(vmid int) (status string, err error) {
	if !isSandboxVMID(vmid) {
		return "", fmt.Errorf("proxmox channel: ping refused, vmid %d outside sandbox range", vmid)
	}
	raw, err := c.run(fmt.Sprintf("ping %d", vmid), 30*time.Second)
	if err != nil {
		return "", err
	}
	var resp struct {
		channelEnvelope
		Status string `json:"status"`
	}
	if jerr := json.Unmarshal([]byte(raw), &resp); jerr != nil {
		return "", fmt.Errorf("proxmox channel: decode ping %q: %w", raw, jerr)
	}
	if !resp.OK {
		return "", fmt.Errorf("proxmox channel: ping not ok: %s", resp.Error)
	}
	return resp.Status, nil
}
