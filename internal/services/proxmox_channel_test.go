package services

import (
	"errors"
	"net"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// TestProxmoxChannel_ConfiguredAcceptsEitherKeySource verifies the migrated
// Configured() accepts BOTH the DB-first in-memory PEM and the env key FILE, and
// rejects the missing-host / missing-key cases.
func TestProxmoxChannel_ConfiguredAcceptsEitherKeySource(t *testing.T) {
	cases := []struct {
		name string
		c    *ProxmoxChannel
		want bool
	}{
		{"nil channel", nil, false},
		{"empty", &ProxmoxChannel{}, false},
		{"host only, no key", &ProxmoxChannel{host: "h:22"}, false},
		{"keyPEM only, no host", &ProxmoxChannel{keyPEM: []byte("x")}, false},
		{"keyFile only, no host", &ProxmoxChannel{keyFile: "/k"}, false},
		{"host + keyPEM (DB path)", &ProxmoxChannel{host: "h:22", keyPEM: []byte("x")}, true},
		{"host + keyFile (env path)", &ProxmoxChannel{host: "h:22", keyFile: "/k"}, true},
	}
	for _, tc := range cases {
		if got := tc.c.Configured(); got != tc.want {
			t.Errorf("%s: Configured() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNewProxmoxChannelFromKey_NormalizesHostAndHoldsKeyInMemory verifies the DB-first
// constructor normalises a port-less host and carries the PEM in memory (never a file
// path), so run() takes the in-memory parse path.
func TestNewProxmoxChannelFromKey_NormalizesHostAndHoldsKeyInMemory(t *testing.T) {
	pem := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n")
	c := NewProxmoxChannelFromKey("192.0.2.20", "goabackup", pem)
	if c.host != "192.0.2.20:22" {
		t.Errorf("host = %q, want 192.0.2.20:22 (default port appended)", c.host)
	}
	if string(c.keyPEM) != string(pem) {
		t.Error("keyPEM not carried in memory")
	}
	if c.keyFile != "" {
		t.Errorf("keyFile = %q, want empty (DB path never uses a file)", c.keyFile)
	}
	if !c.Configured() {
		t.Error("a host + in-memory PEM channel must report Configured()")
	}
}

// TestChannelRegistry_HotReloadAndRollback exercises the registry's atomic lifecycle:
// seed env → provision (ApplyChannel) → rollback. It is the channel analogue of the
// ServiceRegistry seed/apply tests.
func TestChannelRegistry_HotReloadAndRollback(t *testing.T) {
	// Env-derived (key FILE) channel frozen as the rollback fallback.
	envCh := NewProxmoxChannel(nil) // unconfigured env
	envCh = &ProxmoxChannel{host: "envhost:22", keyFile: "/etc/goabackup.key"}
	reg := NewChannelRegistry(envCh)

	// Boot: the live channel is the env one.
	if got := reg.Channel(); got != envCh {
		t.Fatal("fresh registry must return the seeded env channel")
	}
	if reg.EnvChannel() != envCh {
		t.Error("EnvChannel() must return the frozen env fallback")
	}

	// Provision: a fresh in-app key (in-memory PEM) hot-reloads the live channel via a
	// single swap; the env fallback is untouched.
	k, err := GenerateEd25519Key("goabackup-channel")
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	reg.ApplyChannel("10.0.0.1:22", "goabackup", []byte(k.PrivateKey))
	live := reg.Channel()
	if live == envCh {
		t.Fatal("ApplyChannel must publish a NEW channel, not the env one")
	}
	if live.host != "10.0.0.1:22" || len(live.keyPEM) == 0 || live.keyFile != "" {
		t.Errorf("live channel after provision is wrong: host=%q keyPEM=%d keyFile=%q",
			live.host, len(live.keyPEM), live.keyFile)
	}
	if reg.EnvChannel() != envCh {
		t.Error("ApplyChannel must NOT mutate the frozen env fallback")
	}

	// Rollback (delete-without-env-key would publish env): live reverts to the env one.
	restored := reg.RollbackToEnv()
	if restored != envCh || reg.Channel() != envCh {
		t.Error("RollbackToEnv must republish the frozen env channel")
	}
}

// TestNewChannelRegistry_NilEnvNeverReturnsNilChannel verifies the registry never
// hands a nil channel even when seeded with nil: Channel() returns a real (unconfigured)
// channel so every caller can safely call Configured()/ops.
func TestNewChannelRegistry_NilEnvNeverReturnsNilChannel(t *testing.T) {
	reg := NewChannelRegistry(nil)
	if reg.Channel() == nil {
		t.Fatal("Channel() must never return nil")
	}
	if reg.Channel().Configured() {
		t.Error("a nil-seeded registry channel must be unconfigured")
	}
	// ApplyChannelClient(nil) also degrades to an unconfigured channel, never nil.
	reg.ApplyChannelClient(nil)
	if reg.Channel() == nil || reg.Channel().Configured() {
		t.Error("ApplyChannelClient(nil) must publish a non-nil, unconfigured channel")
	}
}

// chanProviderStub adapts a fixed channel to ChannelProvider for the BackupService
// wiring test (it is the test double for the registry).
type chanProviderStub struct{ c *ProxmoxChannel }

func (p chanProviderStub) Channel() *ProxmoxChannel { return p.c }

// TestBackupService_LiveChannelResolution verifies liveChannel() resolves through the
// provider (hot-reload aware) and never returns nil, including the unset-provider and
// provider-returns-nil cases.
func TestBackupService_LiveChannelResolution(t *testing.T) {
	s := newTestBackupService()

	// No provider wired → liveChannel() is a non-nil, unconfigured channel.
	if got := s.liveChannel(); got == nil || got.Configured() {
		t.Error("unset provider: liveChannel() must be non-nil and unconfigured")
	}

	// Provider returning nil → still non-nil, unconfigured.
	s.SetChannelProvider(chanProviderStub{c: nil})
	if got := s.liveChannel(); got == nil || got.Configured() {
		t.Error("nil-returning provider: liveChannel() must be non-nil and unconfigured")
	}

	// A configured channel flows through.
	ch := &ProxmoxChannel{host: "h:22", keyPEM: []byte("x")}
	s.SetChannelProvider(chanProviderStub{c: ch})
	if got := s.liveChannel(); got != ch {
		t.Error("liveChannel() must return the provider's channel")
	}

	// SetChannel shim wraps a frozen pointer in a static provider.
	s.SetChannel(ch)
	if got := s.liveChannel(); got != ch {
		t.Error("SetChannel shim must make liveChannel() return the frozen channel")
	}
}

// channelHostKeysStub records the host the channel asked to verify and hands back a
// callback whose verdict the test controls.
type channelHostKeysStub struct {
	askedIP string
	verdict error
}

func (s *channelHostKeysStub) SSHHostKeyCallback(ip string) gossh.HostKeyCallback {
	s.askedIP = ip
	return func(string, net.Addr, gossh.PublicKey) error { return s.verdict }
}

// TestProxmoxChannel_RefusesWithoutHostKeyStore is the fail-closed contract: with no
// TOFU store wired, the channel must NOT dial an unverified Proxmox. Falling back to
// InsecureIgnoreHostKey here would let a machine-in-the-middle forge the cryptcheck and
// healthcheck verdicts — i.e. forge the restorability proof itself.
func TestProxmoxChannel_RefusesWithoutHostKeyStore(t *testing.T) {
	SetDefaultChannelHostKeys(nil)
	t.Cleanup(func() { SetDefaultChannelHostKeys(nil) })

	c := NewProxmoxChannelFromKey("192.0.2.20", "goabackup", []byte("irrelevant"))
	if _, err := c.hostKeyCallback(); !errors.Is(err, ErrNoChannelHostKeys) {
		t.Fatalf("hostKeyCallback() error = %v, want ErrNoChannelHostKeys", err)
	}

	// The refusal must surface on a real operation too, before any dial is attempted.
	if _, err := c.DiskFree(); !errors.Is(err, ErrNoChannelHostKeys) {
		t.Errorf("DiskFree() error = %v, want ErrNoChannelHostKeys", err)
	}
}

// TestProxmoxChannel_VerifiesAgainstPinnedHostKey checks the channel verifies through
// the shared TOFU store, keyed by the BARE host (the key the console pins under), and
// that a changed host key is propagated as a hard failure rather than swallowed.
func TestProxmoxChannel_VerifiesAgainstPinnedHostKey(t *testing.T) {
	SetDefaultChannelHostKeys(nil)
	t.Cleanup(func() { SetDefaultChannelHostKeys(nil) })

	store := &channelHostKeysStub{}
	c := NewProxmoxChannelFromKey("192.0.2.20", "goabackup", []byte("irrelevant"),
		WithChannelHostKeys(store))

	cb, err := c.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback(): %v", err)
	}
	if store.askedIP != "192.0.2.20" {
		t.Errorf("TOFU store keyed on %q, want the bare host 192.0.2.20 (no :22)", store.askedIP)
	}
	if err := cb("192.0.2.20:22", nil, nil); err != nil {
		t.Errorf("a pinned host must be accepted, got %v", err)
	}

	// A host key that no longer matches the pin is an explicit refusal.
	store.verdict = errors.New("clé hôte SSH modifiée pour 192.0.2.20 — possible attaque MITM")
	cb, err = c.hostKeyCallback()
	if err != nil {
		t.Fatalf("hostKeyCallback(): %v", err)
	}
	if err := cb("192.0.2.20:22", nil, nil); err == nil {
		t.Error("a changed host key must fail the connection, not be ignored")
	}
}

// TestProxmoxChannel_HostKeyStorePrecedence verifies an explicit store wins over the
// package default, and that a nil option leaves the default in place (so an optional
// dependency can be passed without branching at the call site).
func TestProxmoxChannel_HostKeyStorePrecedence(t *testing.T) {
	fallback := &channelHostKeysStub{}
	SetDefaultChannelHostKeys(fallback)
	t.Cleanup(func() { SetDefaultChannelHostKeys(nil) })

	explicit := &channelHostKeysStub{}
	c := NewProxmoxChannelFromKey("10.0.0.9", "goabackup", []byte("k"), WithChannelHostKeys(explicit))
	if _, err := c.hostKeyCallback(); err != nil {
		t.Fatalf("hostKeyCallback(): %v", err)
	}
	if explicit.askedIP != "10.0.0.9" || fallback.askedIP != "" {
		t.Error("an explicit WithChannelHostKeys store must win over the package default")
	}

	// nil option → package default still used.
	c = NewProxmoxChannelFromKey("10.0.0.9", "goabackup", []byte("k"), WithChannelHostKeys(nil))
	if _, err := c.hostKeyCallback(); err != nil {
		t.Fatalf("hostKeyCallback(): %v", err)
	}
	if fallback.askedIP != "10.0.0.9" {
		t.Error("a nil store option must be ignored so the package default applies")
	}

	// The env constructor takes options too (the boot channel must be verified as well).
	envCh := NewProxmoxChannel(nil, WithChannelHostKeys(explicit))
	if envCh.hostKeys != explicit {
		t.Error("NewProxmoxChannel must honour ChannelOption")
	}
}

// TestChannelHostOnly strips the SSH port so the pin is shared with the console's,
// including for an IPv6 literal target.
func TestChannelHostOnly(t *testing.T) {
	cases := map[string]string{
		"192.0.2.20:22":    "192.0.2.20",
		"192.0.2.20":       "192.0.2.20",
		"pve.local:22":     "pve.local",
		"[2001:db8::1]:22": "2001:db8::1",
		"":                 "",
	}
	for in, want := range cases {
		if got := channelHostOnly(in); got != want {
			t.Errorf("channelHostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
