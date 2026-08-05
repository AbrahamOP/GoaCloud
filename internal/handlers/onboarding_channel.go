package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"goacore/deploy/goabackup"
	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/services"
)

// This file is the onboarding pipeline for the Proxmox helper CHANNEL
// (service='goabackup-channel'), the off-site backup/restore-test data path. It is
// deliberately UNLIKE the other onboarding panels: GoaCore GENERATES an ed25519 key
// in-app, persists the private PEM encrypted, and SERVES an auditable install SCRIPT
// that the client admin runs IN ROOT on THEIR OWN Proxmox. GoaCore NEVER opens an SSH
// session to install — there is zero trust movement app→host at install time. The
// private key never touches the GoaCore disk and is NEVER returned by any GET/test.
//
// The channel is a FORCED-COMMAND channel, not a read-only one: rclone-push writes
// off-site and can delete the local vzdump archive it just pushed. The wording served
// to the admin says so explicitly — promising "lecture seule" would be a lie the helper
// does not keep.
//
// Every Admin endpoint re-checks RequireAdmin inline (defence in depth — the route
// group is already Admin-only). The ONE exception is the installer download, which by
// construction is fetched from a root shell that carries no session cookie: it lives on
// a PUBLIC route authenticated by a single-use, short-lived token minted in-app (see
// installerTokenStore). Behind the admin session it would follow the 303 to /login and
// hand a 200 HTML page to `sudo bash`.

const (
	// defaultChannelUser is the SSH login the helper expects (matches the script's
	// useradd and the env default GOABACKUP_SSH_USER). The provision flow always uses
	// this fixed login — the admin does not choose it.
	defaultChannelUser = "goabackup"

	// channelKeyComment is the comment baked into the generated key's name. It is
	// purely cosmetic (it does not appear in the authorized_keys forced-command line,
	// which we build ourselves) but documents the key's purpose if ever inspected.
	channelKeyComment = "goabackup-channel@goacloud"

	// channelInstallerPath is the PUBLIC (token-authenticated) installer route. It is
	// public on purpose: the admin runs the curl from a Proxmox root shell that has no
	// GoaCore session. Behind the session gate, curl -L would follow the 303 to /login,
	// receive the login page with a 200 (so -f never trips) and pipe HTML into bash.
	channelInstallerPath = "/canal/installer.sh"

	// channelInstallerTokenTTL bounds a one-time installer token's life. It only has to
	// survive a copy-paste from the browser into a root shell, so minutes is plenty —
	// and a leaked command line stops being useful very quickly.
	channelInstallerTokenTTL = 15 * time.Minute

	// channelInstallerTokenMax caps the number of live tokens so repeated page renders
	// can never grow the store without bound. The oldest grant is evicted at the cap.
	channelInstallerTokenMax = 32
)

// installerGrant is a pending one-time authorisation to download the install script.
// instanceHost is the host the grant was minted for: the served script embeds it, so
// binding it here makes the served bytes — and therefore their sha256 — independent of
// whatever Host header the curl arrives with.
type installerGrant struct {
	expires      time.Time
	instanceHost string
}

// installerTokenStore holds the outstanding one-time installer tokens. Tokens are 256
// bits of crypto/rand, valid for channelInstallerTokenTTL, and BURNED on the first
// lookup — a second curl on the same URL gets a 403, so a command line left in a shell
// history or a proxy log is not a replayable download of the install script.
//
// In-memory on purpose: a token must not outlive the process (a restart is a new
// onboarding), and the store is per-instance state, not persisted configuration.
type installerTokenStore struct {
	mu     sync.Mutex
	tokens map[string]installerGrant
}

// channelInstallerTokens is the process-wide store. The wizard mints into it when it
// renders the command and burns from it when the Proxmox fetches the script.
var channelInstallerTokens = &installerTokenStore{tokens: make(map[string]installerGrant)}

// issue mints a fresh single-use token bound to instanceHost.
func (s *installerTokenStore) issue(instanceHost string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("installer token: %w", err)
	}
	token := hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.gcLocked(now)
	s.evictOldestLocked()
	s.tokens[token] = installerGrant{expires: now.Add(channelInstallerTokenTTL), instanceHost: instanceHost}
	return token, nil
}

// consume looks a token up and removes it in the same critical section — single use is
// enforced even when two curls race. An expired grant is burned too and reported as
// invalid, so a stale token can never be retried into validity.
func (s *installerTokenStore) consume(token string) (installerGrant, bool) {
	if token == "" {
		return installerGrant{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.gcLocked(now)
	grant, ok := s.tokens[token]
	if !ok {
		return installerGrant{}, false
	}
	delete(s.tokens, token)
	if now.After(grant.expires) {
		return installerGrant{}, false
	}
	return grant, true
}

// revokeAll burns every outstanding grant. Called on provision: rotating the key makes
// every previously displayed command obsolete, and failing on the TOKEN gives the admin
// a clear "recopiez la commande" instead of a puzzling hash mismatch.
func (s *installerTokenStore) revokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.tokens)
}

// gcLocked drops expired grants. Callers hold s.mu.
func (s *installerTokenStore) gcLocked(now time.Time) {
	for token, grant := range s.tokens {
		if now.After(grant.expires) {
			delete(s.tokens, token)
		}
	}
}

// evictOldestLocked makes room for one more grant when the store sits at its cap, by
// dropping the one closest to expiry. Callers hold s.mu.
func (s *installerTokenStore) evictOldestLocked() {
	for len(s.tokens) >= channelInstallerTokenMax {
		var oldest string
		var oldestExp time.Time
		for token, grant := range s.tokens {
			if oldest == "" || grant.expires.Before(oldestExp) {
				oldest, oldestExp = token, grant.expires
			}
		}
		delete(s.tokens, oldest)
	}
}

// channelProvisionResponse is returned by the provision POST. It carries the
// non-secret material the UI needs to render step 2 (the root command + the helper
// integrity hash) and the fingerprint for display. It NEVER carries the private key.
type channelProvisionResponse struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"public_key,omitempty"` // the ed25519 authorized_keys line (public)
	HelperSHA   string `json:"helper_sha256,omitempty"`
	// InstallerSHA is the sha256 of the EXACT script the returned URL will serve. It
	// reaches the admin through the browser's TLS-verified page, and the returned
	// Command compares the download against THIS value — never against a digest
	// re-fetched over the same `curl -k` channel, which an interceptor would simply
	// serve consistently with a tampered script.
	InstallerSHA string `json:"installer_sha256,omitempty"`
	InstallerURL string `json:"installer_url,omitempty"` // public token URL, single use
	Command      string `json:"command,omitempty"`       // the copy-paste root command
}

// channelTestResponse is returned by the live "Vérifier l'installation" probe. It
// proves the channel works end-to-end (disk-free over SSH forced-command) WITHOUT
// ever exposing the key. Kind mirrors the other services ("network"/"api") so the UI
// can phrase a transient failure differently from a hard one.
type channelTestResponse struct {
	OK    bool   `json:"ok"`
	Kind  string `json:"kind,omitempty"`
	Error string `json:"error,omitempty"`
	// Detail carries a human-readable, secret-free proof line on success (e.g. the
	// detected backend + free space) so the UI can show concrete evidence.
	Detail string `json:"detail,omitempty"`
}

// channelCardData is the page view model. The private key is represented ONLY by
// SecretPresent — its value is never sent to the template.
type channelCardData struct {
	Configured    bool
	Source        string // "db" | "env" | "unconfigured"
	Status        string // "ok" | "error" | "unknown"
	SecretPresent bool
	EnvImportable bool
	CanRollback   bool
	LastError     string
	Host          string
	User          string
	Fingerprint   string
	KeyType       string
	HasInAppKey   bool // a DB row carrying a real ed25519 PEM (≠ an env-seeded host-only row)
}

// HandleOnboardingChannel serves the Admin-only canal wizard page (GET only). The
// provision/test/installer/delete actions are separate endpoints the page calls.
func (h *Handler) HandleOnboardingChannel(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	h.renderChannel(w, r, "", "")
}

// renderChannel gathers the channel card and renders the wizard template. errMsg/okMsg
// are optional banners. The private key is never sent to the template.
func (h *Handler) renderChannel(w http.ResponseWriter, r *http.Request, errMsg, okMsg string) {
	card := h.channelCard()
	// Mint the install material for THIS render: a single-use token so the command
	// works from a cookie-less root shell, and the sha256 of the exact script that
	// token will serve so the command can verify what it downloaded against a digest
	// that travelled over the browser's TLS-verified connection.
	installerURL, installerSHA, command := h.channelInstallMaterial(r)
	data := map[string]any{
		"User":    middleware.GetSessionUser(r, h.SessionStore),
		"Error":   errMsg,
		"Success": okMsg,
		"Channel": card,
		// The host-derived installer URL is injected so the <pre> command in step 2 is
		// always the CURRENT instance's URL (sovereignty: never a hard-coded domain).
		"InstallerURL": installerURL,
		// The integrity digest displayed in the UI, and the ready-to-paste command that
		// checks the download against it.
		"InstallerSHA":   installerSHA,
		"InstallCommand": command,
		// The fixed SSH login the script provisions, shown in the prerequisites encart.
		"ChannelUser": defaultChannelUser,
		// The host-side revocation command shown at delete time (the DB delete does NOT
		// touch the host's authorized_keys — that is a separate manual step).
		"RevokeCommand": channelRevokeCommand(),
		// Settings-hub chrome: re-chromed into the Paramètres hub. Sauvegarde is
		// Admin-only ⇒ IsAdmin is true here.
		"Active":         "sauvegarde",
		"IsAdmin":        middleware.GetSessionRole(r, h.SessionStore) == "Admin",
		"HeaderSubtitle": "Canal de sauvegarde et stockage cloud (off-site).",
	}
	if err := h.Templates.ExecuteTemplate(w, "onboarding-canal.html", data); err != nil {
		slog.Error("Template error (onboarding-canal.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// channelCard builds the view model from the live DB row (when present) or the env
// seed fallback. The secret is reduced to a SecretPresent flag; HasInAppKey
// distinguishes a real in-DB ed25519 key from an env-seeded host-only row (whose empty
// secret deliberately signals "use the key FILE").
func (h *Handler) channelCard() channelCardData {
	card := channelCardData{Status: "unknown", Source: "unconfigured", User: defaultChannelUser}

	conn, secret, err := h.Connections.GetGoabackupChannel()
	if conn != nil {
		pubkey, fingerprint, keytype := services.GoabackupChannelExtra(conn)
		_ = pubkey // the pubkey is served by the installer endpoint, not echoed on the card
		card.Source = "db"
		card.Status = conn.Status
		card.Host = conn.URL
		if conn.TokenID != "" {
			card.User = conn.TokenID
		}
		card.Fingerprint = fingerprint
		card.KeyType = keytype
		card.LastError = conn.LastError
		card.CanRollback = true
		// A usable in-app key means a decipherable, non-empty PEM secret. An env-seeded
		// row (import-env) carries an EMPTY secret on purpose (it falls back to the key
		// FILE), so it is "configured via env file", not an in-app key.
		card.SecretPresent = err == nil && secret != ""
		card.HasInAppKey = card.SecretPresent
		card.Configured = card.Host != "" && (card.HasInAppKey || h.Config.GoabackupSSHKeyFile != "")
		return card
	}

	// No DB row: fall back to the env (key FILE) config.
	if h.Config.GoabackupSSHHost != "" && h.Config.GoabackupSSHKeyFile != "" {
		card.Source = "env"
		card.Host = h.Config.GoabackupSSHHost
		if h.Config.GoabackupSSHUser != "" {
			card.User = h.Config.GoabackupSSHUser
		}
		card.Configured = true
		card.SecretPresent = true // the key FILE is the secret on the env path
		card.EnvImportable = true
		card.KeyType = "file"
	}
	return card
}

// HandleOnboardingChannelProvision is the POST that GENERATES a fresh ed25519 pair,
// persists the private PEM encrypted, hot-reloads the live channel so the next
// disk-free probe uses the new key, and returns the non-secret install material
// (command + helper sha256 + pubkey + fingerprint). The private key is NEVER returned,
// logged, or written to disk. CSRF-protected (POST) + Admin-only.
//
// Rotation semantics: a second provision OVERWRITES the single DB row (the store's
// upsert) and re-applies the channel live. The OLD host-side authorized_keys line stays
// active until the admin re-runs the install script (which overwrites it), so the live
// probe will read RED until the script is re-run — the UI must warn about this.
func (h *Handler) HandleOnboardingChannelProvision(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	// The channel host is fixed to the configured Proxmox host of THIS instance: the
	// helper runs on the same Proxmox that holds the vzdumps. We derive it from the live
	// Proxmox snapshot (host:port → host) so the admin does not re-type it, falling back
	// to any host already on the channel row / env. An unresolved host is a hard error
	// (we cannot build a usable channel without a target).
	host := h.resolveChannelHost()
	if host == "" {
		writeJSON(w, http.StatusOK, channelProvisionResponse{
			Error: "Hôte Proxmox introuvable : configurez d'abord la connexion Proxmox (l'agent de sauvegarde tourne sur ce même hôte).",
		})
		return
	}

	key, err := services.GenerateEd25519Key(channelKeyComment)
	if err != nil {
		slog.Error("channel provision: key generation failed", "error", err)
		writeJSON(w, http.StatusOK, channelProvisionResponse{Error: "Échec de la génération de la clé."})
		return
	}

	form := models.GoabackupChannelForm{
		Host:          host,
		User:          defaultChannelUser,
		PrivateKeyPEM: key.PrivateKey, // the SECRET — encrypted by SaveGoabackupChannel, never echoed
		PublicKey:     key.PublicKey,  // the authorized_keys line (public)
		Fingerprint:   key.Fingerprint,
		KeyType:       key.KeyType,
	}

	user := middleware.GetSessionUser(r, h.SessionStore)
	if err := h.Connections.SaveGoabackupChannel(form, user); err != nil {
		slog.Error("channel provision: persist failed", "error", err)
		writeJSON(w, http.StatusOK, channelProvisionResponse{Error: "Échec de l'enregistrement de la clé en base."})
		return
	}

	// Hot-reload the live channel with the freshly-generated key IN MEMORY so the next
	// "Vérifier l'installation" probe uses it without a restart. The private PEM is held
	// in memory only (never on disk) by the channel. The TOFU host-key store is wired in
	// explicitly here so the very first probe — the one that pins the Proxmox identity
	// the later restorability verdicts are read through — is already verified.
	h.ChannelRegistry.ApplyChannelClient(services.NewProxmoxChannelFromKey(
		host, defaultChannelUser, []byte(key.PrivateKey),
		services.WithChannelHostKeys(h.channelHostKeys())))

	go services.LogAudit(h.DB, 0, user, "Onboarding Canal",
		"Clé de canal ed25519 générée et enregistrée (fingerprint "+key.Fingerprint+", hôte "+host+")", middleware.RealIP(r))

	// A rotation obsoletes every command already displayed (the script now carries a
	// different pubkey, hence a different sha256): burn the outstanding tokens first so
	// a stale copy-paste fails on the token with a clear message.
	channelInstallerTokens.revokeAll()
	installerURL, installerSHA, command := h.channelInstallMaterialFor(r, key.PublicKey)
	writeJSON(w, http.StatusOK, channelProvisionResponse{
		OK:           true,
		Fingerprint:  key.Fingerprint,
		PublicKey:    key.PublicKey,
		HelperSHA:    helperSHA256(),
		InstallerSHA: installerSHA,
		InstallerURL: installerURL,
		Command:      command,
	})
}

// HandleOnboardingChannelInstaller serves the install SCRIPT to a logged-in admin
// (text/plain, Admin-only). It is the "Voir le script" preview inside the browser; the
// Proxmox root shell uses the public token route instead (see
// HandleOnboardingChannelInstallerToken), because it carries no session cookie.
func (h *Handler) HandleOnboardingChannelInstaller(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	h.serveInstallerScript(w, channelInstanceHost(r))
}

// HandleOnboardingChannelInstallerToken serves the install SCRIPT on a PUBLIC route
// authenticated by a single-use, short-lived token (?t=...). This is the route the
// copy-pasted root command hits.
//
// Why public: the admin runs the curl from a Proxmox root shell that has no GoaCore
// session. Behind the admin gate the request is answered with a 303 to /login, which
// curl -L follows to a 200 HTML page — so -f never trips, the login page lands in
// /tmp/goabackup-install.sh, and `sudo bash` runs HTML. Authentication therefore moves
// from the session cookie to a token GoaCore minted in-app, valid for minutes and
// burned on first use, and the served bytes are pinned to the host recorded in the
// grant so their sha256 matches the digest the UI displayed.
func (h *Handler) HandleOnboardingChannelInstallerToken(w http.ResponseWriter, r *http.Request) {
	grant, ok := channelInstallerTokens.consume(r.URL.Query().Get("t"))
	if !ok {
		// Deliberately non-committal (expired / already used / never issued are one
		// answer) and actionable: the admin just reloads the wizard for a fresh command.
		http.Error(w,
			"# Jeton d'installation invalide, deja utilise ou expire.\n"+
				"# Rouvrez l'ecran Canal dans GoaCore et recopiez la commande affichee.",
			http.StatusForbidden)
		return
	}

	// No session on this route: the trace is attributed to the installer itself, with
	// the source IP, so a download the admin did not trigger is still visible.
	go services.LogAudit(h.DB, 0, "installeur-canal", "Onboarding Canal",
		"Script d'installation du canal téléchargé (jeton à usage unique consommé)", middleware.RealIP(r))

	h.serveInstallerScript(w, grant.instanceHost)
}

// serveInstallerScript renders and writes the install script for instanceHost. It
// injects the CURRENT public key, embeds the helper INLINE as a heredoc and publishes
// the helper sha256 the script re-verifies before installing anything. It GENERATES
// NOTHING (it reads the already-provisioned pubkey); a 409 is returned when no key has
// been provisioned yet.
func (h *Handler) serveInstallerScript(w http.ResponseWriter, instanceHost string) {
	conn, _, err := h.Connections.GetGoabackupChannel()
	if err != nil {
		// An undecipherable secret still has a usable pubkey in extra_json — keep going.
		slog.Warn("channel installer: get row returned error (continuing with pubkey)", "error", err)
	}
	pubkey, _, _ := services.GoabackupChannelExtra(conn)
	pubkey = strings.TrimSpace(pubkey)
	if pubkey == "" {
		http.Error(w, "# Aucune cle de canal generee. Generez d'abord la cle (etape 1) puis rechargez le script.", http.StatusConflict)
		return
	}

	script := buildInstallerScript(pubkey, instanceHost)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// A sensible filename if the admin saves it (curl -o), without forcing a download.
	w.Header().Set("Content-Disposition", `inline; filename="goabackup-install.sh"`)
	_, _ = w.Write([]byte(script))
}

// HandleOnboardingChannelHelper serves the raw embedded helper (text/plain, Admin-only)
// so an admin can download + verify it separately against the published sha256 if they
// prefer not to trust the inline heredoc. It is the SAME bytes the installer inlines.
func (h *Handler) HandleOnboardingChannelHelper(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `inline; filename="goabackup-runner.sh"`)
	_, _ = w.Write([]byte(goabackup.Runner))
}

// HandleOnboardingChannelTest is the live "Vérifier l'installation" probe (POST,
// Admin-only). It runs disk-free over the LIVE channel (the freshly-provisioned key)
// — a real end-to-end proof that the admin's script worked: the host accepted the key,
// the forced-command ran, sudo + the helper replied. It exposes NOTHING secret.
func (h *Handler) HandleOnboardingChannelTest(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	channel := h.ChannelRegistry.Channel()
	if !channel.Configured() {
		writeJSON(w, http.StatusOK, channelTestResponse{
			Kind:  services.TestKindAPI,
			Error: "Canal non configuré : générez la clé puis exécutez le script d'installation sur le Proxmox.",
		})
		return
	}

	info, err := channel.DiskFree()
	if err != nil {
		// A failed probe after provisioning almost always means the script has not been
		// run yet (or the rotated key is not yet installed), or SSH 22 is blocked. We
		// classify it as network so the UI phrases it as "pas encore installé / réessayer".
		writeJSON(w, http.StatusOK, channelTestResponse{
			Kind:  services.TestKindNetwork,
			Error: "Échec de la vérification : la clé n'est probablement pas encore installée sur le Proxmox (relancez le script), ou le port SSH 22 est bloqué.",
		})
		return
	}

	detail := fmt.Sprintf("Backend %s, %.1f Go libres localement", safeBackend(info.Backend), float64(info.LocalAvailBytes)/(1<<30))
	writeJSON(w, http.StatusOK, channelTestResponse{OK: true, Detail: detail})
}

// HandleOnboardingChannelImportEnv seeds the DB row from the environment (host/user
// only — the env carries a key FILE PATH, not a PEM, so the secret stays empty and the
// channel keeps reading GOABACKUP_SSH_KEY_FILE). Admin-only. It does NOT generate a key.
func (h *Handler) HandleOnboardingChannelImportEnv(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if err := h.Connections.ImportFromEnvGoabackupChannel(h.Config); err != nil {
		h.renderChannel(w, r, "Import impossible : "+err.Error(), "")
		return
	}
	// The env path keeps using the key FILE: re-apply the env-derived (file-based)
	// channel live via the registry's frozen env fallback so the source is coherent.
	h.ChannelRegistry.RollbackToEnv()

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Canal",
		"Configuration env du canal importée en base (source=env, clé fichier)", middleware.RealIP(r))

	h.renderChannel(w, r, "", "Configuration env du canal importée — le canal utilise la clé fichier de l'environnement.")
}

// HandleOnboardingChannelDelete removes the in-app 'goabackup-channel' row and rolls the
// live channel back to the env (key FILE) fallback, or to unconfigured when env carried
// none. It re-renders with the host-side revocation command, because deleting the DB row
// does NOT remove the authorized_keys line on the Proxmox host. Admin-only.
func (h *Handler) HandleOnboardingChannelDelete(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	if _, err := h.Connections.DeleteGoabackupChannel(); err != nil {
		slog.Error("channel onboarding: delete failed", "error", err)
		h.renderChannel(w, r, "Échec de la suppression en base.", "")
		return
	}
	// Revert live to the env (key FILE) channel frozen at boot — or unconfigured.
	h.ChannelRegistry.RollbackToEnv()

	user := middleware.GetSessionUser(r, h.SessionStore)
	go services.LogAudit(h.DB, 0, user, "Onboarding Canal",
		"Clé de canal en base supprimée (retour au fallback env / non configuré)", middleware.RealIP(r))

	h.renderChannel(w, r, "",
		"Clé supprimée en base. IMPORTANT : la ligne authorized_keys reste sur le Proxmox — révoquez-la côté hôte avec la commande affichée ci-dessous.")
}

// --- helpers ---

// resolveChannelHost returns the host (ip:port or ip) the channel should target. The
// helper runs on the SAME Proxmox that holds the vzdumps, so we derive the host from the
// live Proxmox connection, then fall back to an existing channel row, then the env. The
// SSH port is NOT inferred here — normalizeChannelHost (in the channel) appends :22.
func (h *Handler) resolveChannelHost() string {
	if snap := h.ConfigStore.ProxmoxSnapshot(); snap.URL != "" {
		if host := hostFromURL(snap.URL); host != "" {
			return host
		}
	}
	if conn, _, _ := h.Connections.GetGoabackupChannel(); conn != nil && conn.URL != "" {
		return conn.URL
	}
	return h.Config.GoabackupSSHHost
}

// hostFromURL extracts the bare host from a Proxmox API URL ("https://192.0.2.10:8006"
// → "192.0.2.10"). The API port (8006) is NOT the SSH port, so we drop it; the channel
// appends the SSH default :22. Returns "" when the URL has no host.
func hostFromURL(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip any path/query.
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	// Strip the API port (we want the bare host; the channel adds :22).
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// helperSHA256 is the hex SHA256 of the embedded helper — the integrity hash published
// in the install script and the UI so the admin can verify the inlined heredoc.
func helperSHA256() string {
	return sha256Hex(goabackup.Runner)
}

// sha256Hex is the hex SHA256 of a rendered artefact.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// channelHostKeys exposes the shared SSH TOFU store to the channel, or nil when the
// handler was built without one (tests) so the channel falls back to the package
// default rather than dereferencing a nil service.
func (h *Handler) channelHostKeys() services.ChannelHostKeys {
	if h.SSHService == nil {
		return nil
	}
	return h.SSHService
}

// channelInstallMaterial mints the install material for the CURRENT provisioned key:
// the single-use installer URL, the sha256 of the exact script it will serve, and the
// root command that ties the two together. All three are empty when no key has been
// provisioned yet — there is nothing to install, and no honest digest to publish.
func (h *Handler) channelInstallMaterial(r *http.Request) (installerURL, installerSHA, command string) {
	conn, _, err := h.Connections.GetGoabackupChannel()
	if err != nil {
		// An undecipherable secret still has a usable pubkey in extra_json — keep going.
		slog.Warn("channel install material: get row returned error (continuing with pubkey)", "error", err)
	}
	pubkey, _, _ := services.GoabackupChannelExtra(conn)
	pubkey = strings.TrimSpace(pubkey)
	if pubkey == "" {
		return "", "", ""
	}
	return h.channelInstallMaterialFor(r, pubkey)
}

// channelInstallMaterialFor is channelInstallMaterial for an explicitly supplied
// pubkey — the provision path, which has the freshly generated key in hand and must not
// race the DB read. The token is bound to the instance host so the script we later
// serve is byte-identical to the one hashed here, whatever Host the curl presents.
func (h *Handler) channelInstallMaterialFor(r *http.Request, pubkey string) (installerURL, installerSHA, command string) {
	host := channelInstanceHost(r)
	token, err := channelInstallerTokens.issue(host)
	if err != nil {
		// Without a token the command cannot be authenticated; publishing a token-less
		// URL would just fail with a 403 later. Surface nothing rather than something
		// broken — the admin can reload the page to retry.
		slog.Error("channel: installer token generation failed", "error", err)
		return "", "", ""
	}
	installerURL = channelInstallerURL(host, token)
	installerSHA = sha256Hex(buildInstallerScript(pubkey, host))
	return installerURL, installerSHA, channelRootCommand(installerURL, installerSHA)
}

// channelInstanceHost returns the instance host (host:port) the admin's browser used,
// derived from r.Host — never a hard-coded domain (sovereignty). It is sanitised to
// host/port characters because it ends up both in the installer URL of a command pasted
// into a root shell and in a comment line of the script itself.
func channelInstanceHost(r *http.Request) string {
	if host := sanitizeForEcho(r.Host); host != "" {
		return host
	}
	return "localhost:8443"
}

// channelInstallerURL builds the absolute, token-bearing installer URL on THIS instance.
// HTTPS is assumed (GoaCore serves TLS on 8443); the self-signed cert is handled by the
// admin's curl -k, and integrity comes from the sha256 the command carries — not from
// the transport.
func channelInstallerURL(instanceHost, token string) string {
	return "https://" + instanceHost + channelInstallerPath + "?t=" + url.QueryEscape(token)
}

// channelRootCommand is the recommended AUDITABLE root command (download → VERIFY →
// inspect → run), NOT a blind curl|sudo bash.
//
// installerSHA is the load-bearing part. It is computed server-side, displayed in the
// browser over the admin's TLS-verified page, and baked into the command as a literal,
// so the check compares the download against a digest that took a DIFFERENT path from
// the script. Re-downloading the digest over the same `curl -k` would prove nothing: an
// interceptor able to rewrite the script rewrites the digest to match.
func channelRootCommand(installerURL, installerSHA string) string {
	return "curl -k -fsSL '" + installerURL + "' -o /tmp/goabackup-install.sh" +
		" && echo '" + installerSHA + "  /tmp/goabackup-install.sh' | sha256sum -c -" +
		" && less /tmp/goabackup-install.sh" +
		" && sudo bash /tmp/goabackup-install.sh"
}

// channelRevokeCommand is the host-side revocation shown at delete time: it removes the
// goabackup authorized_keys line (and optionally the user) on the Proxmox. Deleting the
// DB row does NOT do this — it must be run by the admin on the host.
func channelRevokeCommand() string {
	return "rm -f ~goabackup/.ssh/authorized_keys   # ou: userdel -r goabackup ; rm -f /etc/sudoers.d/goabackup /usr/local/bin/goabackup-runner.sh"
}

// safeBackend renders an empty backend (an old helper) as "inconnu" so the proof line
// stays readable.
func safeBackend(b string) string {
	if b == "" {
		return "inconnu"
	}
	return b
}
