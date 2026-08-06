package services

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// remoteUserPattern restricts the SSH user to safe characters to prevent
// command/argument injection via the --user flag.
var remoteUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidRemoteUser reports whether user is a safe, non-empty SSH login name. It is
// the single source of truth reused by the handlers (reject at the HTTP boundary
// with a 400) and by RunPlaybook (reject before shelling out to ansible-playbook).
func ValidRemoteUser(user string) bool {
	return remoteUserPattern.MatchString(user)
}

// ListPlaybooks scans the given directory and returns a map of categories to playbook files.
func ListPlaybooks(dir string) (map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}

	playbooks := make(map[string][]string)
	playbooks["Général"] = []string{}

	for _, e := range entries {
		if e.IsDir() {
			subEntries, err := os.ReadDir(dir + "/" + e.Name())
			if err == nil {
				var subList []string
				for _, sub := range subEntries {
					if !sub.IsDir() && (strings.HasSuffix(sub.Name(), ".yml") || strings.HasSuffix(sub.Name(), ".yaml")) {
						subList = append(subList, e.Name()+"/"+sub.Name())
					}
				}
				if len(subList) > 0 {
					playbooks[e.Name()] = subList
				}
			}
		} else if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
			playbooks["Général"] = append(playbooks["Général"], e.Name())
		}
	}

	if len(playbooks["Général"]) == 0 {
		delete(playbooks, "Général")
	}

	return playbooks, nil
}

// HostKeyStore expose les clés d'hôte SSH déjà épinglées (TOFU) pour une IP.
//
// L'unique implémentation est *SSHService (voir PinnedHostKeys plus bas) : le
// magasin est la table ssh_host_keys, celle qu'alimente et vérifie déjà
// SSHHostKeyCallback (ssh.go) pour la console et le déploiement de clés. Ansible
// s'y raccorde au lieu d'avoir sa propre politique de confiance, pour qu'il n'y ait
// qu'une seule source de vérité sur l'identité des hôtes de la flotte.
type HostKeyStore interface {
	// PinnedHostKeys renvoie les clés hôtes épinglées pour ip, encodées en base64
	// du format filaire SSH (celui stocké par SSHHostKeyCallback). Slice vide =
	// hôte jamais épinglé.
	PinnedHostKeys(ip string) ([]string, error)
}

// PinnedHostKeys implémente HostKeyStore sur le magasin partagé ssh_host_keys.
// Elle vit ici plutôt que dans ssh.go parce qu'elle n'existe que pour le chemin
// Ansible : la console, elle, vérifie les clés en direct via SSHHostKeyCallback.
func (s *SSHService) PinnedHostKeys(ip string) ([]string, error) {
	var stored string
	err := s.db.QueryRow("SELECT host_key FROM ssh_host_keys WHERE ip = ?", ip).Scan(&stored)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lecture des clés hôtes épinglées pour %s: %w", ip, err)
	}
	if strings.TrimSpace(stored) == "" {
		return nil, nil
	}
	return []string{stored}, nil
}

// ErrHostNotPinned marque le refus d'exécuter un playbook vers un hôte dont
// l'identité n'a jamais été épinglée. Les appelants peuvent le tester avec
// errors.Is pour distinguer ce cas d'une vraie erreur d'exécution.
var ErrHostNotPinned = errors.New("clé hôte SSH non épinglée")

// ErrHostKeyMismatch signale que l'hôte présente une clé différente de celle déjà
// épinglée : soit la machine a été réinstallée, soit quelqu'un s'interpose. GoaCore
// ne remplace JAMAIS une clé épinglée tout seul.
var ErrHostKeyMismatch = errors.New("la clé hôte SSH présentée diffère de la clé épinglée")

// ErrHostKeyFingerprintMismatch signale que la clé présentée par l'hôte ne
// correspond pas à l'empreinte que l'exploitant attendait : l'épinglage est refusé.
var ErrHostKeyFingerprintMismatch = errors.New("l'empreinte présentée ne correspond pas à l'empreinte attendue")

// hostKeyScanTimeout borne la poignée de main SSH d'un scan d'empreinte.
const hostKeyScanTimeout = 10 * time.Second

// ansibleSSHPort est le port sur lequel Ansible se connecte (et donc celui dont on
// épingle la clé : le known_hosts généré par RunPlaybook utilise l'hôte nu, forme
// réservée au port 22).
const ansibleSSHPort = 22

// HostKeyPinner est le chemin d'AMORÇAGE du TOFU : il permet d'épingler
// délibérément l'identité d'un hôte, sans passer par une console SSH ni par un
// déploiement de clé. Sans lui, le durcissement de RunPlaybook (refus de tout hôte
// non épinglé) n'aurait aucune sortie : les planifications existantes resteraient
// bloquées à jamais.
//
// L'unique implémentation est *SSHService.
type HostKeyPinner interface {
	// ScanHostKey ouvre une connexion vers ip:22, récupère la clé hôte présentée et
	// renvoie son empreinte SHA256 SANS rien enregistrer.
	ScanHostKey(ip string) (fingerprint string, err error)
	// PinHostKey récupère la clé hôte de ip:22 et l'enregistre dans ssh_host_keys.
	// expectedFingerprint, s'il est non vide, doit correspondre à l'empreinte
	// présentée, sinon rien n'est enregistré (validation hors bande par
	// l'exploitant). L'empreinte réellement épinglée est renvoyée pour affichage.
	PinHostKey(ip, expectedFingerprint string) (fingerprint string, err error)
}

// scanHostKey ouvre une poignée de main SSH vers ip:port et renvoie la clé hôte
// présentée. L'authentification n'est jamais tentée : la clé d'hôte est échangée
// AVANT l'authentification, donc un « unable to authenticate » est un succès pour
// nous tant qu'une clé a été capturée.
func scanHostKey(ip string, port int) (gossh.PublicKey, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("adresse IP invalide : %s", ip)
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, hostKeyScanTimeout)
	if err != nil {
		return nil, fmt.Errorf("connexion à %s impossible : %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(hostKeyScanTimeout)); err != nil {
		return nil, fmt.Errorf("échéance de connexion : %w", err)
	}

	var captured gossh.PublicKey
	cfg := &gossh.ClientConfig{
		User: "goacore-hostkey-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			captured = key
			return nil
		},
		Timeout: hostKeyScanTimeout,
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, cfg)
	if err == nil {
		go gossh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(gossh.Prohibited, "scan")
			}
		}()
		sshConn.Close()
	}
	if captured == nil {
		return nil, fmt.Errorf("clé hôte de %s non récupérée : %w", addr, err)
	}
	return captured, nil
}

// ScanHostKey implémente HostKeyPinner : lecture seule, aucune écriture en base.
// C'est ce que l'UI affiche à l'exploitant pour qu'il compare l'empreinte avec
// celle relevée sur la machine (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`)
// AVANT de confirmer l'épinglage.
func (s *SSHService) ScanHostKey(ip string) (string, error) {
	key, err := scanHostKey(ip, ansibleSSHPort)
	if err != nil {
		return "", err
	}
	return gossh.FingerprintSHA256(key), nil
}

// PinHostKey implémente HostKeyPinner : c'est LE geste d'amorçage explicite.
//
// Il récupère la clé hôte présentée par ip:22 et l'enregistre dans ssh_host_keys —
// le magasin partagé avec la console et le déploiement de clés — puis renvoie son
// empreinte SHA256 pour que l'appelant la restitue à l'exploitant.
//
//   - expectedFingerprint non vide : la clé présentée doit correspondre, sinon rien
//     n'est écrit (ErrHostKeyFingerprintMismatch). C'est la voie recommandée :
//     l'exploitant valide l'empreinte hors bande.
//   - hôte déjà épinglé avec la MÊME clé : succès idempotent.
//   - hôte déjà épinglé avec une clé DIFFÉRENTE : refus (ErrHostKeyMismatch). Une
//     rotation légitime se règle en supprimant explicitement la ligne épinglée.
func (s *SSHService) PinHostKey(ip, expectedFingerprint string) (string, error) {
	return s.pinHostKeyOnPort(ip, ansibleSSHPort, expectedFingerprint)
}

// pinHostKeyOnPort porte la logique de PinHostKey avec un port explicite (les tests
// montent un serveur SSH local sur un port éphémère).
func (s *SSHService) pinHostKeyOnPort(ip string, port int, expectedFingerprint string) (string, error) {
	key, err := scanHostKey(ip, port)
	if err != nil {
		return "", err
	}
	fingerprint := gossh.FingerprintSHA256(key)
	if want := strings.TrimSpace(expectedFingerprint); want != "" && want != fingerprint {
		return fingerprint, fmt.Errorf("%w pour %s : présentée %s, attendue %s",
			ErrHostKeyFingerprintMismatch, ip, fingerprint, want)
	}

	keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())
	var stored string
	err = s.db.QueryRow("SELECT host_key FROM ssh_host_keys WHERE ip = ?", ip).Scan(&stored)
	switch {
	case err == sql.ErrNoRows:
		if _, ierr := s.db.Exec("INSERT INTO ssh_host_keys (ip, host_key) VALUES (?, ?)", ip, keyB64); ierr != nil {
			return fingerprint, fmt.Errorf("enregistrement de la clé hôte de %s : %w", ip, ierr)
		}
		slog.Warn("ansible: clé hôte épinglée", "ip", ip, "fingerprint", fingerprint)
		return fingerprint, nil
	case err != nil:
		return fingerprint, fmt.Errorf("lecture de la clé hôte épinglée pour %s : %w", ip, err)
	case strings.TrimSpace(stored) == keyB64:
		// Déjà épinglé à l'identique : rien à faire.
		return fingerprint, nil
	default:
		return fingerprint, fmt.Errorf("%w pour %s (empreinte présentée : %s)", ErrHostKeyMismatch, ip, fingerprint)
	}
}

// ErrNoHostKeyStore signale une erreur de câblage : aucun magasin de clés hôtes
// n'a été fourni ni enregistré. On refuse d'exécuter plutôt que de se rabattre sur
// une connexion non vérifiée.
var ErrNoHostKeyStore = errors.New("magasin de clés hôtes non configuré : impossible de vérifier l'identité de l'hôte cible")

func hostNotPinnedError(ip string) error {
	return fmt.Errorf("%w pour %s : GoaCore n'a jamais vérifié l'identité de cet hôte. "+
		"Épinglez-la (action « Épingler la clé hôte » de l'écran Clés SSH, ou "+
		"SSHService.PinHostKey) : GoaCore affichera l'empreinte SHA256 présentée par %s, "+
		"que vous comparerez à celle relevée sur la machine avec "+
		"`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` avant de confirmer. "+
		"Ouvrir une console SSH vers cet hôte (ou y déployer une clé) l'épingle aussi. "+
		"Relancez ensuite le playbook", ErrHostNotPinned, ip, ip)
}

// UnpinnedScheduleHost décrit une planification Ansible dont l'hôte cible n'est pas
// (encore) épinglé : elle échouera à sa prochaine exécution.
type UnpinnedScheduleHost struct {
	ScheduleID int
	Playbook   string
	VMID       int
	IP         string
}

// unpinnedScheduleLister est le contrat interne permettant d'inventorier, au
// démarrage, les planifications dont l'hôte n'est pas épinglé. Implémenté par
// *SSHService (qui porte à la fois la base et le magasin de clés).
type unpinnedScheduleLister interface {
	UnpinnedScheduleHosts() ([]UnpinnedScheduleHost, error)
}

// UnpinnedScheduleHosts liste les planifications ACTIVÉES dont l'hôte cible n'a
// aucune clé épinglée. Elles seront refusées par RunPlaybook tant que l'exploitant
// n'aura pas épinglé l'hôte : mieux vaut le lui dire au démarrage que de le laisser
// découvrir la panne au premier échec silencieux.
func (s *SSHService) UnpinnedScheduleHosts() ([]UnpinnedScheduleHost, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(`
		SELECT a.id, a.playbook, a.vmid, COALESCE(v.ip_address, '')
		FROM ansible_schedules a
		LEFT JOIN vm_cache v ON v.vmid = a.vmid
		WHERE a.enabled = TRUE
		  AND (v.ip_address IS NULL OR v.ip_address NOT IN (SELECT ip FROM ssh_host_keys))
		ORDER BY a.id`)
	if err != nil {
		return nil, fmt.Errorf("inventaire des planifications non épinglées : %w", err)
	}
	defer rows.Close()

	var out []UnpinnedScheduleHost
	for rows.Next() {
		var u UnpinnedScheduleHost
		if err := rows.Scan(&u.ScheduleID, &u.Playbook, &u.VMID, &u.IP); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// warnUnpinnedSchedules journalise l'inventaire ci-dessus. Best-effort : une erreur
// de lecture ne doit jamais empêcher le démarrage.
func warnUnpinnedSchedules(store HostKeyStore) {
	lister, ok := store.(unpinnedScheduleLister)
	if !ok {
		return
	}
	pending, err := lister.UnpinnedScheduleHosts()
	if err != nil {
		slog.Warn("ansible: inventaire des planifications non épinglées impossible", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}
	slog.Warn("ansible: des planifications ciblent des hôtes NON épinglés — elles seront refusées tant que l'identité de l'hôte n'aura pas été épinglée (écran Clés SSH)",
		"count", len(pending))
	for _, p := range pending {
		ip := p.IP
		if ip == "" {
			ip = "(IP inconnue du cache)"
		}
		slog.Warn("ansible: planification bloquée par le TOFU",
			"schedule_id", p.ScheduleID, "playbook", p.Playbook, "vmid", p.VMID, "ip", ip)
	}
}

// defaultPlaybookTimeout borne la durée d'un playbook quand GOACORE_ANSIBLE_TIMEOUT
// n'est pas défini.
const defaultPlaybookTimeout = 30 * time.Minute

// PlaybookTimeout renvoie la durée maximale d'une exécution de playbook. Elle est
// configurable via GOACORE_ANSIBLE_TIMEOUT au format Go ("45m", "2h") ; une valeur
// absente ou invalide retombe sur 30 minutes. L'ordonnanceur s'en sert aussi pour
// dimensionner le bail d'une tâche réclamée.
func PlaybookTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("GOACORE_ANSIBLE_TIMEOUT"))
	if raw == "" {
		return defaultPlaybookTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		slog.Warn("GOACORE_ANSIBLE_TIMEOUT invalide, valeur par défaut appliquée",
			"value", raw, "default", defaultPlaybookTimeout)
		return defaultPlaybookTimeout
	}
	return d
}

// ansibleBin est le binaire lancé par RunPlaybook. Variable (et non constante) pour
// que les tests puissent lui substituer un faux binaire.
var ansibleBin = "ansible-playbook"

var (
	defaultHostKeysMu sync.RWMutex
	defaultHostKeys   HostKeyStore
)

// SetDefaultHostKeyStore enregistre le magasin utilisé par RunPlaybook quand
// l'appelant ne lui en passe pas explicitement un (WithHostKeyStore). À appeler une
// fois au démarrage avec le *SSHService.
//
// C'est aussi le point d'accroche de l'AVERTISSEMENT DE DÉMARRAGE : puisque le
// magasin arrive ici une fois, au boot, on en profite pour inventorier les
// planifications dont l'hôte n'est pas épinglé (donc qui échoueront) et les
// journaliser. Best-effort, jamais bloquant.
func SetDefaultHostKeyStore(store HostKeyStore) {
	defaultHostKeysMu.Lock()
	defaultHostKeys = store
	defaultHostKeysMu.Unlock()

	if store != nil {
		warnUnpinnedSchedules(store)
	}
}

func defaultHostKeyStore() HostKeyStore {
	defaultHostKeysMu.RLock()
	defer defaultHostKeysMu.RUnlock()
	return defaultHostKeys
}

// runPlaybookConfig porte les réglages optionnels d'une exécution.
type runPlaybookConfig struct {
	hostKeys HostKeyStore
	timeout  time.Duration
}

// RunPlaybookOption configure une exécution de playbook.
type RunPlaybookOption func(*runPlaybookConfig)

// WithHostKeyStore impose le magasin de clés hôtes à utiliser pour cette exécution.
func WithHostKeyStore(store HostKeyStore) RunPlaybookOption {
	return func(c *runPlaybookConfig) { c.hostKeys = store }
}

// WithTimeout impose la durée maximale de cette exécution (défaut : PlaybookTimeout).
func WithTimeout(d time.Duration) RunPlaybookOption {
	return func(c *runPlaybookConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// playbookWorkspace est le répertoire privé (0700) qui porte les secrets d'une
// exécution : la clé privée (0600) et le known_hosts dérivé des clés épinglées.
type playbookWorkspace struct {
	dir            string
	keyPath        string
	knownHostsPath string
}

// newPlaybookWorkspace crée le répertoire temporaire dédié et y écrit la clé privée
// puis le known_hosts. En cas d'erreur, rien ne subsiste sur le disque.
func newPlaybookWorkspace(privateKey, targetIP string, pinnedKeys []string) (*playbookWorkspace, error) {
	// Le known_hosts est calculé AVANT toute écriture : un hôte non épinglé ne doit
	// jamais provoquer le dépôt de la clé privée sur le disque.
	knownHosts, err := knownHostsContent(targetIP, pinnedKeys)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "goacore-ansible-")
	if err != nil {
		return nil, fmt.Errorf("création du répertoire temporaire : %w", err)
	}
	ws := &playbookWorkspace{
		dir:            dir,
		keyPath:        filepath.Join(dir, "id_key"),
		knownHostsPath: filepath.Join(dir, "known_hosts"),
	}
	// Le chemin part dans --ssh-common-args, qu'ansible redécoupe à la shlex : un
	// espace ou un guillemet donnerait un UserKnownHostsFile tronqué, donc un échec
	// incompréhensible. Mieux vaut le dire tout de suite.
	if strings.ContainsAny(dir, " \t\"'") {
		ws.remove()
		return nil, fmt.Errorf("répertoire temporaire %q inutilisable : le chemin ne doit contenir ni espace ni guillemet (voir TMPDIR)", dir)
	}
	// MkdirTemp crée déjà en 0700 ; on le réaffirme pour ne rien devoir à l'umask.
	if err := os.Chmod(dir, 0o700); err != nil {
		ws.remove()
		return nil, fmt.Errorf("durcissement du répertoire temporaire : %w", err)
	}
	if err := os.WriteFile(ws.keyPath, []byte(privateKey), 0o600); err != nil {
		ws.remove()
		return nil, fmt.Errorf("écriture de la clé privée temporaire : %w", err)
	}
	if err := os.WriteFile(ws.knownHostsPath, []byte(knownHosts), 0o600); err != nil {
		ws.remove()
		return nil, fmt.Errorf("écriture du known_hosts temporaire : %w", err)
	}
	return ws, nil
}

// remove efface le répertoire et tout ce qu'il contient. Idempotent.
func (w *playbookWorkspace) remove() {
	if w == nil || w.dir == "" {
		return
	}
	if err := os.RemoveAll(w.dir); err != nil {
		slog.Error("ansible: suppression du répertoire temporaire impossible", "dir", w.dir, "error", err)
	}
}

// knownHostsContent rend le contenu d'un fichier known_hosts pour targetIP à partir
// des clés épinglées (base64 du format filaire, tel que stocké en base).
func knownHostsContent(targetIP string, pinnedKeys []string) (string, error) {
	var b strings.Builder
	for _, raw := range pinnedKeys {
		blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return "", fmt.Errorf("clé hôte épinglée illisible pour %s : %w", targetIP, err)
		}
		pub, err := gossh.ParsePublicKey(blob)
		if err != nil {
			return "", fmt.Errorf("clé hôte épinglée invalide pour %s : %w", targetIP, err)
		}
		// Format known_hosts : "<hôte> <type> <base64>". Ansible se connecte sur le
		// port 22, pour lequel OpenSSH cherche l'hôte nu (la forme [hôte]:port n'est
		// utilisée que hors port par défaut).
		b.WriteString(targetIP + " " + strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub))) + "\n")
	}
	if b.Len() == 0 {
		return "", hostNotPinnedError(targetIP)
	}
	return b.String(), nil
}

// RunPlaybook executes an ansible-playbook command and returns a streaming reader.
// The caller MUST call the returned cleanup function after consuming all output.
// cleanup waits for the process to exit, removes the temp workspace, and RETURNS the
// playbook's exit error (nil on success, *exec.ExitError on a non-zero exit) — so the
// caller can base success/failure on the real exit code rather than on fragile
// string-matching of the output. cleanup is idempotent (safe to call more than once).
//
// remoteUser is REQUIRED (no 'root' fallback): root SSH is disabled fleet-wide
// (PermitRootLogin=no), so a run must always target an explicit, non-root user.
// When become is true, --become is appended so privileged tasks escalate via sudo
// instead of needing a root login.
//
// Vérification d'identité de l'hôte : l'exécution n'a lieu que si la clé hôte de
// targetIP est déjà épinglée dans ssh_host_keys (le TOFU partagé avec la console).
// Les clés épinglées sont écrites dans un known_hosts temporaire présenté à ssh avec
// StrictHostKeyChecking=yes ; sinon on refuse avec ErrHostNotPinned. Sans cela, la
// clé privée et l'escalade sudo seraient offertes à n'importe quel hôte se faisant
// passer pour la cible.
//
// L'exécution est bornée par PlaybookTimeout (ou WithTimeout) : au-delà, tout le
// groupe de processus (ansible-playbook et ses ssh/python enfants) est tué, ce qui
// ferme le pipe et libère le lecteur.
func RunPlaybook(playbookPath string, targetIP string, privateKey string, remoteUser string, become bool, opts ...RunPlaybookOption) (io.ReadCloser, func() error, error) {
	cfg := runPlaybookConfig{hostKeys: defaultHostKeyStore(), timeout: PlaybookTimeout()}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Validate IP to prevent command injection via inventory parameter
	if ip := net.ParseIP(targetIP); ip == nil {
		return nil, nil, fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	// remote_user is mandatory and validated to prevent injection. No silent 'root'
	// fallback: an empty user is a caller bug (handlers/worker enforce it earlier).
	if remoteUser == "" {
		return nil, nil, fmt.Errorf("remote user is required")
	}
	if !ValidRemoteUser(remoteUser) {
		return nil, nil, fmt.Errorf("invalid remote user: %s", remoteUser)
	}

	if cfg.hostKeys == nil {
		return nil, nil, ErrNoHostKeyStore
	}
	pinned, err := cfg.hostKeys.PinnedHostKeys(targetIP)
	if err != nil {
		return nil, nil, err
	}
	if len(pinned) == 0 {
		return nil, nil, hostNotPinnedError(targetIP)
	}

	ws, err := newPlaybookWorkspace(privateKey, targetIP, pinned)
	if err != nil {
		return nil, nil, err
	}
	// Filet de sécurité : tant que le process n'est pas lancé (erreur ou panique),
	// le répertoire — donc la clé privée — disparaît.
	started := false
	defer func() {
		if !started {
			ws.remove()
		}
	}()

	args := []string{
		"-i", fmt.Sprintf("%s,", targetIP),
		playbookPath,
		"--private-key", ws.keyPath,
		"--user", remoteUser,
		"--ssh-common-args", fmt.Sprintf(
			"-o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes",
			ws.knownHostsPath),
	}
	if become {
		// Privilege escalation via sudo for privileged tasks run by a non-root user.
		args = append(args, "--become")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	cmd := exec.CommandContext(ctx, ansibleBin, args...)
	// ansible-playbook essaime des ssh/python enfants qui héritent du pipe : tuer le
	// seul père laisserait des orphelins écrire dedans (le lecteur n'aurait jamais
	// d'EOF). On l'isole donc dans son propre groupe et on tue le groupe entier.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		cancel()
		return nil, nil, err
	}
	started = true

	// La goroutine attend la fin du process, mémorise son code de sortie puis ferme le
	// pipe (EOF côté lecteur). `done` est fermé une fois waitErr écrit, ce qui rend
	// cleanup() sûr en appels multiples (lecture répétée d'un channel fermé).
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		if ctx.Err() == context.DeadlineExceeded {
			// Sinon l'appelant ne verrait qu'un « signal: killed » sans cause.
			waitErr = fmt.Errorf("playbook interrompu : délai maximal de %s dépassé", cfg.timeout)
		}
		// La clé privée disparaît dès la fin du process, sans dépendre de la
		// discipline de l'appelant (cleanup reste là pour l'ordre de lecture).
		ws.remove()
		pw.Close()
		cancel()
		close(done)
	}()

	// cleanup attend la fin du process, supprime le répertoire temporaire (clé privée
	// + known_hosts) et renvoie l'erreur de sortie réelle (nil si le playbook a
	// réussi). Idempotent.
	cleanup := func() error {
		<-done
		ws.remove()
		return waitErr
	}

	return pr, cleanup, nil
}
