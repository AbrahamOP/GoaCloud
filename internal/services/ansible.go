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

// ErrNoHostKeyStore signale une erreur de câblage : aucun magasin de clés hôtes
// n'a été fourni ni enregistré. On refuse d'exécuter plutôt que de se rabattre sur
// une connexion non vérifiée.
var ErrNoHostKeyStore = errors.New("magasin de clés hôtes non configuré : impossible de vérifier l'identité de l'hôte cible")

func hostNotPinnedError(ip string) error {
	return fmt.Errorf("%w pour %s : GoaCore n'a jamais vérifié l'identité de cet hôte. "+
		"Ouvrez une console SSH vers %s (ou déployez-y une clé) depuis l'écran Clés SSH "+
		"pour épingler son empreinte, puis relancez le playbook", ErrHostNotPinned, ip, ip)
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
func SetDefaultHostKeyStore(store HostKeyStore) {
	defaultHostKeysMu.Lock()
	defer defaultHostKeysMu.Unlock()
	defaultHostKeys = store
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
