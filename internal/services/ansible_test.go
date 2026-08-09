package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tests de non-régression du chemin Ansible : vérification d'identité de l'hôte
// (known_hosts issu des clés épinglées), hygiène des secrets sur le disque et
// bornage de l'exécution. Le binaire ansible-playbook est remplacé par un script
// shell (ansibleBin) : ces tests n'exigent donc ni Ansible ni réseau.
// ─────────────────────────────────────────────────────────────────────────────

// ansibleFakeStore est un HostKeyStore de test.
type ansibleFakeStore struct {
	keys map[string][]string
	err  error
}

func (f ansibleFakeStore) PinnedHostKeys(ip string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.keys[ip], nil
}

// newPinnedHostKey génère une clé hôte ed25519 et renvoie sa forme stockée en base
// (base64 du format filaire, comme SSHHostKeyCallback) et sa ligne authorized_keys.
func newPinnedHostKey(t *testing.T) (stored string, authorized string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("génération clé hôte : %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap clé hôte : %v", err)
	}
	return base64.StdEncoding.EncodeToString(sshPub.Marshal()),
		strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))
}

// fakeAnsibleBin installe un faux ansible-playbook (script shell) pour la durée du
// test et renvoie son chemin.
func fakeAnsibleBin(t *testing.T, script string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-ansible-playbook")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("écriture du faux binaire : %v", err)
	}
	previous := ansibleBin
	ansibleBin = path
	t.Cleanup(func() { ansibleBin = previous })
}

// isolatedTmp redirige os.MkdirTemp vers un répertoire propre au test et renvoie une
// fonction qui compte ce qui y traîne encore.
func isolatedTmp(t *testing.T) func() []string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return func() []string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("lecture du TMPDIR de test : %v", err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}
}

func TestKnownHostsContent(t *testing.T) {
	stored, authorized := newPinnedHostKey(t)

	got, err := knownHostsContent("172.16.0.11", []string{stored})
	if err != nil {
		t.Fatalf("knownHostsContent: %v", err)
	}
	want := "172.16.0.11 " + authorized + "\n"
	if got != want {
		t.Fatalf("known_hosts inattendu :\n got %q\nwant %q", got, want)
	}
}

func TestKnownHostsContentRejectsUnusableKeys(t *testing.T) {
	cases := map[string][]string{
		"aucune clé épinglée": nil,
		"base64 invalide":     {"pas-du-base64!!"},
		"blob non SSH":        {base64.StdEncoding.EncodeToString([]byte("bonjour"))},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := knownHostsContent("10.0.0.1", keys); err == nil {
				t.Fatal("une clé inutilisable doit être refusée, pas ignorée")
			}
		})
	}
}

// Un hôte jamais épinglé doit bloquer l'exécution AVANT que la clé privée ne touche
// le disque : c'est le cœur du correctif (plus de StrictHostKeyChecking=accept-new).
func TestRunPlaybookRefusesUnpinnedHost(t *testing.T) {
	leftovers := isolatedTmp(t)
	fakeAnsibleBin(t, "#!/bin/sh\necho 'ne devrait jamais tourner'\n")

	_, _, err := RunPlaybook("playbooks/test.yml", "172.16.0.11", "PRIVATE", "claude", true,
		WithHostKeyStore(ansibleFakeStore{}))
	if !errors.Is(err, ErrHostNotPinned) {
		t.Fatalf("erreur attendue ErrHostNotPinned, obtenu : %v", err)
	}
	if !strings.Contains(err.Error(), "Clés SSH") {
		t.Errorf("le message doit renvoyer vers l'écran d'épinglage, obtenu : %v", err)
	}
	if names := leftovers(); len(names) != 0 {
		t.Fatalf("aucun fichier temporaire ne doit subsister, trouvé : %v", names)
	}
}

// Absence de magasin = erreur de câblage : on refuse au lieu de se rabattre sur une
// connexion non vérifiée.
func TestRunPlaybookRefusesWithoutHostKeyStore(t *testing.T) {
	SetDefaultHostKeyStore(nil)
	_, _, err := RunPlaybook("playbooks/test.yml", "172.16.0.11", "PRIVATE", "claude", false)
	if !errors.Is(err, ErrNoHostKeyStore) {
		t.Fatalf("erreur attendue ErrNoHostKeyStore, obtenu : %v", err)
	}
}

// Le magasin par défaut sert les appelants qui ne passent pas d'option explicite.
func TestRunPlaybookUsesDefaultHostKeyStore(t *testing.T) {
	SetDefaultHostKeyStore(ansibleFakeStore{})
	t.Cleanup(func() { SetDefaultHostKeyStore(nil) })

	_, _, err := RunPlaybook("playbooks/test.yml", "172.16.0.11", "PRIVATE", "claude", false)
	if !errors.Is(err, ErrHostNotPinned) {
		t.Fatalf("le magasin par défaut doit être consulté, erreur obtenue : %v", err)
	}
}

// Exécution nominale : le playbook reçoit bien un known_hosts épinglé + un
// StrictHostKeyChecking=yes, la clé privée est en 0600 dans un répertoire 0700, et
// tout disparaît après cleanup().
func TestRunPlaybookPinsHostAndProtectsSecrets(t *testing.T) {
	leftovers := isolatedTmp(t)
	fakeAnsibleBin(t, `#!/bin/sh
echo "ARGS: $*"
key=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--private-key" ]; then key="$a"; fi
  prev="$a"
done
dir=$(dirname "$key")
echo "KEYMODE: $(stat -c %a "$key")"
echo "DIRMODE: $(stat -c %a "$dir")"
echo "KEY: $(cat "$key")"
echo "KNOWNHOSTS: $(cat "$dir/known_hosts")"
`)

	stored, authorized := newPinnedHostKey(t)
	store := ansibleFakeStore{keys: map[string][]string{"172.16.0.11": {stored}}}

	out, cleanup, err := RunPlaybook("playbooks/test.yml", "172.16.0.11", "MA-CLE-PRIVEE", "claude", true,
		WithHostKeyStore(store))
	if err != nil {
		t.Fatalf("RunPlaybook: %v", err)
	}
	raw, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("lecture de la sortie : %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	got := string(raw)

	for _, want := range []string{
		"-o StrictHostKeyChecking=yes",
		"-o UserKnownHostsFile=",
		"--become",
		"KEYMODE: 600",
		"DIRMODE: 700",
		"KEY: MA-CLE-PRIVEE",
		"KNOWNHOSTS: 172.16.0.11 " + authorized,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sortie sans %q :\n%s", want, got)
		}
	}
	if strings.Contains(got, "accept-new") {
		t.Errorf("StrictHostKeyChecking=accept-new ne doit plus être passé :\n%s", got)
	}
	if names := leftovers(); len(names) != 0 {
		t.Fatalf("le répertoire temporaire doit être supprimé, trouvé : %v", names)
	}
}

// Un playbook bloqué doit être tué — lui ET ses enfants (ssh/python) qui gardent le
// pipe ouvert, sinon le lecteur ne verrait jamais d'EOF.
func TestRunPlaybookTimeoutKillsProcessGroup(t *testing.T) {
	leftovers := isolatedTmp(t)
	// Le `sleep &` hérite du pipe : sans tuer le groupe entier, io.ReadAll bloquerait
	// jusqu'à la fin du fils.
	fakeAnsibleBin(t, "#!/bin/sh\necho demarre\nsleep 60 &\nsleep 60\n")

	stored, _ := newPinnedHostKey(t)
	store := ansibleFakeStore{keys: map[string][]string{"172.16.0.11": {stored}}}

	out, cleanup, err := RunPlaybook("playbooks/test.yml", "172.16.0.11", "PRIVATE", "claude", false,
		WithHostKeyStore(store), WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatalf("RunPlaybook: %v", err)
	}

	read := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(out)
		read <- err
	}()
	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("lecture de la sortie : %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("le lecteur n'a jamais reçu d'EOF : le groupe de processus a survécu au délai")
	}

	exitErr := cleanup()
	if exitErr == nil || !strings.Contains(exitErr.Error(), "délai maximal") {
		t.Fatalf("cleanup doit signaler le dépassement de délai, obtenu : %v", exitErr)
	}
	if names := leftovers(); len(names) != 0 {
		t.Fatalf("le répertoire temporaire doit être supprimé même après un kill, trouvé : %v", names)
	}
}

func TestPlaybookTimeoutFromEnv(t *testing.T) {
	cases := []struct {
		env  string
		want time.Duration
	}{
		{"", defaultPlaybookTimeout},
		{"45m", 45 * time.Minute},
		{"2h", 2 * time.Hour},
		{"n'importe quoi", defaultPlaybookTimeout},
		{"-5m", defaultPlaybookTimeout},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.env), func(t *testing.T) {
			t.Setenv("GOACORE_ANSIBLE_TIMEOUT", c.env)
			if got := PlaybookTimeout(); got != c.want {
				t.Fatalf("PlaybookTimeout() = %v, attendu %v", got, c.want)
			}
		})
	}
}
