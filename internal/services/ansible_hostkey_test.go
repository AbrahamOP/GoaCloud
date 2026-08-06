package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// ─────────────────────────────────────────────────────────────────────────────
// Amorçage du TOFU Ansible.
//
// RunPlaybook refuse tout hôte absent de ssh_host_keys : sans chemin d'épinglage
// explicite, ce durcissement condamnerait définitivement toutes les planifications
// existantes. Ces tests fixent le chemin d'amorçage (scan de l'empreinte puis
// épinglage validé) et son refus d'écraser une clé déjà épinglée.
// ─────────────────────────────────────────────────────────────────────────────

// hostKeyFixture est la table ssh_host_keys en mémoire du faux pilote.
type hostKeyFixture struct {
	mu      sync.Mutex
	keys    map[string]string
	inserts int
}

func (f *hostKeyFixture) get(ip string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.keys[ip]
	return v, ok
}

var (
	hkFixturesMu sync.Mutex
	hkFixtures   = map[string]*hostKeyFixture{}
	hkRegOnce    sync.Once
)

type hkDriver struct{}

func (hkDriver) Open(dsn string) (driver.Conn, error) {
	hkFixturesMu.Lock()
	defer hkFixturesMu.Unlock()
	f, ok := hkFixtures[dsn]
	if !ok {
		return nil, errors.New("unknown fixture")
	}
	return hkConn{f: f}, nil
}

type hkConn struct{ f *hostKeyFixture }

func (c hkConn) Prepare(q string) (driver.Stmt, error) {
	return hkStmt{f: c.f, query: strings.ToLower(strings.Join(strings.Fields(q), " "))}, nil
}
func (hkConn) Close() error              { return nil }
func (hkConn) Begin() (driver.Tx, error) { return nil, io.EOF }

type hkStmt struct {
	f     *hostKeyFixture
	query string
}

func (hkStmt) Close() error  { return nil }
func (hkStmt) NumInput() int { return -1 }

func (s hkStmt) Exec(args []driver.Value) (driver.Result, error) {
	if strings.HasPrefix(s.query, "insert into ssh_host_keys") && len(args) == 2 {
		ip, _ := args[0].(string)
		key, _ := args[1].(string)
		s.f.mu.Lock()
		s.f.keys[ip] = key
		s.f.inserts++
		s.f.mu.Unlock()
	}
	return driver.RowsAffected(1), nil
}

func (s hkStmt) Query(args []driver.Value) (driver.Rows, error) {
	if strings.Contains(s.query, "select host_key from ssh_host_keys") && len(args) == 1 {
		ip, _ := args[0].(string)
		if key, ok := s.f.get(ip); ok {
			return &retRows{cols: []string{"host_key"}, vals: [][]driver.Value{{key}}}, nil
		}
		return &retRows{cols: []string{"host_key"}}, nil
	}
	return &retRows{}, nil
}

func openHostKeyDB(t *testing.T, dsn string, f *hostKeyFixture) *sql.DB {
	t.Helper()
	hkRegOnce.Do(func() { sql.Register("hostkeyfake", hkDriver{}) })
	hkFixturesMu.Lock()
	hkFixtures[dsn] = f
	hkFixturesMu.Unlock()
	db, err := sql.Open("hostkeyfake", dsn)
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		hkFixturesMu.Lock()
		delete(hkFixtures, dsn)
		hkFixturesMu.Unlock()
	})
	return db
}

// startFakeSSHServer monte un serveur SSH local qui présente une clé hôte puis
// refuse toute authentification : c'est exactement ce qu'un scan d'empreinte
// rencontre (la clé d'hôte est échangée AVANT l'authentification).
func startFakeSSHServer(t *testing.T) (host string, port int, signer gossh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("génération de la clé hôte : %v", err)
	}
	signer, err = gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer : %v", err)
	}

	cfg := &gossh.ServerConfig{
		PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
			return nil, errors.New("no")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen : %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sc, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go gossh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						_ = ch.Reject(gossh.Prohibited, "test")
					}
				}()
				sc.Close()
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, signer
}

// TestScanHostKeyReturnsPresentedKey : le scan récupère la clé présentée par l'hôte
// sans rien enregistrer — c'est ce que l'exploitant compare hors bande avant de
// confirmer l'épinglage.
func TestScanHostKeyReturnsPresentedKey(t *testing.T) {
	ip, port, signer := startFakeSSHServer(t)

	key, err := scanHostKey(ip, port)
	if err != nil {
		t.Fatalf("scanHostKey: %v", err)
	}
	if gossh.FingerprintSHA256(key) != gossh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("la clé récupérée n'est pas celle présentée par l'hôte")
	}
	if !strings.HasPrefix(gossh.FingerprintSHA256(key), "SHA256:") {
		t.Fatalf("empreinte inattendue : %s", gossh.FingerprintSHA256(key))
	}
}

func TestScanHostKeyRejectsInvalidIP(t *testing.T) {
	if _, err := scanHostKey("pas-une-ip", 22); err == nil {
		t.Fatal("une IP invalide doit être refusée avant toute connexion")
	}
}

// TestPinHostKeyBootstrapsAndIsIdempotent : c'est le chemin d'amorçage qui manquait.
// Après épinglage, l'hôte est connu de RunPlaybook (PinnedHostKeys le voit), et un
// second épinglage de la même clé ne réécrit rien.
func TestPinHostKeyBootstrapsAndIsIdempotent(t *testing.T) {
	ip, port, signer := startFakeSSHServer(t)
	f := &hostKeyFixture{keys: map[string]string{}}
	s := &SSHService{db: openHostKeyDB(t, "pin-bootstrap", f)}

	fp, err := s.pinHostKeyOnPort(ip, port, "")
	if err != nil {
		t.Fatalf("pinHostKeyOnPort: %v", err)
	}
	if fp != gossh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("empreinte restituée %s, attendue %s", fp, gossh.FingerprintSHA256(signer.PublicKey()))
	}

	// La clé est désormais visible par le chemin Ansible.
	pinned, err := s.PinnedHostKeys(ip)
	if err != nil {
		t.Fatalf("PinnedHostKeys: %v", err)
	}
	if len(pinned) != 1 {
		t.Fatalf("%d clé(s) épinglée(s) après amorçage, attendu 1", len(pinned))
	}
	if _, err := knownHostsContent(ip, pinned); err != nil {
		t.Fatalf("la clé épinglée doit produire un known_hosts exploitable : %v", err)
	}

	// Idempotent : même clé, aucune réécriture.
	if _, err := s.pinHostKeyOnPort(ip, port, fp); err != nil {
		t.Fatalf("second épinglage de la même clé refusé : %v", err)
	}
	f.mu.Lock()
	inserts := f.inserts
	f.mu.Unlock()
	if inserts != 1 {
		t.Fatalf("%d insertions, attendu 1 (épinglage idempotent)", inserts)
	}
}

// TestPinHostKeyRefusesFingerprintMismatch : si l'exploitant annonce une empreinte
// et que l'hôte en présente une autre, on n'écrit rien.
func TestPinHostKeyRefusesFingerprintMismatch(t *testing.T) {
	ip, port, _ := startFakeSSHServer(t)
	f := &hostKeyFixture{keys: map[string]string{}}
	s := &SSHService{db: openHostKeyDB(t, "pin-mismatch", f)}

	_, err := s.pinHostKeyOnPort(ip, port, "SHA256:cequelexploitantattendait")
	if !errors.Is(err, ErrHostKeyFingerprintMismatch) {
		t.Fatalf("erreur attendue ErrHostKeyFingerprintMismatch, obtenu : %v", err)
	}
	if len(f.keys) != 0 {
		t.Fatal("rien ne doit être épinglé quand l'empreinte ne correspond pas")
	}
}

// TestPinHostKeyRefusesToOverwriteAnotherKey : une clé déjà épinglée n'est jamais
// remplacée en silence (réinstallation… ou interposition).
func TestPinHostKeyRefusesToOverwriteAnotherKey(t *testing.T) {
	ip, port, _ := startFakeSSHServer(t)
	other, _ := newPinnedHostKey(t)
	f := &hostKeyFixture{keys: map[string]string{ip: other}}
	s := &SSHService{db: openHostKeyDB(t, "pin-overwrite", f)}

	_, err := s.pinHostKeyOnPort(ip, port, "")
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("erreur attendue ErrHostKeyMismatch, obtenu : %v", err)
	}
	if got, _ := f.get(ip); got != other {
		t.Fatal("la clé épinglée a été écrasée")
	}
	if _, err := base64.StdEncoding.DecodeString(other); err != nil {
		t.Fatalf("fixture invalide : %v", err)
	}
}

// TestHostNotPinnedErrorExplainsTheBootstrap : le message doit dire précisément quoi
// faire — c'est lui que l'exploitant lit quand une planification s'arrête.
func TestHostNotPinnedErrorExplainsTheBootstrap(t *testing.T) {
	msg := hostNotPinnedError("172.16.0.11").Error()
	for _, needle := range []string{"172.16.0.11", "Épingler", "empreinte", "ssh-keygen -lf"} {
		if !strings.Contains(msg, needle) {
			t.Errorf("le message d'erreur ne mentionne pas %q : %s", needle, msg)
		}
	}
}

// TestWarnUnpinnedSchedulesIsBestEffort : l'avertissement de démarrage ne doit jamais
// faire tomber le boot, quel que soit le magasin fourni.
func TestWarnUnpinnedSchedulesIsBestEffort(t *testing.T) {
	// Magasin qui n'inventorie rien : simple no-op.
	warnUnpinnedSchedules(ansibleFakeStore{})
	// Magasin réel adossé à une base qui ne connaît pas la requête : erreur avalée.
	f := &hostKeyFixture{keys: map[string]string{}}
	warnUnpinnedSchedules(&SSHService{db: openHostKeyDB(t, "warn-schedules", f)})
	// Et via le point d'accroche de démarrage.
	SetDefaultHostKeyStore(&SSHService{db: openHostKeyDB(t, "warn-schedules-2", f)})
	t.Cleanup(func() { SetDefaultHostKeyStore(nil) })
}

// TestScanHostKeyPortIsAnsiblePort : l'épinglage doit porter sur le port qu'Ansible
// utilise réellement, sinon le known_hosts généré ne correspondrait à rien.
func TestScanHostKeyPortIsAnsiblePort(t *testing.T) {
	if ansibleSSHPort != 22 {
		t.Fatalf("ansibleSSHPort = %s, attendu 22 (forme d'hôte nu du known_hosts)", strconv.Itoa(ansibleSSHPort))
	}
}
