package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// defaultCertDir holds the generated pair. It is a SUBDIRECTORY of the working
	// directory on purpose: a named volume can be mounted on it (see the compose
	// files) without masking the binary and the assets that live next to it.
	defaultCertDir = "certs"

	// certValidity is the lifetime of a generated certificate; renewBefore is how
	// long before expiry a boot regenerates it. An instance restarted at least once
	// a month therefore never serves an expired certificate.
	certValidity = 365 * 24 * time.Hour
	renewBefore  = 30 * 24 * time.Hour
)

// alwaysCoveredHosts are the SANs every generated certificate carries, so the
// container health check (https://localhost:8443) and a local test keep working
// whatever TLS_HOSTS says. 0.0.0.0 is deliberately NOT here: it is a wildcard bind
// address, never a name a client connects to, so it covered exactly nothing.
var alwaysCoveredHosts = []string{"localhost", "127.0.0.1", "::1"}

// CertConfig locates the TLS material served on the HTTPS port and describes what
// a generated certificate must cover. Two modes:
//
//   - operator-provided (TLS_CERT_FILE + TLS_KEY_FILE): GoaCore never writes those
//     files, it only checks at boot that the pair loads.
//   - self-signed (default): the pair is PERSISTED under TLS_DIR and reused across
//     restarts. Regenerating it on every start — the previous behaviour — handed
//     the operator a new fingerprint at every update, so the browser warning could
//     never be dismissed for good and the certificate could not be pinned.
type CertConfig struct {
	CertFile string
	KeyFile  string

	// Hosts are the extra DNS names / IPs put in the SANs (env TLS_HOSTS), on top
	// of alwaysCoveredHosts. Ignored when the operator provides the pair.
	Hosts []string

	// SelfSigned reports whether GoaCore owns the pair (generates and renews it).
	SelfSigned bool

	// Incomplete carries the "half configured" case — exactly one of
	// TLS_CERT_FILE / TLS_KEY_FILE set — so Ensure can refuse to boot instead of
	// silently falling back to a self-signed pair the operator did not ask for.
	Incomplete string
}

// CertConfigFromEnv reads the certificate configuration from the environment:
//
//	TLS_CERT_FILE / TLS_KEY_FILE  operator-provided pair (set both, or neither)
//	TLS_DIR                       directory of the generated pair (default "certs")
//	TLS_HOSTS                     comma/space separated DNS names and IPs added to
//	                              the SANs, e.g. "goacore.example.com,192.168.20.11"
func CertConfigFromEnv() CertConfig {
	certFile := strings.TrimSpace(os.Getenv("TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("TLS_KEY_FILE"))
	if certFile != "" || keyFile != "" {
		cfg := CertConfig{CertFile: certFile, KeyFile: keyFile}
		if certFile == "" || keyFile == "" {
			cfg.Incomplete = "TLS_CERT_FILE and TLS_KEY_FILE must be set together (one of them is empty)"
		}
		return cfg
	}

	dir := strings.TrimSpace(os.Getenv("TLS_DIR"))
	if dir == "" {
		dir = defaultCertDir
	}
	return CertConfig{
		CertFile:   filepath.Join(dir, "server.crt"),
		KeyFile:    filepath.Join(dir, "server.key"),
		Hosts:      splitHosts(os.Getenv("TLS_HOSTS")),
		SelfSigned: true,
	}
}

// Ensure makes sure a usable pair sits on disk before the server starts. It is
// idempotent: on an instance whose certificate is still valid and still covers the
// configured hosts, it does nothing.
func (c CertConfig) Ensure() error {
	if c.Incomplete != "" {
		return errors.New(c.Incomplete)
	}
	if !c.SelfSigned {
		// Fail fast: an unreadable operator certificate must surface at boot, not as
		// a TLS handshake error on the first visitor.
		if _, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
			return fmt.Errorf("cannot load the certificate from TLS_CERT_FILE/TLS_KEY_FILE: %w", err)
		}
		slog.Info("Using the operator-provided TLS certificate", "cert", c.CertFile)
		return nil
	}
	if reason := c.regenerateReason(); reason != "" {
		slog.Info("Generating a self-signed certificate", "reason", reason, "cert", c.CertFile, "hosts", c.hosts())
		return c.generate()
	}
	slog.Info("Reusing the persisted self-signed certificate", "cert", c.CertFile)
	return nil
}

// regenerateReason returns why the persisted pair cannot be reused, or "" when it
// can. Checking the SANs (and not only the expiry) is what makes TLS_HOSTS usable:
// adding a name to it regenerates the certificate at the next restart.
func (c CertConfig) regenerateReason() string {
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return "no usable certificate/key pair on disk"
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "certificate cannot be parsed"
	}
	if time.Now().Add(renewBefore).After(leaf.NotAfter) {
		return "certificate expired or expiring within " + renewBefore.String()
	}
	for _, host := range c.hosts() {
		if err := leaf.VerifyHostname(host); err != nil {
			return fmt.Sprintf("certificate does not cover %q", host)
		}
	}
	return ""
}

// hosts returns the SANs the certificate must carry: the always-covered ones plus
// TLS_HOSTS, deduplicated and order-stable.
func (c CertConfig) hosts() []string {
	seen := make(map[string]bool, len(alwaysCoveredHosts)+len(c.Hosts))
	out := make([]string, 0, len(alwaysCoveredHosts)+len(c.Hosts))
	for _, host := range append(append([]string{}, alwaysCoveredHosts...), c.Hosts...) {
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

// generate writes a fresh self-signed pair to disk.
func (c CertConfig) generate() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Random serial: reissuing under the same subject with the fixed serial 1 (the
	// previous behaviour) is exactly what makes certificate stores report a
	// duplicate/invalid entry after a regeneration.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	hosts := c.hosts()
	// CommonName is legacy (clients match on the SANs) but it is what a certificate
	// viewer shows first: put the name the operator actually browses to there.
	commonName := "GoaCore"
	if len(c.Hosts) > 0 {
		commonName = c.Hosts[0]
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"GoaCore Self-Signed"},
			CommonName:   commonName,
		},
		// One hour of backdating absorbs a small clock skew between the container
		// and the browser, which would otherwise reject a brand new certificate.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Délibérément PAS une autorité de certification. Faire de ce certificat une CA
		// permettrait d'importer sa clé privée — qui vit dans un volume, en clair — dans
		// le magasin de confiance de l'exploitant, où elle signerait alors n'importe quel
		// domaine : la commodité de « ne plus voir l'avertissement » se paierait d'une
		// autorité de confiance dont la clé traîne sur le disque. Pour supprimer
		// réellement l'avertissement, la voie est TLS_CERT_FILE/TLS_KEY_FILE avec un
		// certificat d'une PKI interne ou de Let's Encrypt ; à défaut, l'exception par
		// site dans le navigateur, que la persistance de l'empreinte rend durable.
		IsCA: false,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// 0700: the directory holds the private key. MkdirAll is a no-op when the
	// volume is already mounted and owned by the app user.
	if dir := filepath.Dir(c.CertFile); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create the certificate directory %q: %w", dir, err)
		}
	}

	if err := writeFileMode(c.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	// 0600, enforced even when the file already exists: the key now PERSISTS, so a
	// world-readable mode inherited from the umask would outlive the process.
	if err := writeFileMode(c.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}

	slog.Info("Self-signed certificate generated", "cert", c.CertFile, "key", c.KeyFile,
		"hosts", hosts, "expires", template.NotAfter.Format(time.RFC3339))
	return nil
}

// writeFileMode writes data and forces perm, which os.WriteFile alone does not do
// when the file already exists (it keeps the previous mode).
func writeFileMode(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("cannot write %q: %w", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("cannot set the permissions of %q: %w", path, err)
	}
	return nil
}

// splitHosts parses a comma/space separated host list, dropping empty items.
func splitHosts(raw string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// NewTLSConfig returns a TLS config. When skipVerify is true, certificate verification is disabled.
func NewTLSConfig(skipVerify bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: skipVerify} //nolint:gosec
}
