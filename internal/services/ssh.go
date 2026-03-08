package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goacloud/internal/models"

	gossh "golang.org/x/crypto/ssh"
)

// SSHService handles SSH key management and deployment.
type SSHService struct {
	db        *sql.DB
	encKey    [32]byte
	proxmoxURL         string
	proxmoxTokenID     string
	proxmoxTokenSecret string
	proxmoxNode        string
	skipTLS   bool
}

// NewSSHService creates a new SSHService.
func NewSSHService(db *sql.DB, encKey [32]byte, proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret string, skipTLS bool) *SSHService {
	return &SSHService{
		db:                 db,
		encKey:             encKey,
		proxmoxURL:         proxmoxURL,
		proxmoxTokenID:     proxmoxTokenID,
		proxmoxTokenSecret: proxmoxTokenSecret,
		proxmoxNode:        proxmoxNode,
		skipTLS:            skipTLS,
	}
}

func (s *SSHService) tlsConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: s.skipTLS} //nolint:gosec
}

// EncryptSSHKey encrypts a plaintext SSH private key using AES-256-GCM.
func (s *SSHService) EncryptSSHKey(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.encKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSSHKey decrypts an AES-256-GCM encrypted SSH private key.
func (s *SSHService) DecryptSSHKey(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.encKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// GenerateRSAKey creates a 4096-bit RSA key pair.
func GenerateRSAKey(name string) (*models.SSHKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	privatePEM := string(pem.EncodeToMemory(&privBlock))

	publicRsaKey, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicBytes := gossh.MarshalAuthorizedKey(publicRsaKey)
	publicPEM := string(publicBytes)

	fingerprint := gossh.FingerprintLegacyMD5(publicRsaKey)

	return &models.SSHKey{
		Name:          name,
		KeyType:       "RSA",
		PublicKey:     strings.TrimSpace(publicPEM),
		PrivateKey:    privatePEM,
		Fingerprint:   fingerprint,
		AssociatedVMs: "",
	}, nil
}

// SaveSSHKey saves an SSH key to the database (encrypts private key).
func (s *SSHService) SaveSSHKey(key *models.SSHKey) error {
	encrypted, err := s.EncryptSSHKey(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %v", err)
	}
	_, err = s.db.Exec("INSERT INTO ssh_keys (name, key_type, public_key, private_key, fingerprint) VALUES (?, ?, ?, ?, ?)",
		key.Name, key.KeyType, key.PublicKey, encrypted, key.Fingerprint)
	return err
}

// DeleteSSHKey removes an SSH key by ID.
func (s *SSHService) DeleteSSHKey(id int) error {
	_, err := s.db.Exec("DELETE FROM ssh_keys WHERE id = ?", id)
	return err
}

// GetSSHKeys returns all SSH keys (without private keys).
func (s *SSHService) GetSSHKeys() ([]models.SSHKey, error) {
	rows, err := s.db.Query("SELECT id, name, key_type, public_key, fingerprint, created_at, COALESCE(associated_vms, '') FROM ssh_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.SSHKey
	for rows.Next() {
		var k models.SSHKey
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.Fingerprint, &k.CreatedAt, &k.AssociatedVMs); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// GetSSHKeyByID returns an SSH key including the decrypted private key.
func (s *SSHService) GetSSHKeyByID(id int) (*models.SSHKey, error) {
	var k models.SSHKey
	err := s.db.QueryRow("SELECT id, name, key_type, public_key, private_key, fingerprint, created_at, COALESCE(associated_vms, '') FROM ssh_keys WHERE id = ?", id).
		Scan(&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.PrivateKey, &k.Fingerprint, &k.CreatedAt, &k.AssociatedVMs)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(k.PrivateKey, "-----") {
		return &k, nil
	}
	decrypted, err := s.DecryptSSHKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}
	k.PrivateKey = decrypted
	return &k, nil
}

// UpdateSSHKeyUsage updates the associated VMs for an SSH key.
func (s *SSHService) UpdateSSHKeyUsage(id int, associatedVMs string) error {
	_, err := s.db.Exec("UPDATE ssh_keys SET associated_vms = ? WHERE id = ?", associatedVMs, id)
	return err
}

// MigrateEncryptSSHKeys migrates plaintext SSH keys to encrypted format.
func (s *SSHService) MigrateEncryptSSHKeys() {
	rows, err := s.db.Query("SELECT id, private_key FROM ssh_keys")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var privKey string
		if err := rows.Scan(&id, &privKey); err != nil {
			continue
		}
		if strings.HasPrefix(privKey, "-----") {
			encrypted, err := s.EncryptSSHKey(privKey)
			if err == nil {
				s.db.Exec("UPDATE ssh_keys SET private_key = ? WHERE id = ?", encrypted, id)
			}
		}
	}
}

// SSHHostKeyCallback implements Trust-On-First-Use (TOFU) for SSH host key verification.
func (s *SSHService) SSHHostKeyCallback(ip string) gossh.HostKeyCallback {
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())
		var stored string
		err := s.db.QueryRow("SELECT host_key FROM ssh_host_keys WHERE ip = ?", ip).Scan(&stored)
		if err == sql.ErrNoRows {
			if _, err := s.db.Exec("INSERT INTO ssh_host_keys (ip, host_key) VALUES (?, ?)", ip, keyB64); err != nil {
				return nil
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("erreur de lecture clé hôte: %v", err)
		}
		if stored != keyB64 {
			return fmt.Errorf("clé hôte SSH modifiée pour %s — possible attaque MITM", ip)
		}
		return nil
	}
}

// pveNodeInternal is used internally for node discovery.
type pveNodeInternal struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

type pveNodesListInternal struct {
	Data []pveNodeInternal `json:"data"`
}

// DeployKeyToProxmox deploys a public key to a Proxmox VM/CT via the API.
func (s *SSHService) DeployKeyToProxmox(vmid int, vmType string, pubKey string) error {
	if s.proxmoxURL == "" || s.proxmoxTokenID == "" {
		return fmt.Errorf("Proxmox Configuration Missing")
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: s.tlsConfig()},
		Timeout:   10 * time.Second,
	}

	// Auto-discover node
	targetNode := s.proxmoxNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", s.proxmoxURL), nil)
	reqNodes.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", s.proxmoxTokenID, s.proxmoxTokenSecret))
	if respNodes, err := client.Do(reqNodes); err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList pveNodesListInternal
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == s.proxmoxNode {
							found = true
							break
						}
					}
				}
				if !found && firstOnline != "" {
					targetNode = firstOnline
				}
			}
		}
	}

	guestType := "qemu"
	if vmType == "lxc" || vmType == "CT" {
		guestType = "lxc"
	}
	targetURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d/config", s.proxmoxURL, targetNode, guestType, vmid)

	encodedKey := url.QueryEscape(pubKey)
	encodedKey = strings.ReplaceAll(encodedKey, "+", "%20")

	paramKey := "sshkeys"
	if guestType == "lxc" {
		paramKey = "ssh-public-keys"
	}

	data := url.Values{}
	data.Set(paramKey, encodedKey)

	req, err := http.NewRequest("PUT", targetURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", s.proxmoxTokenID, s.proxmoxTokenSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Request Failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "ssh-public-keys") && strings.Contains(bodyStr, "property is not defined") {
			return fmt.Errorf("Proxmox refuse l'injection de clé pour ce conteneur LXC (Limitation API). Veuillez ajouter la clé manuellement dans ~/.ssh/authorized_keys sur le conteneur.")
		}
		return fmt.Errorf("Proxmox API Error %d: %s", resp.StatusCode, bodyStr)
	}

	return nil
}

// DeployKeyViaSSHPassword deploys a public key via SSH password authentication.
func (s *SSHService) DeployKeyViaSSHPassword(ip string, port int, user string, password string, pubKey string) error {
	config := &gossh.ClientConfig{
		User: user,
		Auth: []gossh.AuthMethod{
			gossh.Password(password),
		},
		HostKeyCallback: s.SSHHostKeyCallback(ip),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH Connection Failed: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Failed to create session: %v", err)
	}
	defer session.Close()

	session.Stdin = strings.NewReader(pubKey + "\n")
	cmd := "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("Failed to install key: %v. Output: %s", err, string(output))
	}

	return nil
}
