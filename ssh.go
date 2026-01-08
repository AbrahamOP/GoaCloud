package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "fmt"
    // "log" // Removed if unused
    "time"

    "golang.org/x/crypto/ssh"
    "net/http"
    "net/url"
    "strings"
    "io"
)

type SSHKey struct {
    ID          int
    Name        string
    KeyType     string
    PublicKey   string
    PrivateKey  string
    Fingerprint string
    CreatedAt   time.Time
    AssociatedVMs string // Comma-separated list of VM names/IDs
}

// GenerateRSAKey creates a 4096-bit RSA key pair
func GenerateRSAKey(name string) (*SSHKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return nil, err
    }

    // Encode Private Key to PEM
    privDER := x509.MarshalPKCS1PrivateKey(privateKey)
    privBlock := pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privDER,
    }
    privatePEM := string(pem.EncodeToMemory(&privBlock))

    // Generate Public Key
    publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
    if err != nil {
        return nil, err
    }
    publicBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
    publicPEM := string(publicBytes)
    
    // Generate Fingerprint
    fingerprint := ssh.FingerprintLegacyMD5(publicRsaKey)

    return &SSHKey{
        Name:        name,
        KeyType:     "RSA",
        PublicKey:   strings.TrimSpace(publicPEM),
        PrivateKey:  privatePEM,
        Fingerprint: fingerprint,
        AssociatedVMs: "",
    }, nil
}

func SaveSSHKey(key *SSHKey) error {
    _, err := db.Exec("INSERT INTO ssh_keys (name, key_type, public_key, private_key, fingerprint) VALUES (?, ?, ?, ?, ?)",
        key.Name, key.KeyType, key.PublicKey, key.PrivateKey, key.Fingerprint)
    return err
}

func DeleteSSHKey(id int) error {
    _, err := db.Exec("DELETE FROM ssh_keys WHERE id = ?", id)
    return err
}

func GetSSHKeys() ([]SSHKey, error) {
    rows, err := db.Query("SELECT id, name, key_type, public_key, fingerprint, created_at, COALESCE(associated_vms, '') FROM ssh_keys ORDER BY created_at DESC")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var keys []SSHKey
    for rows.Next() {
        var k SSHKey
        if err := rows.Scan(&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.Fingerprint, &k.CreatedAt, &k.AssociatedVMs); err != nil {
            return nil, err
        }
        keys = append(keys, k)
    }
    return keys, nil
}

func GetSSHKeyByID(id int) (*SSHKey, error) {
    var k SSHKey
    err := db.QueryRow("SELECT id, name, key_type, public_key, private_key, fingerprint, created_at, COALESCE(associated_vms, '') FROM ssh_keys WHERE id = ?", id).
        Scan(&k.ID, &k.Name, &k.KeyType, &k.PublicKey, &k.PrivateKey, &k.Fingerprint, &k.CreatedAt, &k.AssociatedVMs)
    if err != nil {
        return nil, err
    }
    return &k, nil
}

func UpdateSSHKeyUsage(id int, associatedVMs string) error {
    _, err := db.Exec("UPDATE ssh_keys SET associated_vms = ? WHERE id = ?", associatedVMs, id)
    return err
}

// Proxmox Deployment

type PveNodeInternal struct {
    Node   string `json:"node"`
    Status string `json:"status"`
}

type PveNodesListInternal struct {
    Data []PveNodeInternal `json:"data"`
}

func DeployKeyToProxmox(vmid int, vmType string, pubKey string) error {
	proxmoxURL := getEnv("PROXMOX_URL", "")
	tokenID := getEnv("PROXMOX_TOKEN_ID", "")
	tokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
	configuredNode := getEnv("PROXMOX_NODE", "pve")

	if proxmoxURL == "" || tokenID == "" {
		return fmt.Errorf("Proxmox Configuration Missing")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	// 1. Auto-discover Node (Crucial fix for "hostname lookup log failed")
	targetNode := configuredNode
	reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", proxmoxURL), nil)
	reqNodes.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	respNodes, err := client.Do(reqNodes)
	if err == nil {
		defer respNodes.Body.Close()
		if respNodes.StatusCode == 200 {
			var nodeList PveNodesListInternal
			if err := json.NewDecoder(respNodes.Body).Decode(&nodeList); err == nil {
				found := false
				firstOnline := ""
				for _, n := range nodeList.Data {
					if n.Status == "online" {
						if firstOnline == "" {
							firstOnline = n.Node
						}
						if n.Node == configuredNode {
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

	// 2. Prepare URL based on Type
	// Default to qemu if not specified or unrecognized
	guestType := "qemu"
	if vmType == "lxc" || vmType == "CT" {
		guestType = "lxc"
	}
	targetURL := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%d/config", proxmoxURL, targetNode, guestType, vmid)
    
    // 3. Prepare Data
    data := url.Values{}
    // Proxmox expects the value to be URL-encoded "inside" the parameter 
    // because it stores it as a URL-encoded string in the VM config.
    // The previous error 400 "invalid urlencoded string" meant the decoded value contained invalid chars (spaces).
    // ADDITIONALLY: Proxmox seems to reject '+' as space in this inner encoded string. It wants '%20'.
    encodedKey := url.QueryEscape(pubKey)
    encodedKey = strings.ReplaceAll(encodedKey, "+", "%20")
    
    // Choose correct parameter based on type
    // QEMU uses 'sshkeys', LXC uses 'ssh-public-keys'
    paramKey := "sshkeys"
    if guestType == "lxc" {
        paramKey = "ssh-public-keys"
    }
    
    data.Set(paramKey, encodedKey)

    req, err := http.NewRequest("PUT", targetURL, strings.NewReader(data.Encode()))
    if err != nil {
        return err
    }
    
    req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := client.Do(req)
    if err != nil {
        // Log logging failure details if desired
        return fmt.Errorf("Request Failed: %v", err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    if resp.StatusCode != 200 {
        bodyStr := string(body)
        // Friendly Error for LXC Limitation
        if strings.Contains(bodyStr, "ssh-public-keys") && strings.Contains(bodyStr, "property is not defined") {
             return fmt.Errorf("Proxmox refuse l'injection de clé pour ce conteneur LXC (Limitation API). Veuillez ajouter la clé manuellement dans ~/.ssh/authorized_keys sur le conteneur.")
        }
        return fmt.Errorf("Proxmox API Error %d: %s", resp.StatusCode, bodyStr)
    }
    
    return nil
}

func DeployKeyViaSSHPassword(ip string, port int, user string, password string, pubKey string) error {
    config := &ssh.ClientConfig{
        User: user,
        Auth: []ssh.AuthMethod{
            ssh.Password(password),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In a real app we might want to check host keys
        Timeout:         10 * time.Second,
    }

    addr := fmt.Sprintf("%s:%d", ip, port)
    client, err := ssh.Dial("tcp", addr, config)
    if err != nil {
        return fmt.Errorf("SSH Connection Failed: %v", err)
    }
    defer client.Close()

    session, err := client.NewSession()
    if err != nil {
        return fmt.Errorf("Failed to create session: %v", err)
    }
    defer session.Close()

    // Command to safely append key
    // 1. Create .ssh dir if not exists
    // 2. Append key with newline
    // 3. Set permissions
    cmd := fmt.Sprintf(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "%s" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, pubKey)
    
    output, err := session.CombinedOutput(cmd)
    if err != nil {
        return fmt.Errorf("Failed to install key: %v. Output: %s", err, string(output))
    }

    return nil
}

func GetVMListForSSH() ([]VM, error) {
    proxmoxURL := getEnv("PROXMOX_URL", "")
    proxmoxTokenID := getEnv("PROXMOX_TOKEN_ID", "")
    proxmoxTokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    proxmoxNode := getEnv("PROXMOX_NODE", "pve")

    if proxmoxURL == "" || proxmoxTokenID == "" {
        return nil, fmt.Errorf("Proxmox Configuration Missing")
    }

    // Reuse getProxmoxStats from main.go (same package)
    // includeGuests=true, fullDetails=false (we just need names/IPs)
    stats, err := getProxmoxStats(proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret, true, false)
    if err != nil {
        return nil, err
    }

    return stats.VMs, nil
}
