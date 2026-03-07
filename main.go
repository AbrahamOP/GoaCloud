package main

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "database/sql"
    "embed"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "html/template"
    "io"
    "log"
    "math/big"

    "net"
    "net/http"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/go-sql-driver/mysql"
    "golang.org/x/crypto/bcrypt"
    "github.com/pquerna/otp/totp"
    "encoding/base64"
    "image/png"
    "bytes"
    "github.com/gorilla/sessions"
)

//go:embed templates/*
var templatesFS embed.FS

var db *sql.DB
var tmpl *template.Template
var wazuhClient *WazuhClient
var wazuhIndexerClient *WazuhIndexerClient
var ollamaClient *OllamaClient
var store *sessions.CookieStore
var skipTLSVerify bool

// newTLSConfig retourne une config TLS contrôlée par SKIP_TLS_VERIFY
func newTLSConfig() *tls.Config {
    return &tls.Config{InsecureSkipVerify: skipTLSVerify} //nolint:gosec
}

type Config struct {
    // ...
}

type App struct {
    ID          int
    Name        string
    Description string
    ExternalURL string
    IconURL     string
    Category    string
}

type VM struct {
    ID     int
    Name   string
    Status string // running, stopped
    Uptime string
    IP     string
    Type   string // "qemu" or "lxc"
}

type ProxmoxStats struct {
    CPU          int // Percentage
    RAM          int // Percentage
    RAMUsed      float64
    RAMTotal     float64
    RAMUsedStr   string
    RAMTotalStr  string
    Storage      int // Percentage
    VMs          []VM
}

// PveNodesList and PveNodeStatus structs (assuming they exist elsewhere or are implicitly handled)
type PveNode struct {
    Node   string `json:"node"`
    Status string `json:"status"`
}

type PveNodesList struct {
    Data []PveNode `json:"data"`
}

type PveNodeStatus struct {
    Data struct {
        CPU    float64 `json:"cpu"`
        Memory struct {
            Total int64 `json:"total"`
            Used  int64 `json:"used"`
        } `json:"memory"`
        Rootfs struct {
            Total int64 `json:"total"`
            Used  int64 `json:"used"`
        } `json:"rootfs"`
    } `json:"data"`
}

type PveVM struct {
    VMID   int    `json:"vmid"`
    Name   string `json:"name"`
    Status string `json:"status"`
    Uptime int    `json:"uptime"` // Uptime in seconds
    // Add other fields if needed, like IP for example
}

type PveVMList struct {
    Data []PveVM `json:"data"`
}

type GuestDetail struct {
    ID          int     `json:"id"`
    Name        string  `json:"name"`
    Status      string  `json:"status"`
    Uptime      string  `json:"uptime"`
    CPU         float64 `json:"cpu"` // Percentage
    Cores       int     `json:"cores"`
    RAMUsed     string  `json:"ram_used"`
    RAMTotal    string  `json:"ram_total"`
    RAMPercent  int     `json:"ram_percent"`
    DiskUsed    string  `json:"disk_used"`
    DiskTotal   string  `json:"disk_total"`
    DiskPercent int     `json:"disk_percent"`
    Note        string  `json:"note"`
    Type        string  `json:"type"`
}

type PveGuestStatusResponse struct {
    Data struct {
        Name    string  `json:"name"`
        Status  string  `json:"status"`
        Uptime  float64 `json:"uptime"`
        CPUs    int     `json:"cpus"`
        CPU     float64 `json:"cpu"`
        Mem     int64   `json:"mem"`
        MaxMem  int64   `json:"maxmem"`
        Disk    int64   `json:"disk"`
        MaxDisk int64   `json:"maxdisk"`
    } `json:"data"`
}

type PveGuestConfigResponse struct {
    Data struct {
        Name        string `json:"name"`
        Hostname    string `json:"hostname"`
        Description string `json:"description"`
        Cores       int    `json:"cores"`
        Memory      int    `json:"memory"`
    } `json:"data"`
}

type PveNetworkInterface struct {
    Name      string `json:"name"`
    IPAddresses []struct {
        IPAddress     string `json:"ip-address"`
        IPAddressType string `json:"ip-address-type"` // ipv4 or ipv6
    } `json:"ip-addresses"`
}

type PveLxcInterfacesResponse struct {
    Data []struct {
        Name string `json:"name"`
        Inet string `json:"inet"` // IPv4/CIDR
    } `json:"data"`
}

type PveQemuInterfacesResponse struct {
    Data struct {
        Result []PveNetworkInterface `json:"result"`
    } `json:"data"`
}

type User struct {
    ID        int
    Username  string
    Email     string
    Role      string
    CreatedAt string
    MFAEnabled bool
    MFASecret  string
}

type AuditLog struct {
    ID        int
    UserID    int // Can be 0 if unknown/system
    Username  string
    Action    string
    Details   string
    IPAddress string
    CreatedAt string
}


func main() {
    // Lire la config TLS globale avant tout
    skipTLSVerify = getEnv("SKIP_TLS_VERIFY", "false") == "true"
    if skipTLSVerify {
        log.Println("ATTENTION: SKIP_TLS_VERIFY=true — vérification des certificats TLS désactivée")
    }

    // Configuration de la base de données via variables d'environnement
    cfg := mysql.Config{
        User:                 getEnv("DB_USER", "root"),
        Passwd:               getEnv("DB_PASS", "root"),
        Net:                  "tcp",
        Addr:                 getEnv("DB_HOST", "127.0.0.1:3306"),
        DBName:               getEnv("DB_NAME", "goacloud"),
        AllowNativePasswords: true,
        ParseTime:            true,
    }

    var err error
    // Attente de la disponibilité de la base de données (retry loop simple)
    // Utile pour docker-compose où la DB peut mettre du temps à démarrer
    for i := 0; i < 30; i++ {
        db, err = sql.Open("mysql", cfg.FormatDSN())
        if err == nil {
            err = db.Ping()
            if err == nil {
                break
            }
        }
        log.Printf("En attente de la base de données... (%d/30)", i+1)
        time.Sleep(1 * time.Second)
    }

    if err != nil {
        log.Fatalf("Impossible de se connecter à la base de données: %v", err)
    }
    defer db.Close()
    log.Println("Connecté à la base de données MySQL.")

    // Initialize Users DB (Schema Migration)
    initUsersDB()

    	// Parsing des templates
	funcMap := template.FuncMap{
		"json": func(v interface{}) (template.JS, error) {
			a, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(a), nil
		},
	}
	tmpl = template.New("").Funcs(funcMap)
	// Check if templates directory exists on disk (Dev Mode / Hot Reload)
	if _, statErr := os.Stat("templates"); statErr == nil {
		log.Println("Loading templates from disk (Development Mode)")
		tmpl, err = tmpl.ParseGlob("templates/*.html")
	} else {
		// Fallback to embedded templates (Production)
		log.Println("Loading embedded templates (Production Mode)")
		tmpl, err = tmpl.ParseFS(templatesFS, "templates/*.html")
	}

	if err != nil {
		log.Fatalf("Erreur lors du parsing des templates: %v", err)
	}    

    	// Wazuh Config
	wazuhURL := getEnv("WAZUH_API_URL", "")
	wazuhUser := getEnv("WAZUH_USER", "")
	wazuhPass := getEnv("WAZUH_PASSWORD", "")

	if wazuhURL != "" {
		log.Printf("Configuring Wazuh Client: %s", wazuhURL)
		wazuhClient = NewWazuhClient(wazuhURL, wazuhUser, wazuhPass)
	} else {
		log.Println("Wazuh URL not configured")
	}
    
    // Wazuh Indexer Config (Advanced)
    wazuhIndexerURL := getEnv("WAZUH_INDEXER_URL", "")
    wazuhIndexerUser := getEnv("WAZUH_INDEXER_USER", "")
    wazuhIndexerPass := getEnv("WAZUH_INDEXER_PASSWORD", "")
    
    if wazuhIndexerURL != "" {
        log.Printf("Configuring Wazuh Indexer Client: %s", wazuhIndexerURL)
        wazuhIndexerClient = NewWazuhIndexerClient(wazuhIndexerURL, wazuhIndexerUser, wazuhIndexerPass)
    }

    // AI Client Config
	aiProvider := getEnv("AI_PROVIDER", "ollama") // "ollama" or "openai"
	aiURL := getEnv("AI_URL", "")                 // For Ollama (e.g. http://localhost:11434)
	aiAPIKey := getEnv("AI_API_KEY", "")          // For OpenAI
	aiModel := getEnv("AI_MODEL", "")             // e.g. "gpt-4" or "mistral"

	// Legacy Support (OLLAMA_*)
	if aiProvider == "ollama" && aiURL == "" {
		aiURL = getEnv("OLLAMA_URL", "")
	}
	if aiModel == "" {
		aiModel = getEnv("OLLAMA_MODEL", "")
	}

	if aiURL != "" || aiAPIKey != "" || aiProvider == "ollama" {
		aiClient = NewAIClient(aiProvider, aiURL, aiAPIKey, aiModel)
		if aiClient != nil {
			log.Printf("AI Client configured: %s (%s)", aiProvider, aiModel)
		}
	} else {
		log.Println("AI enrichment disabled (missing configuration)")
	}

    // Initialize Session Store
    sessionKey := getEnv("SESSION_SECRET", "super-secret-key-change-me")
    if sessionKey == "super-secret-key-change-me" {
        log.Println("AVERTISSEMENT: SESSION_SECRET est la valeur par défaut. Définissez une clé secrète forte en production !")
    }
    store = sessions.NewCookieStore([]byte(sessionKey))
    secureCookie := getEnv("COOKIE_SECURE", "true") != "false"
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   86400 * 1, // 1 day
        HttpOnly: true,
        Secure:   secureCookie,
        SameSite: http.SameSiteStrictMode, // Protection CSRF basique
    }

    // Discord Bot Config
    discordToken := getEnv("DISCORD_BOT_TOKEN", "")
    discordChannel := getEnv("DISCORD_CHANNEL_ID", "")
    if discordToken != "" && discordChannel != "" {
        err = InitDiscordBot(discordToken, discordChannel)
        if err != nil {
            log.Printf("Failed to init Discord Bot: %v", err)
        } else {
            defer CloseDiscordBot()
            // Canal dédié aux alertes d'authentification (optionnel, fallback sur canal principal)
            discordAuthChannelID = getEnv("DISCORD_AUTH_CHANNEL_ID", "")
        }
    } else {
        log.Println("Discord Bot not configured (missing token or channel)")
    }

    // Routes
    http.HandleFunc("/setup", handleSetup)
    http.HandleFunc("/login", handleLogin)
    http.HandleFunc("/logout", handleLogout)
    
    // Console Routes
    http.HandleFunc("/console", authMiddleware(handleConsolePage))
    http.HandleFunc("/api/ssh/ws", authMiddleware(handleSSHWebSocket))
    http.HandleFunc("/add", authMiddleware(handleAddApp))
    http.HandleFunc("/proxmox", authMiddleware(handleProxmox))
    // Proxmox APIs
	http.HandleFunc("/api/proxmox/guest/", authMiddleware(handleProxmoxGuestDetail)) // API needs auth too
	http.HandleFunc("/api/proxmox/ips", authMiddleware(handleProxmoxIPs))

    // Wazuh & SOAR
	http.HandleFunc("/wazuh", authMiddleware(handleWazuh))
	http.HandleFunc("/soar", authMiddleware(handleSoar))
    http.HandleFunc("/api/soar/discord/test", authMiddleware(handleDiscordTest))
    http.HandleFunc("/api/soar/ai/test", authMiddleware(handleAITest))
    http.HandleFunc("/api/soar/config", authMiddleware(handleSoarConfig))
    
    // SSH Manager
    http.HandleFunc("/ssh", authMiddleware(handleSSHManager))
    http.HandleFunc("/api/ssh/generate", authMiddleware(handleSSHManager)) // POST for generate
    http.HandleFunc("/api/ssh/deploy", authMiddleware(handleSSHDeploy))
    http.HandleFunc("/api/ssh/delete", authMiddleware(handleSSHDelete))
    
    // Ansible Routes
    http.HandleFunc("/ansible", authMiddleware(handleAnsible))
    http.HandleFunc("/api/ansible/run", authMiddleware(handleAnsibleRun))
    http.HandleFunc("/api/ansible/upload", authMiddleware(handleAnsibleUpload))

    // User Management Routes
    http.HandleFunc("/users", authMiddleware(handleUsers))
    http.HandleFunc("/audit-logs", authMiddleware(handleAuditLogs))
    http.HandleFunc("/api/users/add", authMiddleware(handleAddUser))
    http.HandleFunc("/api/users/delete", authMiddleware(handleDeleteUser))
    http.HandleFunc("/api/users/update", authMiddleware(handleUpdateUser))

    // Proxmox API (JSON)
    http.HandleFunc("/api/proxmox/stats", authMiddleware(handleProxmoxAPI))

    // User Profile
    http.HandleFunc("/profile", authMiddleware(handleProfile))
    http.HandleFunc("/api/profile/update", authMiddleware(handleUpdateProfile))
    
    // MFA Routes
    http.HandleFunc("/api/mfa/setup", authMiddleware(handleSetupMFA))
    http.HandleFunc("/api/mfa/verify", authMiddleware(handleVerifyMFA))
    http.HandleFunc("/api/mfa/disable", authMiddleware(handleDisableMFA))

	http.HandleFunc("/api/wazuh/vulns/", authMiddleware(handleWazuhVulns))
    http.HandleFunc("/", authMiddleware(handleDashboard))

    // Start Cache Worker
    go startCacheWorker()
    // Start Wazuh Worker
    go startWazuhWorker()
    // Start SOAR Worker
    go startSoarWorker()
    // Start SOAR alert dedup cleaner
    go startAlertDedupCleaner()

    // Démarrage du serveur
    // SSL Setup
    certFile := "server.crt"
    keyFile := "server.key"
    if _, err := os.Stat(certFile); os.IsNotExist(err) {
        log.Println("Certificat SSL introuvable, génération d'un certificat auto-signé...")
        if err := generateSelfSignedCert(); err != nil {
            log.Fatalf("Erreur génération certificat: %v", err)
        }
    }

    // Démarrage du serveur
    httpPort := getEnv("PORT", "8080")
    httpsPort := getEnv("HTTPS_PORT", "8443")

    // Goroutine pour HTTP → redirige vers HTTPS
    go func() {
        log.Printf("Serveur HTTP démarré sur http://0.0.0.0:%s (redirection HTTPS)", httpPort)
        redirectMux := http.NewServeMux()
        redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            host := r.Host
            if h, _, err := net.SplitHostPort(host); err == nil {
                host = h
            }
            target := "https://" + host + ":" + httpsPort + r.RequestURI
            http.Redirect(w, r, target, http.StatusMovedPermanently)
        })
        if err := http.ListenAndServe(":"+httpPort, redirectMux); err != nil {
            log.Printf("Erreur serveur HTTP: %v", err)
        }
    }()

    log.Printf("Serveur HTTPS démarré sur https://0.0.0.0:%s", httpsPort)

    // Middleware de sécurité appliqué globalement à toutes les routes HTTPS
    secureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https://img.icons8.com; connect-src 'self' wss:;")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        http.DefaultServeMux.ServeHTTP(w, r)
    })

    // Explicitly disable HTTP/2 to avoid protocol errors with self-signed certs
    server := &http.Server{
        Addr:         ":" + httpsPort,
        Handler:      secureHandler,
        TLSConfig:    &tls.Config{},
        TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
    }

    if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
        log.Fatalf("Erreur serveur HTTPS: %v", err)
    }
}

// startAlertDedupCleaner purge les entrées de soarAlertDedup vieilles de plus de 2h
// pour éviter une fuite mémoire en production longue durée.
func startAlertDedupCleaner() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-2 * time.Hour)
		soarAlertDedup.Range(func(k, v interface{}) bool {
			if t, ok := v.(time.Time); ok && t.Before(cutoff) {
				soarAlertDedup.Delete(k)
			}
			return true
		})
	}
}

func startWazuhWorker() {
    log.Println("Starting Wazuh Cache Worker...")
    // Initial fetch
    updateWazuhCache()

    ticker := time.NewTicker(2 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        updateWazuhCache()
    }
}

func updateWazuhCache() {
    if wazuhClient == nil { return }

    log.Println("Worker: Updating Wazuh Cache...")
    agents, err := wazuhClient.GetAgents()
    if err != nil {
        log.Printf("Worker Error (Wazuh Agents): %v", err)
        return
    }

    // Enrich with Vuln Summaries
    if wazuhIndexerClient != nil {
        var agentIDs []string
        for _, a := range agents {
            agentIDs = append(agentIDs, a.ID)
        }
        
        summaries, err := wazuhIndexerClient.GetVulnSummary(agentIDs)
        if err != nil {
            log.Printf("Worker Error (Vuln Summaries): %v", err)
        } else {
            for i := range agents {
                if s, ok := summaries[agents[i].ID]; ok {
                    agents[i].VulnSummary.Total = s.Total
                    agents[i].VulnSummary.Critical = s.Critical
                    agents[i].VulnSummary.High = s.High
                    agents[i].VulnSummary.Medium = s.Medium
                    agents[i].VulnSummary.Low = s.Low
                }
            }
        }
    }

    // Prefetch Vulnerability Details for all agents
    log.Println("Worker: Prefetching vulnerability details...")
    for _, agent := range agents {
        var vulns []WazuhVuln
        var err error

        // Use Indexer if available, else Legacy API
        if wazuhIndexerClient != nil {
             vulns, err = wazuhIndexerClient.GetVulnerabilities(agent.ID)
        } else {
             vulns, err = wazuhClient.GetAgentVulnerabilitiesList(agent.ID)
        }

        if err != nil {
            log.Printf("Worker Error (Vuln Details %s): %v", agent.ID, err)
            // Keep old cache if exists? Or empty? Let's not overwrite if error to avoid flickering empty state.
            continue 
        }

        // Store in Vuln Cache (Valid for 10 min, but refreshed every 2 min by worker)
        vulnCache.Store(agent.ID, CachedVulns{
            Data:   vulns,
            Expiry: time.Now().Add(10 * time.Minute), 
        })
    }

    wazuhCache.Mutex.Lock()
    wazuhCache.Agents = agents
    wazuhCache.UpdatedAt = time.Now()
    wazuhCache.Mutex.Unlock()
    
    log.Printf("Worker: Wazuh Cache updated (%d agents)", len(agents))
}

func startCacheWorker() {
    log.Println("Starting VM Cache Worker...")
    // Initial update
    updateVMCache()
    
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        updateVMCache()
    }
}

func updateVMCache() {
    proxmoxURL := getEnv("PROXMOX_URL", "")
    proxmoxTokenID := getEnv("PROXMOX_TOKEN_ID", "")
    proxmoxTokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    proxmoxNode := getEnv("PROXMOX_NODE", "pve")

    if proxmoxURL == "" || proxmoxTokenID == "" {
        log.Println("Worker: Configuration Proxmox manquante")
        return
    }

    log.Println("Worker: Mise à jour du cache des IPs...")
    // Fetch all VMs/CTs without stats first
    // We reuse getProxmoxStats but we force full fetch to get IPs
    // Since getProxmoxStats uses 'includeGuests=true' to fetch LIST + IPs, we can reuse it
    // But we need to separate the logic to avoid dependency loop or complexity.
    // Let's create a simpler fetcher here or reuse parts.
    
    // To keep it simple: We call the heavy getProxmoxStats(..., true)
    // Then we iterate and save to DB.
    stats, err := getProxmoxStats(proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret, true, true)
    if err != nil {
        log.Printf("Worker Error: %v", err)
        return
    }

    for _, vm := range stats.VMs {
        // Upsert into DB regardless of IP presence
        // If IP is missing, it will be "-" or empty, which is fine for visibility
        _, err := db.Exec(`
            INSERT INTO vm_cache (vmid, name, ip_address, vm_type) 
            VALUES (?, ?, ?, ?) 
            ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address), name = VALUES(name), updated_at = NOW()`,
            vm.ID, vm.Name, vm.IP, vm.Type)
        if err != nil {
            log.Printf("Worker DB Error for VM %d: %v", vm.ID, err)
        }
    }
    log.Printf("Worker: Cache mis à jour (%d VMs traitées)", len(stats.VMs))
}

// SOAR Worker
var soarAgentStatus sync.Map // map[string]string (AgentID -> Status)
var soarAlertDedup sync.Map  // map[string]time.Time (alertKey -> insertedAt) — déduplication des alertes envoyées

// --- Rate Limiting Login ---
type rateLimitEntry struct {
	count        int
	blockedUntil time.Time
}

var (
	loginMu      sync.Mutex
	loginLimiter = make(map[string]*rateLimitEntry)
)

func isLoginBlocked(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	e, ok := loginLimiter[ip]
	if !ok {
		return false
	}
	return time.Now().Before(e.blockedUntil)
}

// recordLoginFailure enregistre un échec et retourne (count, blocked)
func recordLoginFailure(ip string) (int, bool) {
	loginMu.Lock()
	defer loginMu.Unlock()
	e, ok := loginLimiter[ip]
	if !ok {
		e = &rateLimitEntry{}
		loginLimiter[ip] = e
	}
	e.count++
	if e.count >= 5 {
		e.blockedUntil = time.Now().Add(15 * time.Minute)
		e.count = 0
		return 5, true
	}
	return e.count, false
}

func resetLoginFailures(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginLimiter, ip)
}

// notifyLoginFailure envoie une alerte Discord en cas d'échec de connexion
func notifyLoginFailure(ip, username, reason string, attempt int, blocked bool) {
	if discordSession == nil {
		return
	}
	title := "Échec de connexion"
	msg := fmt.Sprintf("**IP:** `%s`\n**Utilisateur:** `%s`\n**Raison:** %s\n**Tentatives:** %d/5", ip, username, reason, attempt)
	if blocked {
		title = "⛔ IP Bloquée"
		msg += "\n\n> L'adresse IP a été bloquée pendant **15 minutes** suite à trop d'échecs."
	}
	SendAuthAlert(title, msg, blocked)
}

type SoarConfig struct {
    AlertStatus   bool `json:"alert_status"`
    AlertSSH      bool `json:"alert_ssh"`
    AlertSudo     bool `json:"alert_sudo"`
    AlertFIM      bool `json:"alert_fim"`
    AlertPackages bool `json:"alert_packages"`
}

var (
    currentSoarConfig SoarConfig
    soarConfigMutex   sync.RWMutex
    soarConfigFile    = "soar_config.json"

    // AI Client
    aiClient AIClient
    
    // Wazuh Cache
    wazuhCache      WazuhCache
    
    // Vuln Detail Cache (On-Demand)
    vulnCache       sync.Map // map[string]CachedVulns (AgentID -> {Data, Expiry})
)

type WazuhCache struct {
    Agents    []WazuhAgent
    UpdatedAt time.Time
    Mutex     sync.RWMutex
}

type CachedVulns struct {
    Data   []WazuhVuln
    Expiry time.Time
}

func initSoarDB() {
    // Ensure table exists (Self-healing for existing deployments)
    query := `
    CREATE TABLE IF NOT EXISTS soar_config (
        id INT PRIMARY KEY DEFAULT 1,
        alert_status BOOLEAN DEFAULT TRUE,
        alert_ssh BOOLEAN DEFAULT TRUE,
        alert_sudo BOOLEAN DEFAULT TRUE,
        alert_fim BOOLEAN DEFAULT TRUE,
        alert_packages BOOLEAN DEFAULT TRUE
    );`
    _, err := db.Exec(query)
    if err != nil {
        log.Printf("Error creating soar_config table: %v", err)
    }

    // Ensure default row exists
    db.Exec("INSERT IGNORE INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages) VALUES (1, TRUE, TRUE, TRUE, TRUE, TRUE)")
}

func loadSoarConfig() {
    soarConfigMutex.Lock()
    defer soarConfigMutex.Unlock()

    // Initialize DB if needed (first run check)
    initSoarDB()

    row := db.QueryRow("SELECT alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages FROM soar_config WHERE id = 1")
    err := row.Scan(
        &currentSoarConfig.AlertStatus, 
        &currentSoarConfig.AlertSSH, 
        &currentSoarConfig.AlertSudo, 
        &currentSoarConfig.AlertFIM, 
        &currentSoarConfig.AlertPackages,
    )

    if err != nil {
        log.Printf("Error loading SOAR config from DB: %v. Using defaults.", err)
        // Defaults already set in initSoarDB, but just in case of read error:
        currentSoarConfig = SoarConfig{true, true, true, true, true}
    }
}

func saveSoarConfig() error {
    soarConfigMutex.RLock()
    // Prepare values
    status := currentSoarConfig.AlertStatus
    ssh := currentSoarConfig.AlertSSH
    sudo := currentSoarConfig.AlertSudo
    fim := currentSoarConfig.AlertFIM
    packages := currentSoarConfig.AlertPackages
    soarConfigMutex.RUnlock()

    _, err := db.Exec(`
        INSERT INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages)
        VALUES (1, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
        alert_status = VALUES(alert_status),
        alert_ssh = VALUES(alert_ssh),
        alert_sudo = VALUES(alert_sudo),
        alert_fim = VALUES(alert_fim),
        alert_packages = VALUES(alert_packages)
    `, status, ssh, sudo, fim, packages)

    if err != nil {
        log.Printf("Error saving SOAR config to DB: %v", err)
        return err
    }
    
    log.Println("SOAR Config saved to DB successfully.")
    return nil
}

func startSoarWorker() {
    log.Println("Starting SOAR Worker...")
    
    loadSoarConfig() // Load config on start
    
    // Initial population without alerting (to avoid startup spam)
    populateInitialState()
    
    ticker := time.NewTicker(1 * time.Minute) // Check every minute
    defer ticker.Stop()

    for range ticker.C {
        loadSoarConfig() // Reload config from DB on every tick to ensure syncing
        checkSoarEvents()
    }
}

func populateInitialState() {
    if wazuhClient == nil { return }
    agents, err := wazuhClient.GetAgents()
    if err == nil {
        for _, agent := range agents {
            soarAgentStatus.Store(agent.ID, agent.Status)
        }
        log.Printf("SOAR Init: Loaded state for %d agents.", len(agents))
    }
}

func checkSoarEvents() {
    if wazuhClient == nil {
        return
    }

    soarConfigMutex.RLock()
    config := currentSoarConfig
    soarConfigMutex.RUnlock()
    
    // 1. Check for Status Changes
    if config.AlertStatus {
        agents, err := wazuhClient.GetAgents()
        if err != nil {
            log.Printf("SOAR Worker Error (GetAgents): %v", err)
        } else {
            for _, agent := range agents {
                prevStatusInterface, loaded := soarAgentStatus.Load(agent.ID)
                soarAgentStatus.Store(agent.ID, agent.Status)
                
                if loaded {
                    prevStatus := prevStatusInterface.(string)
                    if prevStatus != agent.Status {
                        log.Printf("SOAR State Change: Agent %s changed from %s to %s", agent.Name, prevStatus, agent.Status)

                        if agent.Status == "disconnected" {
                            // Construct minimal context
                            ctx := AIAlertContext{
                                Title: "🔴 Agent Perdu",
                                Description: fmt.Sprintf("L'agent **%s** ne répond plus.", agent.Name),
                                AgentName: agent.Name,
                                AgentIP: agent.IP,
                                RuleLevel: 10, // High severity implied
                            }
                            sendEnrichedDiscordAlert(ctx, "critical")
                        } else if agent.Status == "active" && prevStatus == "disconnected" {
                            // Construct minimal context for status alerts
                            ctx := AIAlertContext{
                                Title: "🟢 Agent Retrouvé",
                                Description: fmt.Sprintf("L'agent **%s** est de nouveau en ligne.", agent.Name),
                                AgentName: agent.Name,
                                AgentIP: agent.IP,
                                RuleLevel: 0, 
                            }
                            sendEnrichedDiscordAlert(ctx, "info")
                        }
                    }
                }
            }
        }
    }
    
    // 2. Check for Alerts (Indexer)
    if wazuhIndexerClient != nil {
        alerts, err := wazuhIndexerClient.GetRecentAlerts(2 * time.Minute)
        if err != nil {
            log.Printf("SOAR Worker Error (Indexer): %v", err)
        } else {
            for _, alert := range alerts {
                alertKey := alert.Agent.ID + alert.Rule.ID + alert.Timestamp
                if _, loaded := soarAlertDedup.Load(alertKey); !loaded {
                     soarAlertDedup.Store(alertKey, time.Now())
                     
                     var title, msg, severity string
                     shouldSend := false

                     switch alert.Rule.ID {
                     case "5402": // Sudo
                        if config.AlertSudo {
                            shouldSend = true
                            title = "👑 Élévation de Privilèges"
                            msg = fmt.Sprintf("**Machine:** %s\n**Event:** Sudo to ROOT\n**Log:** `%s`", alert.Agent.Name, alert.FullLog)
                            severity = "critical"
                        }
                     
                     case "550", "553", "554": // FIM
                        if config.AlertFIM {
                            shouldSend = true
                            title = "📝 Intégrité des Fichiers"
                            msg = fmt.Sprintf("**Machine:** %s\n**Fichier:** `%s`\n**Event:** %s", alert.Agent.Name, alert.Syscheck.Path, alert.Rule.Description)
                            severity = "high"
                        }

                     case "2902", "2903": // Packages
                        if config.AlertPackages {
                            shouldSend = true
                            title = "📦 Gestion Logicielle"
                            msg = fmt.Sprintf("**Machine:** %s\n**Changement:** %s\n**Log:** `%s`", alert.Agent.Name, alert.Rule.Description, alert.FullLog)
                            severity = "info"
                        }

                     default: // SSH & Others
                         // Assuming any other rule we fetch (like 5716) is SSH based on our Indexer Query
                        if config.AlertSSH {
                            shouldSend = true
                            title = "🛡️ Alerte Sécurité"
                            msg = fmt.Sprintf("**Machine:** %s\n**Event:** %s\n**Source IP:** %s", alert.Agent.Name, alert.Rule.Description, alert.Data.SrcIP)
                            severity = "medium"
                            if alert.Rule.ID == "5712" { severity = "high" }
                        }
                     }
                     
                                          if shouldSend {
                         // Construct full context from WazuhAlert
                         aiCtx := AIAlertContext{
                             Title: title,
                             Description: msg,
                             AgentName: alert.Agent.Name,
                             AgentIP: alert.Agent.IP,
                             RuleID: alert.Rule.ID,
                             RuleLevel: alert.Rule.Level,
                             FullLog: alert.FullLog,
                             SourceIP: alert.Data.SrcIP,
                         }
                         sendEnrichedDiscordAlert(aiCtx, severity)
                      }
                }
            }
        }
    }
}

// Handlers

// Helper to send enriched alerts
func sendEnrichedDiscordAlert(alertCtx AIAlertContext, severity string) {
    if discordSession == nil { return }
    
    // Base message for Discord (Human readable)
    msg := alertCtx.Description

    // AI Enrichment
    if aiClient != nil {
        aiCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
        analysis, err := aiClient.EnrichAlert(aiCtx, alertCtx)
        cancel()
        
        if err == nil {
            msg += fmt.Sprintf("\n\n🤖 **Analyse AI:**\n%s", analysis)
        } else {
            log.Printf("AI Enrichment Failed: %v", err)
        }
    }

    SendDiscordAlert(alertCtx.Title, msg, severity)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    // Pre-check for Setup
    count, _ := CountUsers()
    if count == 0 {
        http.Redirect(w, r, "/setup", http.StatusSeeOther)
        return
    }

    if r.Method == http.MethodGet {
        tmpl.ExecuteTemplate(w, "login.html", nil)
        return
    }

    if r.Method == http.MethodPost {
        clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
        if isLoginBlocked(clientIP) {
            http.Error(w, "Trop de tentatives de connexion. Réessayez dans 15 minutes.", http.StatusTooManyRequests)
            return
        }

        username := r.FormValue("username")
        password := r.FormValue("password")
        mfaCode := r.FormValue("mfa_code")

        var hashedPassword string
        var mfaEnabled bool
        var mfaSecret sql.NullString // Can be NULL

        err := db.QueryRow("SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE username = ?", username).Scan(&hashedPassword, &mfaEnabled, &mfaSecret)
        if err == sql.ErrNoRows {
            n, blocked := recordLoginFailure(clientIP)
            go notifyLoginFailure(clientIP, username, "Utilisateur inconnu", n, blocked)
            renderError(w, "login.html", "Utilisateur inconnu")
            return
        } else if err != nil {
            log.Printf("Login DB Error: %v", err)
            http.Error(w, "Erreur interne", http.StatusInternalServerError)
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
        if err != nil {
            n, blocked := recordLoginFailure(clientIP)
            go notifyLoginFailure(clientIP, username, "Mot de passe incorrect", n, blocked)
            renderError(w, "login.html", "Mot de passe incorrect")
            return
        }

        // MFA Check
        if mfaEnabled {
            if mfaCode == "" {
                data := map[string]interface{}{
                    "Error":       "Code MFA requis",
                    "MFARequired": true,
                    "Username":    username,
                }
                tmpl.ExecuteTemplate(w, "login.html", data)
                return
            }

            // Verify Code
            valid := totp.Validate(mfaCode, mfaSecret.String)
            if !valid {
                n, blocked := recordLoginFailure(clientIP)
                go notifyLoginFailure(clientIP, username, "Code MFA invalide", n, blocked)
                renderError(w, "login.html", "Code MFA invalide")
                return
            }
        }

        // Creates session
        session, _ := store.Get(r, "goacloud-session")
        session.Values["authenticated"] = true
        session.Values["username"] = username
        session.Save(r, w)

        resetLoginFailures(clientIP)

        // Audit Log
        go logAudit(0, username, "Login", "Successful login", r.RemoteAddr)

        http.Redirect(w, r, "/", http.StatusSeeOther)
    }
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "goacloud-session")
    session.Values["authenticated"] = false
    session.Values["username"] = ""
    session.Options.MaxAge = -1
    session.Save(r, w)

    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleAddApp(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        tmpl.ExecuteTemplate(w, "add_app.html", nil)
        return
    }

    if r.Method == http.MethodPost {
        name := r.FormValue("name")
        url := r.FormValue("url")
        desc := r.FormValue("description")
        cat := r.FormValue("category")
        icon := r.FormValue("icon_url")

        if name == "" || url == "" {
            http.Error(w, "Nom et URL requis", http.StatusBadRequest)
            return
        }

        _, err := db.Exec("INSERT INTO apps (name, description, external_url, icon_url, category) VALUES (?, ?, ?, ?, ?)",
            name, desc, url, icon, cat)
        
        if err != nil {
            log.Printf("Erreur insertion app: %v", err)
            http.Error(w, "Erreur base de données", http.StatusInternalServerError)
            return
        }
        
        http.Redirect(w, r, "/", http.StatusSeeOther)
    }
}


func initUsersDB() {
    // Create core tables if they don't exist yet.
    // This makes the app self-sufficient regardless of whether schema.sql has been
    // applied by MySQL yet (avoids race condition on Docker first-start).
    coreTables := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS apps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            external_url VARCHAR(255) NOT NULL,
            icon_url VARCHAR(255),
            category VARCHAR(50) DEFAULT 'General',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS vm_cache (
            vmid INT PRIMARY KEY,
            name VARCHAR(255),
            ip_address VARCHAR(45),
            vm_type VARCHAR(10),
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS ssh_keys (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            key_type VARCHAR(20) DEFAULT 'RSA',
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            fingerprint VARCHAR(100),
            associated_vms TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE TABLE IF NOT EXISTS soar_config (
            id INT PRIMARY KEY DEFAULT 1,
            alert_status BOOLEAN DEFAULT TRUE,
            alert_ssh BOOLEAN DEFAULT TRUE,
            alert_sudo BOOLEAN DEFAULT TRUE,
            alert_fim BOOLEAN DEFAULT TRUE,
            alert_packages BOOLEAN DEFAULT TRUE
        )`,
    }
    for _, stmt := range coreTables {
        if _, err := db.Exec(stmt); err != nil {
            log.Printf("DB Init (create table): %v", err)
        }
    }
    // Ensure soar_config default row exists
    db.Exec(`INSERT IGNORE INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages) VALUES (1, TRUE, TRUE, TRUE, TRUE, TRUE)`)

    // Ensure email and role columns exist
    // Simple migration: try to add columns, ignore specific errors if they exist.
    // In a production app, we would check information_schema or use a migration tool.

    // Add Email column
    _, err := db.Exec("ALTER TABLE users ADD COLUMN email VARCHAR(255) NOT NULL DEFAULT ''")
    if err != nil {
        log.Printf("DB Migration (Email): %v", err)
    }

    // Add Role column
    _, err = db.Exec("ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'Viewer'")
    if err != nil {
        log.Printf("DB Migration (Role): %v", err)
    }

    // Add MFA Enabled column
    _, err = db.Exec("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")
    if err != nil {
        log.Printf("DB Migration (MFA Enabled): %v", err)
    }

    // Add MFA Secret column
    _, err = db.Exec("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
    if err != nil {
        log.Printf("DB Migration (MFA Secret): %v", err)
    }

    // Create Audit Logs Table
    _, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        username VARCHAR(255),
        action VARCHAR(255),
        details TEXT,
        ip_address VARCHAR(255),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    if err != nil {
        log.Printf("DB Migration (Audit Logs): %v", err)
    }

    // Add Associated VMs Column to SSH Keys
    _, err = db.Exec("ALTER TABLE ssh_keys ADD COLUMN associated_vms TEXT")
    if err != nil {
        if !strings.Contains(err.Error(), "Duplicate column") && !strings.Contains(err.Error(), "exists") {
             log.Printf("DB Migration (SSH Keys): %v", err)
        }
    }

    // Create SSH known hosts table (TOFU)
    _, err = db.Exec(`CREATE TABLE IF NOT EXISTS ssh_host_keys (
        ip VARCHAR(255) PRIMARY KEY,
        host_key TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    if err != nil {
        log.Printf("DB Migration (SSH Host Keys): %v", err)
    }
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
    rows, err := db.Query("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
    if err != nil {
        http.Error(w, "Erreur base de données", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var u User
        var createdAtTime string 
        if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &createdAtTime); err != nil {
            log.Printf("Error scanning user: %v", err)
            continue
        }
        u.CreatedAt = createdAtTime
        users = append(users, u)
    }

    data := struct {
        Users []User
    }{
        Users: users,
    }
    
    tmpl.ExecuteTemplate(w, "users.html", data)
}

func handleAddUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")
    email := r.FormValue("email")
    role := r.FormValue("role")

    if username == "" || password == "" {
        http.Error(w, "Username and password required", http.StatusBadRequest)
        return
    }

    if len(password) < 8 {
        http.Error(w, "Le mot de passe doit contenir au moins 8 caractères", http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error processing password", http.StatusInternalServerError)
        return
    }

    _, err = db.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)", username, string(hashedPassword), email, role)
    if err != nil {
        log.Printf("Error adding user: %v", err)
        http.Error(w, "Error saving user (duplicate?)", http.StatusInternalServerError)
        return
    }

    // Audit Log
    if sess, err := store.Get(r, "goacloud-session"); err == nil {
        if u, ok := sess.Values["username"].(string); ok && u != "" {
            go logAudit(0, u, "AddUser", fmt.Sprintf("Added user: %s (Role: %s)", username, role), r.RemoteAddr)
        }
    }

    http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    userID := r.FormValue("user_id")
    if userID == "" {
        http.Error(w, "User ID required", http.StatusBadRequest)
        return
    }

    // Protect against deleting the last admin
    var role string
    db.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role)
    if role == "Admin" {
        var adminCount int
        db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'Admin'").Scan(&adminCount)
        if adminCount <= 1 {
            http.Error(w, "Impossible de supprimer le dernier administrateur", http.StatusBadRequest)
            return
        }
    }

    _, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
    if err != nil {
        log.Printf("Error deleting user: %v", err)
        http.Error(w, "Error deleting user", http.StatusInternalServerError)
        return
    }

    // Audit Log
    if sess, err := store.Get(r, "goacloud-session"); err == nil {
        if u, ok := sess.Values["username"].(string); ok && u != "" {
            go logAudit(0, u, "DeleteUser", fmt.Sprintf("Deleted user ID: %s", userID), r.RemoteAddr)
        }
    }

    http.Redirect(w, r, "/users", http.StatusSeeOther)
}


func getApps() ([]App, error) {
    rows, err := db.Query("SELECT id, name, description, external_url, icon_url, category FROM apps ORDER BY category, name")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var apps []App
    for rows.Next() {
        var a App
        var icon sql.NullString
        if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.ExternalURL, &icon, &a.Category); err != nil {
            continue
        }
        if icon.Valid {
            a.IconURL = icon.String
        }
        apps = append(apps, a)
    }
    return apps, nil
}
func handleDashboard(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "goacloud-session")
    username, _ := session.Values["username"].(string)

    apps, err := getApps()
    if err != nil {
        log.Printf("Erreur récupération apps: %v", err)
    }

    data := map[string]interface{}{
        "Apps": apps,
        "Username": username,
    }
    tmpl.ExecuteTemplate(w, "dashboard.html", data)
}

func handleProxmox(w http.ResponseWriter, r *http.Request) {
    // Si les variables d'environnement sont définies, on tente l'appel API
    proxmoxURL := getEnv("PROXMOX_URL", "")
    proxmoxTokenID := getEnv("PROXMOX_TOKEN_ID", "")
    proxmoxTokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    proxmoxNode := getEnv("PROXMOX_NODE", "pve")

    var stats ProxmoxStats

    if proxmoxURL != "" && proxmoxTokenID != "" {
        realStats, err := getProxmoxStats(proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret, true, false)
        if err != nil {
            log.Printf("Erreur API Proxmox: %v", err)
            stats.VMs = []VM{{Name: fmt.Sprintf("Erreur: %v", err), Status: "error"}}
        } else {
            stats = realStats
        }
    } else {
        // Fallback Mock Data si pas de config
         stats = ProxmoxStats{
            CPU:      12,
            RAM:      45,
            RAMUsed:  14.2,
            RAMTotal: 32.0,
            Storage:  68,
            VMs: []VM{
                 {ID: 0, Name: "Mock Data (Configurez ENV)", Status: "running", Uptime: "-", IP: "127.0.0.1"},
            },
        }
    }

    err := tmpl.ExecuteTemplate(w, "proxmox.html", stats)
    if err != nil {
        log.Printf("Template execution error: %v", err)
        http.Error(w, "Erreur de rendu", http.StatusInternalServerError)
    }
}

func handleProxmoxAPI(w http.ResponseWriter, r *http.Request) {
    proxmoxURL := getEnv("PROXMOX_URL", "")
    proxmoxTokenID := getEnv("PROXMOX_TOKEN_ID", "")
    proxmoxTokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    proxmoxNode := getEnv("PROXMOX_NODE", "pve")

    var stats ProxmoxStats

    if proxmoxURL != "" && proxmoxTokenID != "" {
        // Optimization: Only fetch Stats, skip Guest list
        realStats, err := getProxmoxStats(proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret, false, false)
        if err != nil {
            stats.VMs = []VM{{Name: fmt.Sprintf("Erreur: %v", err), Status: "error"}}
        } else {
            stats = realStats
        }
    } else {
         stats = ProxmoxStats{
            CPU:      12,
            RAM:      45,
            RAMUsed:  14.2,
            RAMTotal: 32.0,
            Storage:  68,
            VMs: []VM{
                 {ID: 0, Name: "Mock Data (Configurez ENV)", Status: "running", Uptime: "-", IP: "127.0.0.1"},
            },
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(stats)
}

func handleProxmoxGuestDetail(w http.ResponseWriter, r *http.Request) {
    proxmoxURL := getEnv("PROXMOX_URL", "")
    proxmoxTokenID := getEnv("PROXMOX_TOKEN_ID", "")
    proxmoxTokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    proxmoxNode := getEnv("PROXMOX_NODE", "pve")

    guestType := r.URL.Query().Get("type") // "VM" or "CT" -> need to map to "qemu" or "lxc"
    guestID := r.URL.Query().Get("id")

    if guestType == "" || guestID == "" {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Missing type or id"})
        return
    }

    // Mapping type
    pveType := "qemu"
    if guestType == "CT" {
        pveType = "lxc"
    } else if guestType == "VM" {
        pveType = "qemu"
    } else {
        pveType = guestType
    }

    var detail GuestDetail
    var err error

    if proxmoxURL != "" && proxmoxTokenID != "" {
        detail, err = getProxmoxGuestDetail(proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret, pveType, guestID)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Error fetching details: %v", err)})
            return
        }
    } else {
        // Mock data
        detail = GuestDetail{
            ID: 100, Name: "Mock Guest", Status: "running", Uptime: "1d 2h",
            CPU: 15.5, Cores: 4, RAMUsed: "2.1 GB", RAMTotal: "4 GB", RAMPercent: 52,
            DiskUsed: "10 GB", DiskTotal: "32 GB", DiskPercent: 31,
            Note: "This is a mock note.", Type: guestType,
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(detail)
}

func handleProxmoxIPs(w http.ResponseWriter, r *http.Request) {
    rows, err := db.Query("SELECT vmid, ip_address FROM vm_cache")
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    ipMap := make(map[string]string)
    for rows.Next() {
        var vmid int
        var ip string
        if err := rows.Scan(&vmid, &ip); err == nil {
            ipMap[fmt.Sprintf("%d", vmid)] = ip
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(ipMap)
}

// Proxmox API Structs and Helpers



func getProxmoxStats(rawURL, configuredNode, tokenID, secret string, includeGuests bool, forceRealIPs bool) (ProxmoxStats, error) {
    // Normalise l'URL : enlève les slashes finaux et tout path parasite
    baseURL := strings.TrimRight(rawURL, "/")
    if u, err := url.Parse(baseURL); err == nil {
        baseURL = u.Scheme + "://" + u.Host
    }
    log.Printf("ProxmoxStats baseURL: %s", baseURL)

    stats := ProxmoxStats{VMs: []VM{}}
    client := &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: newTLSConfig(),
        },
    }

    headers := func(req *http.Request) {
        req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
    }

    // 0. Auto-discover Node — toujours tenter, quelle que soit la réponse HTTP
    reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
    headers(reqNodes)
    respNodes, err := client.Do(reqNodes)
    if err != nil {
        return stats, fmt.Errorf("Network error (Nodes): %v", err)
    }
    bodyNodes, _ := io.ReadAll(respNodes.Body)
    respNodes.Body.Close()

    targetNode := configuredNode
    var nodeList PveNodesList
    if jsonErr := json.Unmarshal(bodyNodes, &nodeList); jsonErr == nil && len(nodeList.Data) > 0 {
        found := false
        firstAny := ""
        firstOnline := ""
        for _, n := range nodeList.Data {
            if firstAny == "" {
                firstAny = n.Node
            }
            if n.Status == "online" && firstOnline == "" {
                firstOnline = n.Node
            }
            if n.Node == configuredNode {
                found = true
                break
            }
        }
        if !found {
            if firstOnline != "" {
                log.Printf("Proxmox: noeud '%s' introuvable, utilisation de '%s'", configuredNode, firstOnline)
                targetNode = firstOnline
            } else {
                log.Printf("Proxmox: aucun nœud online, utilisation du premier disponible '%s'", firstAny)
                targetNode = firstAny
            }
        }
    } else {
        log.Printf("Proxmox: impossible de décoder la liste des nœuds (HTTP %d): %s", respNodes.StatusCode, string(bodyNodes))
    }

    // 1. Node Status using targetNode
    req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes/%s/status", baseURL, targetNode), nil)
    headers(req)
    resp, err := client.Do(req)
    if err != nil {
        return stats, fmt.Errorf("Network error: %v", err)
    }
    bodyStatus, _ := io.ReadAll(resp.Body)
    resp.Body.Close()

    if resp.StatusCode != 200 {
        return stats, fmt.Errorf("API Error Node Status (%s) HTTP %d: %s", targetNode, resp.StatusCode, string(bodyStatus))
    }

    var nodeStatus PveNodeStatus
    if err := json.Unmarshal(bodyStatus, &nodeStatus); err == nil {
        stats.CPU = int(nodeStatus.Data.CPU * 100)
        stats.RAMTotal = float64(nodeStatus.Data.Memory.Total) / 1024 / 1024 / 1024
        stats.RAMUsed = float64(nodeStatus.Data.Memory.Used) / 1024 / 1024 / 1024
        
        stats.RAMUsedStr = fmt.Sprintf("%.2f GB", stats.RAMUsed)
        stats.RAMTotalStr = fmt.Sprintf("%.2f GB", stats.RAMTotal)

        if stats.RAMTotal > 0 {
            stats.RAM = int((stats.RAMUsed / stats.RAMTotal) * 100)
        }
        
        // Storage (Rootfs)
        storageTotal := float64(nodeStatus.Data.Rootfs.Total)
        storageUsed := float64(nodeStatus.Data.Rootfs.Used)
        if storageTotal > 0 {
            stats.Storage = int((storageUsed / storageTotal) * 100)
        } else {
            stats.Storage = 0
        }
    } else {
        log.Printf("JSON Decode Error Node Status: %v", err)
    }

    // Helper to fetch guests
    if includeGuests {
        // Optimization: Fetch from DB Cache first for IPs, only fetch list from API
        // Wait, if we use cache, we still need the list to know which VMs exist (status changes).
        // So: Fetch List from API (fast), then enrich with IPs from DB (fast).
        
        // 1. Fetch List from API (QEMU + LXC)
        var allGuests []VM

        fetchAPI := func(endpoint, kind string) {
            req, _ := http.NewRequest("GET", endpoint, nil)
            headers(req)
            resp, err := client.Do(req)
            if err == nil {
                defer resp.Body.Close()
                if resp.StatusCode == 200 {
                    var vms PveVMList
                    if err := json.NewDecoder(resp.Body).Decode(&vms); err == nil {
                        for _, vm := range vms.Data {
                            allGuests = append(allGuests, VM{
                                ID:     vm.VMID,
                                Name:   vm.Name,
                                Status: vm.Status,
                                Uptime: fmt.Sprintf("%dh", vm.Uptime/3600),
                                IP:     "-", // Default
                                Type:   kind,
                            })
                        }
                    }
                }
            }
        }

        fetchAPI(fmt.Sprintf("%s/api2/json/nodes/%s/qemu", baseURL, targetNode), "VM")
        fetchAPI(fmt.Sprintf("%s/api2/json/nodes/%s/lxc", baseURL, targetNode), "CT")
        
        stats.VMs = allGuests

        if forceRealIPs {
            // Worker Mode: Fetch Real IPs from API
             var wg sync.WaitGroup
            for i := range stats.VMs {
                if stats.VMs[i].Status != "running" {
                    continue
                }
                wg.Add(1)
                go func(idx int) {
                    defer wg.Done()
                    ip, err := getGuestIP(client, baseURL, targetNode, tokenID, secret, stats.VMs[idx].Type, stats.VMs[idx].ID)
                    if err == nil && ip != "" {
                        stats.VMs[idx].IP = ip
                    }
                }(i)
            }
            wg.Wait()
        } else {
             // Display Mode: Enrich IPs from DB Cache
            rows, err := db.Query("SELECT vmid, ip_address FROM vm_cache")
            if err == nil {
                defer rows.Close()
                ipMap := make(map[int]string)
                for rows.Next() {
                    var vmid int
                    var ip string
                    if err := rows.Scan(&vmid, &ip); err == nil {
                        ipMap[vmid] = ip
                    }
                }
                
                // Apply IPs
                for i := range stats.VMs {
                    if val, ok := ipMap[stats.VMs[i].ID]; ok {
                        stats.VMs[i].IP = val
                    }
                }
            }
        }

        // Sort by ID
        sort.Slice(stats.VMs, func(i, j int) bool {
            return stats.VMs[i].ID < stats.VMs[j].ID
        })
    }

    return stats, nil
}

func getGuestIP(client *http.Client, baseURL, node, tokenID, secret, kind string, id int) (string, error) {
    // Fail fast if IP fetch is slow (5s max) to avoid blocking the dashboard too much, though this runs in worker now.
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    var url string
    if kind == "CT" { // LXC
        url = fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/interfaces", baseURL, node, id)
    } else if kind == "VM" { // QEMU
        url = fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", baseURL, node, id)
    } else {
        return "", nil
    }

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
    
    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return "", nil
    }

    if kind == "CT" {
        var lxcResp PveLxcInterfacesResponse
        if err := json.NewDecoder(resp.Body).Decode(&lxcResp); err != nil {
            return "", err
        }
        for _, iface := range lxcResp.Data {
            if iface.Name != "lo" && iface.Inet != "" && iface.Inet != "127.0.0.1" {
                parts := strings.Split(iface.Inet, "/")
                if len(parts) > 0 {
                    return parts[0], nil
                }
            }
        }
    } else if kind == "VM" {
        var qemuResp PveQemuInterfacesResponse
        if err := json.NewDecoder(resp.Body).Decode(&qemuResp); err != nil {
            return "", err
        }
        for _, iface := range qemuResp.Data.Result {
            if iface.Name != "lo" {
                for _, ip := range iface.IPAddresses {
                    if ip.IPAddressType == "ipv4" && ip.IPAddress != "127.0.0.1" {
                        return ip.IPAddress, nil
                    }
                }
            }
        }
    }
    return "", nil
}

func getProxmoxGuestDetail(rawURL, configuredNode, tokenID, secret, pveType, vmid string) (GuestDetail, error) {
    // Normalise l'URL
    baseURL := strings.TrimRight(rawURL, "/")
    if u, err := url.Parse(baseURL); err == nil {
        baseURL = u.Scheme + "://" + u.Host
    }

    var detail GuestDetail
    client := &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: newTLSConfig(),
        },
    }

    headers := func(req *http.Request) {
        req.Header.Add("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, secret))
    }

    targetNode := configuredNode

    // 0. Auto-discover Node
    reqNodes, _ := http.NewRequest("GET", fmt.Sprintf("%s/api2/json/nodes", baseURL), nil)
    headers(reqNodes)
    respNodes, err := client.Do(reqNodes)
    if err == nil {
        defer respNodes.Body.Close()
        if respNodes.StatusCode == 200 {
            var nodeList PveNodesList
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

    // 1. Status/Current
    urlStatus := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/status/current", baseURL, targetNode, pveType, vmid)
    req, _ := http.NewRequest("GET", urlStatus, nil)
    headers(req)
    resp, err := client.Do(req)
    if err != nil {
        return detail, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return detail, fmt.Errorf("API Status Error: %s", resp.Status)
    }

    var statusResp PveGuestStatusResponse
    if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
        return detail, err
    }

    d := statusResp.Data
    detail.ID, _ = strconv.Atoi(vmid)
    detail.Name = d.Name
    detail.Status = d.Status
    detail.Uptime = fmt.Sprintf("%dh", int(d.Uptime)/3600)
    detail.CPU = float64(int(d.CPU * 10000)) / 100
    detail.Cores = d.CPUs

    // RAM
    detail.RAMUsed = fmt.Sprintf("%.2f GB", float64(d.Mem)/1024/1024/1024)
    detail.RAMTotal = fmt.Sprintf("%.2f GB", float64(d.MaxMem)/1024/1024/1024)
    if d.MaxMem > 0 {
        detail.RAMPercent = int((float64(d.Mem) / float64(d.MaxMem)) * 100)
    }

    // Disk
    detail.DiskUsed = fmt.Sprintf("%.2f GB", float64(d.Disk)/1024/1024/1024)
    detail.DiskTotal = fmt.Sprintf("%.2f GB", float64(d.MaxDisk)/1024/1024/1024)
    if d.MaxDisk > 0 {
        detail.DiskPercent = int((float64(d.Disk) / float64(d.MaxDisk)) * 100)
    }
    detail.Type = pveType

    // 2. Config
    urlConfig := fmt.Sprintf("%s/api2/json/nodes/%s/%s/%s/config", baseURL, targetNode, pveType, vmid)
    reqConfig, _ := http.NewRequest("GET", urlConfig, nil)
    headers(reqConfig)
    respConfig, err := client.Do(reqConfig)
    if err == nil && respConfig.StatusCode == 200 {
        defer respConfig.Body.Close()
        var configResp PveGuestConfigResponse
        if err := json.NewDecoder(respConfig.Body).Decode(&configResp); err == nil {
            if configResp.Data.Description != "" {
                detail.Note = configResp.Data.Description
            }
            if detail.Name == "" {
                if configResp.Data.Name != "" {
                    detail.Name = configResp.Data.Name
                } else {
                    detail.Name = configResp.Data.Hostname
                }
            }
            if detail.Cores == 0 && configResp.Data.Cores > 0 {
                detail.Cores = configResp.Data.Cores
            }
        }
    }

    return detail, nil
}

// AUTH MIDDLEWARE
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. GLOBAL CHECK: Check if system is initialized (users exist)
        // If NO users exist, force redirect to /setup (unless we are already on /setup or /static)
        if r.URL.Path != "/setup" && !strings.HasPrefix(r.URL.Path, "/static") {
            count, err := CountUsers()
            // Redirect to setup if no users exist OR if DB isn't ready yet (table not created)
            if (err == nil && count == 0) || (err != nil && strings.Contains(err.Error(), "doesn't exist")) {
                http.Redirect(w, r, "/setup", http.StatusSeeOther)
                return
            }
        }

        // 2. Normal Auth Logic
        session, err := store.Get(r, "goacloud-session")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        // Check if user is authenticated
        if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        next(w, r)
    }
}

func CountUsers() (int, error) {
    var count int
    err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
    if err != nil {
        return 0, err
    }
    return count, nil
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
    // Safety Check: If users exist, Setup is disabled
    count, err := CountUsers()
    if err != nil && !strings.Contains(err.Error(), "doesn't exist") {
        http.Error(w, "Database Error", http.StatusInternalServerError)
        return
    }
    if count > 0 {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    if r.Method == http.MethodGet {
        tmpl.ExecuteTemplate(w, "setup.html", nil)
        return
    }

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        confirm := r.FormValue("confirm_password")

        if username == "" || password == "" {
             tmpl.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Tous les champs sont requis"})
             return
        }

        if len(password) < 8 {
             tmpl.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Le mot de passe doit contenir au moins 8 caractères"})
             return
        }

        if password != confirm {
             tmpl.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Les mots de passe ne correspondent pas"})
             return
        }

        // Create Admin User
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
             http.Error(w, "Error hashing password", http.StatusInternalServerError)
             return
        }

        // Force Role = Admin
        _, err = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", username, string(hashedPassword), "Admin")
        if err != nil {
             log.Printf("Error creating admin user: %v", err)
             tmpl.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Erreur base de données: " + err.Error()})
             return
        }

        log.Printf("First run setup completed. Admin user '%s' created.", username)
        
        // Redirect to login to verify
        http.Redirect(w, r, "/login?setup=success", http.StatusSeeOther)
    }
}

// (Removed Duplicate handleLogin)

// Helpers

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

func renderError(w http.ResponseWriter, templateName string, errorMsg string) {
    data := struct {
        Error string
    }{
        Error: errorMsg,
    }
    tmpl.ExecuteTemplate(w, templateName, data)
}

// WAZUH HANDLER
func handleWazuh(w http.ResponseWriter, r *http.Request) {
    if wazuhClient == nil {
        http.Error(w, "Wazuh not configured", http.StatusInternalServerError)
        return
    }

    // Use Cache
    wazuhCache.Mutex.RLock()
    agents := wazuhCache.Agents
    wazuhCache.Mutex.RUnlock()
    
    // Fallback if cache is empty (first load or error)
    if len(agents) == 0 {
         var err error
         agents, err = wazuhClient.GetAgents()
          if err != nil {
            http.Error(w, "Error fetching agents: "+err.Error(), http.StatusInternalServerError)
            return
        }
    }

	// Enrich with Proxmox Stats (Existing loop content needs to be preserved or I should target the specific lines)
    // The previous view_file showed lines 950-952 inside the loop.
    wazuhSess, _ := store.Get(r, "goacloud-session")
    currentUser, _ := wazuhSess.Values["username"].(string)
    data := struct {
        User   string
        Agents []WazuhAgent
    }{
        User:   currentUser,
        Agents: agents,
    }

    err := tmpl.ExecuteTemplate(w, "wazuh.html", data)
    if err != nil {
        http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
        return
    }
}

// API Handler for Vulnerability Details
func handleWazuhVulns(w http.ResponseWriter, r *http.Request) {
	// Extract Agent ID from URL (simple parsing since we don't have Chi/Gorilla)
	// URL: /api/wazuh/vulns/{agent_id}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
    agentID := parts[4]

    // 1. Fully Cache-Based
    // The worker now prefetches everything. If it's not in cache, it means worker hasn't run yet or failed.
    // We can just return empty or what's present.
    
    if val, ok := vulnCache.Load(agentID); ok {
        cached := val.(CachedVulns)
        // We can respect expiry or ignore it since worker manages it.
        // Let's respect it just in case worker dies.
        if time.Now().Before(cached.Expiry) {
             w.Header().Set("Content-Type", "application/json")
             json.NewEncoder(w).Encode(cached.Data)
             return
        }
    }

    // Fallback: If not formatted, return empty list instead of loading sluggishly.
    // Or we could do a synchronous fetch here as last resort? 
    // User requested NO LATENCY, so let's maybe do a quick async fetch and return empty for now?
    // Actually, let's keep the synchronous fallback just for the very first cold start, 
    // but typically the worker will have populated it.
    
    // Just return empty if not found implies "Loading..." usually in UI, but here we want data.
    // Let's rely on worker. If missing, return empty.
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode([]WazuhVuln{})
}

func handleSoar(w http.ResponseWriter, r *http.Request) {
    // Auth handled by middleware
    soarSess, _ := store.Get(r, "goacloud-session")
    currentUser, _ := soarSess.Values["username"].(string)

    data := struct {
        User string
    }{
        User: currentUser,
    }

    err := tmpl.ExecuteTemplate(w, "soar.html", data)
    if err != nil {
        log.Printf("Template error (soar.html): %v", err)
        http.Error(w, "Template error", http.StatusInternalServerError)
    }
}

func handleDiscordTest(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Use enriched alert for testing with dummy context
    ctx := AIAlertContext{
        Title: "Test Notification",
        Description: "Ceci est un test depuis GoaCloud SOAR avec analyse AI.",
        AgentName: "Test-Server",
        AgentIP: "127.0.0.1",
        FullLog: "Jan 01 12:00:00 test-server sshd[123]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2",
        SourceIP: "192.168.1.50",
        RuleID: "5716",
        RuleLevel: 5,
    }
    sendEnrichedDiscordAlert(ctx, "info")
    
    // We can't easily return error from helper but it logs it.
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Notification sent"))
}

func handleAITest(w http.ResponseWriter, r *http.Request) {
    if aiClient == nil {
        http.Error(w, "AI Client not configured", http.StatusServiceUnavailable)
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
    defer cancel()

    analysis, err := aiClient.EnrichAlert(ctx, AIAlertContext{
        Title: "Test Connection",
        Description: "Testing connectivity to AI provider.",
        AgentName: "Debug-Node",
        FullLog: "Test log entry for debugging purposes.",
    })
    
    w.Header().Set("Content-Type", "application/json")
    if err != nil {
        // Return detailed error for debugging
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{
            "status": "error",
            "error": fmt.Sprintf("%v", err),
        })
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "status": "success",
        "analysis": analysis,
    })
}

func handleSoarConfig(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        w.Header().Set("Content-Type", "application/json")
        soarConfigMutex.RLock()
        json.NewEncoder(w).Encode(currentSoarConfig)
        soarConfigMutex.RUnlock()
        return
    }

    if r.Method == http.MethodPost {
        var newConfig SoarConfig
        if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        log.Printf("Updating SOAR Config: %+v", newConfig)

        soarConfigMutex.Lock()
        currentSoarConfig = newConfig
        soarConfigMutex.Unlock()
        
        log.Printf("Updated Config in Memory: %+v", currentSoarConfig)
        
        if err := saveSoarConfig(); err != nil {
             log.Printf("Failed to persist SOAR config: %v", err)
             // We don't fail the request because checking/unchecking should still work in memory
        }

        w.WriteHeader(http.StatusOK)
    }
}

// SSH Handlers

func handleSSHManager(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        action := r.FormValue("action")
        
        if action == "generate" {
            // Generate Key
            name := r.FormValue("name")
            if name == "" {
                http.Error(w, "Name required", http.StatusBadRequest)
                return
            }
            
            key, err := GenerateRSAKey(name)
            if err != nil {
                http.Error(w, "KeyGen Error: "+err.Error(), http.StatusInternalServerError)
                return
            }
            
            if err := SaveSSHKey(key); err != nil {
                 http.Error(w, "DB Save Error: "+err.Error(), http.StatusInternalServerError)
                 return
            }
        } else if action == "update_usage" {
            // Update Usage (Manual Association)
            idStr := r.FormValue("id")
            vms := r.FormValue("vms")
            
            id, _ := strconv.Atoi(idStr)
            if id > 0 {
                if err := UpdateSSHKeyUsage(id, vms); err != nil {
                    http.Error(w, "Update Error: "+err.Error(), http.StatusInternalServerError)
                    return
                }
            }
        }
        
        http.Redirect(w, r, "/ssh", http.StatusSeeOther)
        return
    }

    // Render Page
    keys, err := GetSSHKeys()
    if err != nil {
        log.Printf("Error fetching SSH keys: %v", err)
    }
    
    // Fetch VMs for Dropdown 
    // We reuse getProxmoxStats logic basically, but we need just the list.
    // Let's call a simplified version or just use the cache if available?
    // For simplicity, let's just make a quick stats call or helper.
    // Assuming getProxmoxStats is available in main.go
    proxmoxURL := getEnv("PROXMOX_URL", "")
    proxmoxTokenID := getEnv("PROXMOX_TOKEN_ID", "")
    proxmoxTokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    proxmoxNode := getEnv("PROXMOX_NODE", "pve")
    
    stats, err := getProxmoxStats(proxmoxURL, proxmoxNode, proxmoxTokenID, proxmoxTokenSecret, true, false) // true=guests, false=no real ip check
    if err != nil {
        log.Printf("ERROR SSH Manager: Failed to fetch VMs: %v", err)
    }
    vms := []VM{}
    if err == nil {
        vms = stats.VMs
    }

    data := struct {
        Keys []SSHKey
        VMs  []VM
    }{
        Keys: keys,
        VMs:  vms,
    }

    tmpl.ExecuteTemplate(w, "ssh_keys.html", data)
}

func handleSSHDeploy(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var req struct {
        VMID      int    `json:"vmid"`
        Type      string `json:"type"`
        PublicKey string `json:"public_key"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    if req.VMID == 0 || req.PublicKey == "" {
        http.Error(w, "Invalid parameters", http.StatusBadRequest)
        return
    }
    
    if err := DeployKeyToProxmox(req.VMID, req.Type, req.PublicKey); err != nil {
         log.Printf("SSH Deploy Error: %v", err)
         http.Error(w, "Deployment Failed: "+err.Error(), http.StatusInternalServerError)
         return
    }
    
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}



func handleConsolePage(w http.ResponseWriter, r *http.Request) {
    keys, err := GetSSHKeys()
    if err != nil {
        log.Printf("Error fetching keys: %v", err)
        http.Error(w, "Error fetching keys", http.StatusInternalServerError)
        return
    }

    proxmoxURL := getEnv("PROXMOX_URL", "")
    tokenID := getEnv("PROXMOX_TOKEN_ID", "")
    tokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    configuredNode := getEnv("PROXMOX_NODE", "pve")

    stats, err := getProxmoxStats(proxmoxURL, configuredNode, tokenID, tokenSecret, true, false)
    vms := []VM{}
    if err == nil {
        vms = stats.VMs
    }

    data := struct {
        Keys []SSHKey
        VMs  []VM
    }{
        Keys: keys,
        VMs:  vms,
    }

    tmpl.ExecuteTemplate(w, "console.html", data)
}

func handleSSHDelete(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    idStr := r.URL.Query().Get("id")
    if idStr == "" {
        http.Error(w, "ID required", http.StatusBadRequest)
        return
    }

    id, err := strconv.Atoi(idStr)
    if err != nil {
        http.Error(w, "Invalid ID", http.StatusBadRequest)
        return
    }

    if err := DeleteSSHKey(id); err != nil {
        http.Error(w, "Delete Error: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

// ANSIBLE HANDLERS

func handleAnsible(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.NotFound(w, r)
        return
    }

    // 1. Get Playbooks
	playbooks, err := ListPlaybooks("./playbooks")
	if err != nil {
		log.Printf("Error listing playbooks: %v", err)
		playbooks = map[string][]string{}
	}

	// 2. Get VMs (from DB Cache for speed)
	rows, err := db.Query("SELECT vmid, name, vm_type FROM vm_cache ORDER BY vmid ASC")
	var vms []VM
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var v VM
			rows.Scan(&v.ID, &v.Name, &v.Type)
			vms = append(vms, v)
		}
	} else {
		log.Printf("Error fetching VMCache for Ansible: %v", err)
	}

	// 3. Get SSH Keys
	keys, err := GetSSHKeys()
	if err != nil {
		log.Printf("Error fetching keys: %v", err)
	}

	data := struct {
		Playbooks map[string][]string
		VMs       []VM
		Keys      []SSHKey
	}{
		Playbooks: playbooks,
		VMs:       vms,
		Keys:      keys,
	}

    err = tmpl.ExecuteTemplate(w, "ansible.html", data)
    if err != nil {
        log.Printf("Template execution error: %v", err)
        http.Error(w, "Erreur de rendu", http.StatusInternalServerError)
    }
}

func handleAnsibleRun(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
         http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
         return
    }

    // Parse JSON
    var req struct {
        Playbook string `json:"playbook"`
        VMID     int    `json:"vmid"`
        KeyID    int    `json:"key_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    // 1. Get VM IP from DB Cache
    var targetIP string
    err := db.QueryRow("SELECT ip_address FROM vm_cache WHERE vmid = ?", req.VMID).Scan(&targetIP)
    if err != nil {
        http.Error(w, fmt.Sprintf("VM IP not found (make sure it's running and cached). DB Error: %v", err), http.StatusBadRequest)
        return
    }
    if targetIP == "" || targetIP == "-" {
        http.Error(w, "VM has no IP address cached.", http.StatusBadRequest)
        return
    }

    // 2. Get Private Key
    sshKey, err := GetSSHKeyByID(req.KeyID)
    if err != nil {
        http.Error(w, fmt.Sprintf("SSH Key not found: %v", err), http.StatusBadRequest)
        return
    }

    // 3. Prepare Playbook Path (avec protection path traversal)
    playbookPath := filepath.Join("playbooks", filepath.Clean(req.Playbook))
    absPlaybooks, _ := filepath.Abs("playbooks")
    absPath, _ := filepath.Abs(playbookPath)
    if !strings.HasPrefix(absPath, absPlaybooks+string(filepath.Separator)) {
        http.Error(w, "Invalid playbook path", http.StatusBadRequest)
        return
    }

    // 4. Run & Stream
    // Set headers for streaming
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.Header().Set("Transfer-Encoding", "chunked")
    w.Header().Set("X-Content-Type-Options", "nosniff")

    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming not supported", http.StatusInternalServerError)
        return
    }

    cmdOut, cleanup, err := RunPlaybook(playbookPath, targetIP, sshKey.PrivateKey)
    if err != nil {
        fmt.Fprintf(w, "Configuration Error: %v\n", err)
        return
    }
    defer cleanup() // IMPORTANT: Delete the temp key file when done
    
    // Stream output
    buf := make([]byte, 1024)
    for {
        n, err := cmdOut.Read(buf)
        if n > 0 {
            w.Write(buf[:n])
            flusher.Flush()
        }
        if err != nil {
            break
        }
    }
}

func handleAnsibleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Limit upload size (e.g., 10MB)
    r.ParseMultipartForm(10 << 20)

    var file io.Reader
    var filename string

    // Check if text content is provided
    textContent := r.FormValue("playbook_content")
    textFilename := r.FormValue("playbook_filename")

    if textContent != "" && textFilename != "" {
        // Mode: Direct Text Input
        filename = filepath.Base(textFilename)
        file = strings.NewReader(textContent)
    } else {
        // Mode: File Upload
        f, handler, err := r.FormFile("playbook")
        if err != nil {
            http.Error(w, "Error retrieving file", http.StatusBadRequest)
            return
        }
        defer f.Close()
        filename = filepath.Base(handler.Filename)
        file = f
    }

    // Validate extension
    ext := strings.ToLower(filepath.Ext(filename))
    if ext != ".yml" && ext != ".yaml" {
        http.Error(w, "Only .yml or .yaml files are allowed", http.StatusBadRequest)
        return
    }

    // Save Path (avec protection path traversal)
    savePath := filepath.Join("playbooks", filepath.Base(filename))
    absPlaybooks, _ := filepath.Abs("playbooks")
    absSavePath, _ := filepath.Abs(savePath)
    if !strings.HasPrefix(absSavePath, absPlaybooks+string(filepath.Separator)) {
        http.Error(w, "Invalid filename", http.StatusBadRequest)
        return
    }

    // Create file
    dst, err := os.Create(savePath)
    if err != nil {
        log.Printf("Error creating file: %v", err)
        http.Error(w, "Error saving file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()

    if _, err := io.Copy(dst, file); err != nil {
        log.Printf("Error copying file: %v", err)
        http.Error(w, "Error saving file content", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Playbook uploaded successfully")
}

func generateSelfSignedCert() error {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return err
    }

    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"GoaCloud Self-Signed"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(365 * 24 * time.Hour),

        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return err
    }

    certOut, err := os.Create("server.crt")
    if err != nil {
        return err
    }
    defer certOut.Close()
    if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
        return err
    }

    keyOut, err := os.Create("server.key")
    if err != nil {
        return err
    }
    defer keyOut.Close()

    x509Encoded, err := x509.MarshalECPrivateKey(priv)
    if err != nil {
        return err
    }
    if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded}); err != nil {
        return err
    }

    log.Println("Generated self-signed certificate: server.crt and server.key")
    return nil
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    userID := r.FormValue("user_id")
    role := r.FormValue("role")

    if userID == "" || role == "" {
        http.Error(w, "User ID and Role are required", http.StatusBadRequest)
        return
    }

    _, err := db.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID)
    if err != nil {
        log.Printf("Error updating user role: %v", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    // Audit Log
    if sess, err := store.Get(r, "goacloud-session"); err == nil {
        if u, ok := sess.Values["username"].(string); ok && u != "" {
            go logAudit(0, u, "UpdateUserRole", fmt.Sprintf("Updated user ID %s to role %s", userID, role), r.RemoteAddr)
        }
    }

    http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "goacloud-session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    
    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
         http.Redirect(w, r, "/login", http.StatusSeeOther)
         return
    }

    var user User
    var mfaSecret sql.NullString
    err = db.QueryRow("SELECT id, username, email, role, created_at, mfa_enabled, mfa_secret FROM users WHERE username = ?", username).Scan(
        &user.ID, &user.Username, &user.Email, &user.Role, &user.CreatedAt, &user.MFAEnabled, &mfaSecret,
    )
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    user.MFASecret = mfaSecret.String

    tmpl.ExecuteTemplate(w, "profile.html", user)
}

func handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    session, err := store.Get(r, "goacloud-session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    oldPassword := r.FormValue("old_password")
    newPassword := r.FormValue("new_password")
    confirmPassword := r.FormValue("confirm_password")

    if oldPassword == "" || newPassword == "" {
        http.Error(w, "All fields are required", http.StatusBadRequest)
        return
    }

    if len(newPassword) < 8 {
        http.Redirect(w, r, "/profile?error=Le mot de passe doit contenir au moins 8 caractères", http.StatusSeeOther)
        return
    }

    if newPassword != confirmPassword {
        http.Error(w, "New passwords do not match", http.StatusBadRequest)
        return
    }

    // Verify old password
    var storedHash string
    err = db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        http.Error(w, "User not found", http.StatusInternalServerError)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(oldPassword))
    if err != nil {
        http.Redirect(w, r, "/profile?error=Incorrect old password", http.StatusSeeOther)
        return
    }

    // Hash new password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error processing password", http.StatusInternalServerError)
        return
    }

    _, err = db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(hashedPassword), username)
    if err != nil {
        log.Printf("Error updating password: %v", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/profile?success=true", http.StatusSeeOther)
}

// MFA Handlers

func handleSetupMFA(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "goacloud-session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    // Generate Key
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "GoaCloud",
        AccountName: username,
    })
    if err != nil {
        log.Printf("MFA Generate Error: %v", err)
        http.Error(w, "Error generating key", http.StatusInternalServerError)
        return
    }

    // Convert TOTP key to QR code image
    var buf bytes.Buffer
    img, err := key.Image(200, 200)
    if err != nil {
        log.Printf("MFA Image Error: %v", err)
        http.Error(w, "Error generating QR code", http.StatusInternalServerError)
        return
    }
    png.Encode(&buf, img)

    // Return JSON with Secret and QR Code (Base64)
    response := map[string]string{
        "secret": key.Secret(),
        "qr_code": base64.StdEncoding.EncodeToString(buf.Bytes()),
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func handleVerifyMFA(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    session, err := store.Get(r, "goacloud-session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    var req struct {
        Code   string `json:"code"`
        Secret string `json:"secret"` // Passed from client during setup
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if req.Code == "" || req.Secret == "" {
        http.Error(w, "Code and Secret are required", http.StatusBadRequest)
        return
    }

    valid := totp.Validate(req.Code, req.Secret)
    if !valid {
        http.Error(w, "Invalid code", http.StatusUnauthorized)
        return
    }

    // Save to DB
    _, err = db.Exec("UPDATE users SET mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", req.Secret, username)
    if err != nil {
        log.Printf("MFA DB Update Error: %v", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleDisableMFA(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
         http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
         return
    }

    session, err := store.Get(r, "goacloud-session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    _, err = db.Exec("UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE username = ?", username)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "disabled"})
}

// Audit Log Helper
func logAudit(userID int, username, action, details, ip string) {
    if userID == 0 && username != "" {
        db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
    }

    _, err := db.Exec("INSERT INTO audit_logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        userID, username, action, details, ip)
    if err != nil {
        log.Printf("Audit Log Error: %v", err)
    }
}

// Audit Logs View (Admin)
func handleAuditLogs(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // RBAC Check
    session, err := store.Get(r, "goacloud-session")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    username, ok := session.Values["username"].(string)
    if !ok || username == "" {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    
    var role string
    db.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
    if role != "Admin" {
         renderError(w, "dashboard.html", "Accès refusé. Réservé aux administrateurs.")
         return
    }

    rows, err := db.Query("SELECT id, username, action, details, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100")
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var logs []AuditLog
    for rows.Next() {
        var l AuditLog
        rows.Scan(&l.ID, &l.Username, &l.Action, &l.Details, &l.IPAddress, &l.CreatedAt)
        logs = append(logs, l)
    }

    data := map[string]interface{}{
        "Username": username,
        "Role": role,
        "Logs": logs,
    }
    tmpl.ExecuteTemplate(w, "audit_logs.html", data)
}
