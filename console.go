package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/gorilla/websocket"
    "golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        origin := r.Header.Get("Origin")
        if origin == "" {
            return true // connexion directe (pas navigateur)
        }
        // Accepte si même host que le serveur
        host := r.Host
        return strings.Contains(origin, host)
    },
}

// ConsoleSession holds the state of a web console connection
type ConsoleSession struct {
    Client *ssh.Client
    Conn   *websocket.Conn
}

// handleSSHWebSocket upgrades the connection and starts the SSH session
func handleSSHWebSocket(w http.ResponseWriter, r *http.Request) {
    // 1. Parse Query Params
    vmIDStr := r.URL.Query().Get("vmid")
    // vmType := r.URL.Query().Get("type")
    keyIDStr := r.URL.Query().Get("key_id")
    username := r.URL.Query().Get("user")
    if username == "" {
        username = "root"
    }

    // Upgrade to WebSocket
    ws, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("WebSocket Upgrade Failed:", err)
        return
    }
    defer ws.Close()

    // 2. Resolve IP
    var ip string
    
    // Fetch Proxmox Config from Env (Helper in main.go)
    proxmoxURL := getEnv("PROXMOX_URL", "")
    tokenID := getEnv("PROXMOX_TOKEN_ID", "")
    tokenSecret := getEnv("PROXMOX_TOKEN_SECRET", "")
    configuredNode := getEnv("PROXMOX_NODE", "pve")

    // Fetch Stats (includeGuests=true to get list & IPs from cache)
    stats, err := getProxmoxStats(proxmoxURL, configuredNode, tokenID, tokenSecret, true, false)
    if err == nil {
        for _, vm := range stats.VMs {
            if strconv.Itoa(vm.ID) == vmIDStr {
                ip = vm.IP
                break
            }
        }
    }
    
    if ip == "" || ip == "-" {
        ws.WriteMessage(websocket.TextMessage, []byte("Error: Could not resolve IP for VM ID "+vmIDStr+". Ensure QEMU Guest Agent is installed and running."))
        return
    }

    // 3. Get Private Key
    keyID, _ := strconv.Atoi(keyIDStr)
    key, err := GetSSHKeyByID(keyID)
    if err != nil {
        ws.WriteMessage(websocket.TextMessage, []byte("Error: Key not found"))
        return
    }

    // 4. SSH Config
    signer, err := ssh.ParsePrivateKey([]byte(key.PrivateKey))
    if err != nil {
        ws.WriteMessage(websocket.TextMessage, []byte("Error: Invalid Private Key"))
        return
    }

    config := &ssh.ClientConfig{
        User: username,
        Auth: []ssh.AuthMethod{
            ssh.PublicKeys(signer),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         5 * time.Second,
    }

    // 5. Connect SSH
    addr := fmt.Sprintf("%s:22", ip)
    client, err := ssh.Dial("tcp", addr, config)
    if err != nil {
        ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: SSH Connection Failed: %v", err)))
        return
    }
    defer client.Close()

    session, err := client.NewSession()
    if err != nil {
        ws.WriteMessage(websocket.TextMessage, []byte("Error: New Session Failed"))
        return
    }
    defer session.Close()

    // 6. PTY
    modes := ssh.TerminalModes{
        ssh.ECHO:          1,
        ssh.TTY_OP_ISPEED: 14400,
        ssh.TTY_OP_OSPEED: 14400,
    }
    if err := session.RequestPty("xterm-256color", 40, 80, modes); err != nil {
        ws.WriteMessage(websocket.TextMessage, []byte("Error: PTY Request Failed"))
        return
    }

    // 7. Pipe Stdin/Stdout
    stdin, _ := session.StdinPipe()
    stdout, _ := session.StdoutPipe()
    stderr, _ := session.StderrPipe()

    go func() {
        io.Copy(wsWriter{ws}, stdout)
    }()
    go func() {
        io.Copy(wsWriter{ws}, stderr)
    }()

    if err := session.Shell(); err != nil {
        ws.WriteMessage(websocket.TextMessage, []byte("Error: Shell Start Failed"))
        return
    }

    // Read loop
    for {
        _, msg, err := ws.ReadMessage()
        if err != nil {
             break
        }

        // Custom Resize Protocol
        sMsg := string(msg)
        if len(sMsg) > 7 && sMsg[:7] == "RESIZE:" {
             var rows, cols int
             fmt.Sscanf(sMsg, "RESIZE:%d:%d", &rows, &cols)
             if rows > 0 && cols > 0 {
                 session.WindowChange(rows, cols)
             }
             continue
        }

        if _, err := stdin.Write(msg); err != nil {
            break
        }
    }
}

// wsWriter adapts WebSocket to io.Writer
type wsWriter struct {
    *websocket.Conn
}

func (w wsWriter) Write(p []byte) (n int, err error) {
    err = w.Conn.WriteMessage(websocket.TextMessage, p)
    return len(p), err
}
