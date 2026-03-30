package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	gossh "golang.org/x/crypto/ssh"
	"goacloud/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return u.Host == r.Host
	},
}

// HandleConsolePage renders the web SSH console page.
func (h *Handler) HandleConsolePage(w http.ResponseWriter, r *http.Request) {
	keys, err := h.SSHService.GetSSHKeys()
	if err != nil {
		slog.Error("Error fetching keys", "error", err)
		http.Error(w, "Error fetching keys", http.StatusInternalServerError)
		return
	}

	cfg := h.Config
	var vms []models.VM
	stats, err := h.Proxmox.GetStats(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, true, false)
	if err == nil {
		vms = stats.VMs
	}

	data := struct {
		Keys []models.SSHKey
		VMs  []models.VM
	}{
		Keys: keys,
		VMs:  vms,
	}

	h.Templates.ExecuteTemplate(w, "console.html", data)
}

// HandleSSHWebSocket upgrades the HTTP connection to a WebSocket and starts an SSH session.
func (h *Handler) HandleSSHWebSocket(w http.ResponseWriter, r *http.Request) {
	vmIDStr := r.URL.Query().Get("vmid")
	keyIDStr := r.URL.Query().Get("key_id")
	username := r.URL.Query().Get("user")
	if username == "" {
		username = "root"
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket Upgrade Failed", "error", err)
		return
	}
	defer ws.Close()

	// Resolve VM IP
	var ip string
	cfg := h.Config
	stats, err := h.Proxmox.GetStats(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, true, false)
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

	keyID, _ := strconv.Atoi(keyIDStr)
	key, err := h.SSHService.GetSSHKeyByID(keyID)
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: Key not found"))
		return
	}

	signer, err := gossh.ParsePrivateKey([]byte(key.PrivateKey))
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: Invalid Private Key"))
		return
	}

	config := &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: h.SSHService.SSHHostKeyCallback(ip),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", ip)
	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: SSH Connection Failed: %v", err)))
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: New Session Failed"))
		client.Close()
		return
	}
	defer session.Close()

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 40, 80, modes); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: PTY Request Failed"))
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: Stdin Pipe Failed"))
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: Stdout Pipe Failed"))
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: Stderr Pipe Failed"))
		return
	}

	go func() { io.Copy(wsWriter{ws}, stdout) }()
	go func() { io.Copy(wsWriter{ws}, stderr) }()

	if err := session.Shell(); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Error: Shell Start Failed"))
		return
	}

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}

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

type wsWriter struct {
	*websocket.Conn
}

func (w wsWriter) Write(p []byte) (n int, err error) {
	err = w.Conn.WriteMessage(websocket.TextMessage, p)
	return len(p), err
}
