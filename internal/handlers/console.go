package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/services"
	gossh "golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	// CheckOrigin gates the WS handshake against cross-site WebSocket hijacking.
	// The only legitimate caller is the in-app terminal page (console.html), which
	// connects to window.location.host — so a real browser ALWAYS sends an Origin
	// header equal to the request host. We therefore accept only a same-origin
	// Origin and reject everything else.
	//
	// An empty Origin is rejected on purpose: per the WebSocket spec a browser
	// always sends Origin on the handshake, so a missing one means a non-browser
	// client (curl/script) for which these root-SSH terminals have no legitimate
	// use. This does not break the web terminal (which is same-origin), and it
	// closes the prior hole where a forged/absent Origin was waved through.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
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

	pc := h.ConfigStore.ProxmoxSnapshot()
	var vms []models.VM
	stats, err := h.Proxmox.GetStats(pc.URL, pc.Node, pc.TokenID, pc.TokenSecret, true, false)
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

	if err := h.Templates.ExecuteTemplate(w, "console.html", data); err != nil {
		slog.Error("Template error (console.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// HandleSSHWebSocket upgrades the HTTP connection to a WebSocket and starts an SSH session.
func (h *Handler) HandleSSHWebSocket(w http.ResponseWriter, r *http.Request) {
	vmIDStr := r.URL.Query().Get("vmid")
	keyIDStr := r.URL.Query().Get("key_id")
	username := r.URL.Query().Get("user")
	if username == "" {
		username = "root"
	}

	// Who is opening the shell, from where. Read BEFORE the upgrade: once the
	// connection is hijacked the session store can no longer be used.
	actor := middleware.GetSessionUser(r, h.SessionStore)
	clientIP := middleware.RealIP(r)

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket Upgrade Failed", "error", err)
		return
	}
	defer ws.Close()

	// Resolve VM IP
	var ip string
	pc := h.ConfigStore.ProxmoxSnapshot()
	stats, err := h.Proxmox.GetStats(pc.URL, pc.Node, pc.TokenID, pc.TokenSecret, true, false)
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
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: h.SSHService.SSHHostKeyCallback(ip),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", ip)
	client, err := gossh.Dial("tcp", addr, config)
	if err != nil {
		// A failed attempt to open a shell on a guest is itself worth a trace:
		// it is what a repeated, unsuccessful lateral move looks like.
		go services.LogAudit(h.DB, 0, actor, "ConsoleFailed",
			fmt.Sprintf("Échec d'ouverture d'un shell SSH sur la machine #%s (%s@%s)", vmIDStr, username, ip), clientIP)
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

	// gorilla/websocket forbids concurrent writers, so stdout and stderr share a
	// single mutex-guarded writer. The WaitGroup lets us wait for both copies to
	// drain before returning, so neither goroutine outlives the request.
	writer := &wsWriter{conn: ws}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(writer, stdout) }()
	go func() { defer wg.Done(); io.Copy(writer, stderr) }()

	if err := session.Shell(); err != nil {
		writer.WriteText([]byte("Error: Shell Start Failed"))
		session.Close()
		wg.Wait()
		return
	}

	// Opening an interactive shell on a guest is the single most sensitive action
	// of the product, and the WebSocket route is a GET the audit middleware does
	// not cover. It is therefore traced here with the context only this handler
	// knows: which guest, as which remote user, with which key — the key by name
	// and id, never by its material.
	openedAt := time.Now()
	go services.LogAudit(h.DB, 0, actor, "ConsoleOpen",
		fmt.Sprintf("Shell SSH ouvert sur la machine #%s (%s@%s) avec la clé « %s » (#%d)", vmIDStr, username, ip, key.Name, key.ID), clientIP)
	defer func() {
		go services.LogAudit(h.DB, 0, actor, "ConsoleClose",
			fmt.Sprintf("Shell SSH fermé sur la machine #%s (%s@%s) après %s", vmIDStr, username, ip, time.Since(openedAt).Round(time.Second)), clientIP)
	}()

	// Set inactivity timeout (30 min) — reset on each message
	const idleTimeout = 30 * time.Minute
	ws.SetReadDeadline(time.Now().Add(idleTimeout))

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}
		ws.SetReadDeadline(time.Now().Add(idleTimeout))

		sMsg := string(msg)
		if len(sMsg) > 7 && sMsg[:7] == "RESIZE:" {
			var rows, cols int
			if _, err := fmt.Sscanf(sMsg, "RESIZE:%d:%d", &rows, &cols); err == nil && rows > 0 && cols > 0 {
				session.WindowChange(rows, cols)
			}
			continue
		}

		if _, err := stdin.Write(msg); err != nil {
			break
		}
	}

	// Closing the session unblocks the io.Copy goroutines (stdout/stderr hit EOF);
	// wait for them so they can't write to the connection after we return.
	session.Close()
	wg.Wait()
}

// wsWriter serializes WebSocket writes from multiple goroutines.
type wsWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *wsWriter) Write(p []byte) (int, error) {
	return w.WriteText(p)
}

func (w *wsWriter) WriteText(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.WriteMessage(websocket.TextMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
