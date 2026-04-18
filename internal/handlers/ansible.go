package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
)

// HandleAnsible renders the Ansible playbook manager page.
func (h *Handler) HandleAnsible(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	playbooks, err := services.ListPlaybooks("./playbooks")
	if err != nil {
		slog.Error("Error listing playbooks", "error", err)
		playbooks = map[string][]string{}
	}

	rows, err := h.DB.Query("SELECT vmid, name, vm_type FROM vm_cache ORDER BY vmid ASC")
	var vms []models.VM
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var v models.VM
			if err := rows.Scan(&v.ID, &v.Name, &v.Type); err != nil {
				slog.Error("Error scanning VM", "error", err)
				continue
			}
			vms = append(vms, v)
		}
		if err := rows.Err(); err != nil {
			slog.Error("Error iterating VMs", "error", err)
		}
	} else {
		slog.Error("Error fetching VMCache for Ansible", "error", err)
	}

	keys, err := h.SSHService.GetSSHKeys()
	if err != nil {
		slog.Error("Error fetching keys", "error", err)
	}

	// Count active schedules for KPI
	var activeSchedules int
	_ = h.DB.QueryRow("SELECT COUNT(*) FROM ansible_schedules WHERE enabled = TRUE").Scan(&activeSchedules)

	// Count total playbooks
	totalPlaybooks := 0
	for _, files := range playbooks {
		totalPlaybooks += len(files)
	}

	data := struct {
		Playbooks       map[string][]string
		VMs             []models.VM
		Keys            []models.SSHKey
		ActiveSchedules int
		TotalPlaybooks  int
	}{
		Playbooks:       playbooks,
		VMs:             vms,
		Keys:            keys,
		ActiveSchedules: activeSchedules,
		TotalPlaybooks:  totalPlaybooks,
	}

	if err = h.Templates.ExecuteTemplate(w, "ansible.html", data); err != nil {
		slog.Error("Template execution error", "error", err)
		http.Error(w, "Erreur de rendu", http.StatusInternalServerError)
	}
}

// HandleAnsibleRun executes an Ansible playbook and streams the output.
func (h *Handler) HandleAnsibleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	var req struct {
		Playbook string `json:"playbook"`
		VMID     int    `json:"vmid"`
		KeyID    int    `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var targetIP string
	err := h.DB.QueryRow("SELECT ip_address FROM vm_cache WHERE vmid = ?", req.VMID).Scan(&targetIP)
	if err != nil {
		http.Error(w, "VM IP not found (make sure it's running and cached)", http.StatusBadRequest)
		return
	}
	if targetIP == "" || targetIP == "-" {
		http.Error(w, "VM has no IP address cached.", http.StatusBadRequest)
		return
	}

	sshKey, err := h.SSHService.GetSSHKeyByID(req.KeyID)
	if err != nil {
		http.Error(w, "SSH Key not found", http.StatusBadRequest)
		return
	}

	// Path traversal protection
	playbookPath := filepath.Join("playbooks", filepath.Clean(req.Playbook))
	absPlaybooks, err1 := filepath.Abs("playbooks")
	absPath, err2 := filepath.Abs(playbookPath)
	if err1 != nil || err2 != nil || !strings.HasPrefix(absPath, absPlaybooks+string(filepath.Separator)) {
		http.Error(w, "Invalid playbook path", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	cmdOut, cleanup, err := services.RunPlaybook(playbookPath, targetIP, sshKey.PrivateKey)
	if err != nil {
		fmt.Fprintf(w, "Configuration Error: %v\n", err)
		return
	}
	defer cleanup()

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

// HandleAnsibleUpload saves an uploaded playbook YAML file to the playbooks directory.
func (h *Handler) HandleAnsibleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	r.ParseMultipartForm(10 << 20)

	var file io.Reader
	var filename string

	textContent := r.FormValue("playbook_content")
	textFilename := r.FormValue("playbook_filename")

	if textContent != "" && textFilename != "" {
		filename = filepath.Base(textFilename)
		file = strings.NewReader(textContent)
	} else {
		f, handler, err := r.FormFile("playbook")
		if err != nil {
			http.Error(w, "Error retrieving file", http.StatusBadRequest)
			return
		}
		defer f.Close()
		filename = filepath.Base(handler.Filename)
		file = f
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".yml" && ext != ".yaml" {
		http.Error(w, "Only .yml or .yaml files are allowed", http.StatusBadRequest)
		return
	}

	// Path traversal protection
	savePath := filepath.Join("playbooks", filepath.Base(filename))
	absPlaybooks, err1 := filepath.Abs("playbooks")
	absSavePath, err2 := filepath.Abs(savePath)
	if err1 != nil || err2 != nil || !strings.HasPrefix(absSavePath, absPlaybooks+string(filepath.Separator)) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	dst, err := os.Create(savePath)
	if err != nil {
		slog.Error("Error creating file", "error", err)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		slog.Error("Error copying file", "error", err)
		http.Error(w, "Error saving file content", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Playbook uploaded successfully")
}

// resolveSafePlaybookPath validates that name is a path under ./playbooks/
// with a .yml or .yaml extension, and returns the absolute path to open.
func resolveSafePlaybookPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("missing playbook name")
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".yml" && ext != ".yaml" {
		return "", fmt.Errorf("only .yml or .yaml files are allowed")
	}
	cleaned := filepath.Clean(name)
	if strings.HasPrefix(cleaned, "..") || strings.HasPrefix(cleaned, string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path")
	}
	full := filepath.Join("playbooks", cleaned)
	absRoot, err := filepath.Abs("playbooks")
	if err != nil {
		return "", err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absFull, absRoot+string(filepath.Separator)) && absFull != absRoot {
		return "", fmt.Errorf("path escapes playbooks directory")
	}
	return full, nil
}

// HandleAnsiblePlaybookGet returns the raw text content of a playbook.
// GET /api/ansible/playbook?name=Category/file.yml
func (h *Handler) HandleAnsiblePlaybookGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	full, err := resolveSafePlaybookPath(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Playbook not found", http.StatusNotFound)
			return
		}
		slog.Error("Error reading playbook", "error", err, "path", full)
		http.Error(w, "Error reading playbook", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// HandleAnsiblePlaybookUpdate overwrites an existing playbook's content.
// PUT /api/ansible/playbook   body: {"name":"Category/file.yml","content":"..."}
func (h *Handler) HandleAnsiblePlaybookUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	full, err := resolveSafePlaybookPath(req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Only update existing playbooks; use /upload to create.
	if _, err := os.Stat(full); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Playbook not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error accessing playbook", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(full, []byte(req.Content), 0644); err != nil {
		slog.Error("Error writing playbook", "error", err, "path", full)
		http.Error(w, "Error writing playbook", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
