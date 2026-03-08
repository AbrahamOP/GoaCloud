package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
)

// HandleSSHManager handles the SSH key manager page (GET) and key generation/update (POST).
func (h *Handler) HandleSSHManager(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		action := r.FormValue("action")

		if action == "generate" {
			name := r.FormValue("name")
			if name == "" {
				http.Error(w, "Name required", http.StatusBadRequest)
				return
			}
			key, err := services.GenerateRSAKey(name)
			if err != nil {
				http.Error(w, "KeyGen Error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if err := h.SSHService.SaveSSHKey(key); err != nil {
				http.Error(w, "DB Save Error: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else if action == "update_usage" {
			idStr := r.FormValue("id")
			vms := r.FormValue("vms")
			id, _ := strconv.Atoi(idStr)
			if id > 0 {
				if err := h.SSHService.UpdateSSHKeyUsage(id, vms); err != nil {
					http.Error(w, "Update Error: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}

		http.Redirect(w, r, "/ssh", http.StatusSeeOther)
		return
	}

	keys, err := h.SSHService.GetSSHKeys()
	if err != nil {
		slog.Error("Error fetching SSH keys", "error", err)
	}

	cfg := h.Config
	var vms []models.VM
	if cfg.ProxmoxURL != "" && cfg.ProxmoxTokenID != "" {
		stats, err := h.Proxmox.GetStats(cfg.ProxmoxURL, cfg.ProxmoxNode, cfg.ProxmoxTokenID, cfg.ProxmoxTokenSecret, true, false)
		if err != nil {
			slog.Error("ERROR SSH Manager: Failed to fetch VMs", "error", err)
		} else {
			vms = stats.VMs
		}
	}

	data := struct {
		Keys []models.SSHKey
		VMs  []models.VM
	}{
		Keys: keys,
		VMs:  vms,
	}

	h.Templates.ExecuteTemplate(w, "ssh_keys.html", data)
}

// HandleSSHDeploy deploys a public key to a Proxmox VM via the API.
func (h *Handler) HandleSSHDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
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

	if err := h.SSHService.DeployKeyToProxmox(req.VMID, req.Type, req.PublicKey); err != nil {
		slog.Error("SSH Deploy Error", "error", err)
		http.Error(w, "Deployment Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleSSHDelete deletes an SSH key by ID.
func (h *Handler) HandleSSHDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
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

	if err := h.SSHService.DeleteSSHKey(id); err != nil {
		http.Error(w, "Delete Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
