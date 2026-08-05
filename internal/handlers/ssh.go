package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"goacore/internal/middleware"
	"goacore/internal/models"
	"goacore/internal/services"
	gossh "golang.org/x/crypto/ssh"
)

// publicKeyFingerprint returns the SHA256 fingerprint of an authorized_keys line,
// so the audit trail can name WHICH key was deployed without ever copying key
// material into the log.
func publicKeyFingerprint(authorizedKey string) string {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "empreinte indisponible"
	}
	return gossh.FingerprintSHA256(pub)
}

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
			// A new credential for the whole fleet: trace it by name and fingerprint.
			go services.LogAudit(h.DB, 0, middleware.GetSessionUser(r, h.SessionStore), "SSHKeyGenerate",
				fmt.Sprintf("Clé %s « %s » générée (%s)", key.KeyType, key.Name, key.Fingerprint), middleware.RealIP(r))
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

	pc := h.ConfigStore.ProxmoxSnapshot()
	var vms []models.VM
	if pc.URL != "" && pc.TokenID != "" {
		stats, err := h.Proxmox.GetStats(pc.URL, pc.Node, pc.TokenID, pc.TokenSecret, true, false)
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

	if err := h.Templates.ExecuteTemplate(w, "ssh_keys.html", data); err != nil {
		slog.Error("Template error (ssh_keys.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
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

	// Deploying a key grants a durable foothold on the guest: the trail must name
	// the target and the key (by fingerprint — the material itself never lands in
	// the log), on success as well as on failure.
	actor := middleware.GetSessionUser(r, h.SessionStore)
	ip := middleware.RealIP(r)
	target := fmt.Sprintf("%s #%d", req.Type, req.VMID)
	fingerprint := publicKeyFingerprint(req.PublicKey)

	if err := h.SSHService.DeployKeyToProxmox(req.VMID, req.Type, req.PublicKey); err != nil {
		slog.Error("SSH Deploy Error", "error", err)
		go services.LogAudit(h.DB, 0, actor, "SSHKeyDeployFailed",
			fmt.Sprintf("Échec du déploiement de la clé %s sur %s", fingerprint, target), ip)
		http.Error(w, "Deployment Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	go services.LogAudit(h.DB, 0, actor, "SSHKeyDeploy",
		fmt.Sprintf("Clé publique %s déployée sur %s", fingerprint, target), ip)

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

	// Read the key before it is gone: an id alone tells a later reader nothing
	// about which credential was revoked.
	label := fmt.Sprintf("#%d", id)
	if key, err := h.SSHService.GetSSHKeyByID(id); err == nil {
		label = fmt.Sprintf("« %s » (#%d, %s)", key.Name, key.ID, key.Fingerprint)
	}

	if err := h.SSHService.DeleteSSHKey(id); err != nil {
		http.Error(w, "Delete Error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	go services.LogAudit(h.DB, 0, middleware.GetSessionUser(r, h.SessionStore), "SSHKeyDelete",
		fmt.Sprintf("Clé SSH %s supprimée", label), middleware.RealIP(r))

	w.WriteHeader(http.StatusOK)
}
