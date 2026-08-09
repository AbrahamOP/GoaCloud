package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

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

// ─────────────────────────────────────────────────────────────────────────────
// Épinglage des clés d'hôte (amorçage TOFU)
//
// RunPlaybook refuse toute cible dont la clé d'hôte n'est pas épinglée
// (services.ErrHostNotPinned) : sans ces trois routes, une planification Ansible
// vers un hôte jamais joint par la console reste bloquée à jamais, et un hôte
// réinstallé (ErrHostKeyMismatch) est une impasse définitive.
//
// Le parcours est délibérément en DEUX temps. GoaCore ne décide pas à la place de
// l'exploitant : « scan » ne fait que MONTRER l'empreinte SHA256 présentée par
// l'hôte (aucune écriture), à comparer sur la machine avec
// `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` ; « pin » n'écrit que si
// l'empreinte confirmée correspond à celle réellement présentée. Un épinglage à
// l'aveugle rendrait le durcissement décoratif : il suffirait d'un MITM au moment
// de l'amorçage pour figer la mauvaise identité.
//
// Les trois routes sont Admin-only (groupe AdminOnly du routeur + RequireAdmin
// inline, défense en profondeur) et tracées dans le journal d'audit : épingler ou
// désépingler une identité d'hôte engage tous les accès SSH ultérieurs.
// ─────────────────────────────────────────────────────────────────────────────

// hostKeyRequest is the JSON body of the three host-key endpoints. Fingerprint is
// only read by the pin endpoint (the SHA256 form displayed by the scan endpoint).
type hostKeyRequest struct {
	IP          string `json:"ip"`
	Fingerprint string `json:"fingerprint"`
}

// hostKeyResponse is the JSON answer of the three host-key endpoints. Error carries
// an operator-facing message (French, like the underlying services errors).
type hostKeyResponse struct {
	IP          string `json:"ip,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Status      string `json:"status,omitempty"`
	Error       string `json:"error,omitempty"`
}

// decodeHostKeyRequest reads and validates the shared JSON body. It writes the 400
// response itself and returns ok=false when the body is unusable.
func decodeHostKeyRequest(w http.ResponseWriter, r *http.Request) (hostKeyRequest, bool) {
	var req hostKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, hostKeyResponse{Error: "Corps de requête invalide."})
		return req, false
	}
	req.IP = strings.TrimSpace(req.IP)
	req.Fingerprint = strings.TrimSpace(req.Fingerprint)
	if net.ParseIP(req.IP) == nil {
		// Le scan n'accepte qu'une IP littérale : le magasin ssh_host_keys est
		// indexé par IP, et un nom d'hôte laisserait l'identité épinglée dépendre
		// d'une résolution DNS que GoaCore ne contrôle pas.
		writeJSON(w, http.StatusBadRequest, hostKeyResponse{Error: "Adresse IP invalide."})
		return req, false
	}
	return req, true
}

// HandleSSHHostKeyScan reads the host key presented by ip:22 and returns its SHA256
// fingerprint WITHOUT storing anything. It is the first half of the bootstrap: the
// operator compares the returned fingerprint on the machine itself before confirming.
func (h *Handler) HandleSSHHostKeyScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	req, ok := decodeHostKeyRequest(w, r)
	if !ok {
		return
	}

	actor := middleware.GetSessionUser(r, h.SessionStore)
	clientIP := middleware.RealIP(r)

	fingerprint, err := h.SSHService.ScanHostKey(req.IP)
	if err != nil {
		slog.Error("SSH host key scan failed", "ip", req.IP, "error", err)
		go services.LogAudit(h.DB, 0, actor, "SSHHostKeyScanFailed",
			fmt.Sprintf("Lecture de la clé hôte de %s impossible", req.IP), clientIP)
		// L'hôte est injoignable ou ne présente pas de clé : c'est un échec de la
		// cible, pas de la requête.
		writeJSON(w, http.StatusBadGateway, hostKeyResponse{IP: req.IP, Error: err.Error()})
		return
	}

	// L'empreinte affichée est ce sur quoi l'exploitant va fonder sa décision :
	// la tracer permet de rejouer plus tard ce qui lui a été montré.
	go services.LogAudit(h.DB, 0, actor, "SSHHostKeyScan",
		fmt.Sprintf("Clé hôte de %s lue (empreinte présentée : %s) — aucune écriture", req.IP, fingerprint), clientIP)

	writeJSON(w, http.StatusOK, hostKeyResponse{IP: req.IP, Fingerprint: fingerprint, Status: "scanned"})
}

// HandleSSHHostKeyPin pins the host key of ip:22, and ONLY if the fingerprint the
// operator confirms matches the one the host actually presents. It is the second
// half of the bootstrap.
func (h *Handler) HandleSSHHostKeyPin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	req, ok := decodeHostKeyRequest(w, r)
	if !ok {
		return
	}
	if req.Fingerprint == "" {
		// Épingler sans empreinte confirmée reviendrait à faire confiance à ce que
		// le réseau présente à cet instant : c'est exactement ce que l'épinglage
		// est censé empêcher.
		writeJSON(w, http.StatusBadRequest, hostKeyResponse{IP: req.IP,
			Error: "Empreinte attendue manquante : confirmez l'empreinte relevée sur la machine."})
		return
	}

	actor := middleware.GetSessionUser(r, h.SessionStore)
	clientIP := middleware.RealIP(r)

	fingerprint, err := h.SSHService.PinHostKey(req.IP, req.Fingerprint)
	if err != nil {
		slog.Error("SSH host key pin refused", "ip", req.IP, "error", err)
		go services.LogAudit(h.DB, 0, actor, "SSHHostKeyPinRefused",
			fmt.Sprintf("Épinglage de la clé hôte de %s refusé : %v", req.IP, err), clientIP)
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, services.ErrHostKeyFingerprintMismatch):
			// L'hôte ne présente pas ce que l'exploitant a confirmé : soit une
			// erreur de recopie, soit quelqu'un s'interpose. Rien n'a été écrit.
			status = http.StatusConflict
		case errors.Is(err, services.ErrHostKeyMismatch):
			// Hôte déjà épinglé avec une AUTRE clé : réinstallation ou MITM. La
			// sortie est la suppression explicite de l'épinglage (DELETE ci-dessous).
			status = http.StatusConflict
		}
		writeJSON(w, status, hostKeyResponse{IP: req.IP, Fingerprint: fingerprint, Error: err.Error()})
		return
	}

	go services.LogAudit(h.DB, 0, actor, "SSHHostKeyPin",
		fmt.Sprintf("Clé hôte de %s épinglée (%s)", req.IP, fingerprint), clientIP)

	writeJSON(w, http.StatusOK, hostKeyResponse{IP: req.IP, Fingerprint: fingerprint, Status: "pinned"})
}

// HandleSSHHostKeyDelete removes the pinned host key of ip — the only way out of
// ErrHostKeyMismatch after a legitimate reinstall.
func (h *Handler) HandleSSHHostKeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}
	req, ok := decodeHostKeyRequest(w, r)
	if !ok {
		return
	}

	actor := middleware.GetSessionUser(r, h.SessionStore)
	clientIP := middleware.RealIP(r)

	removed, err := h.SSHService.DeletePinnedHostKey(req.IP)
	if err != nil {
		slog.Error("SSH host key unpin failed", "ip", req.IP, "error", err)
		writeJSON(w, http.StatusInternalServerError, hostKeyResponse{IP: req.IP, Error: err.Error()})
		return
	}

	status := "deleted"
	if !removed {
		// Rien à supprimer : l'état visé (« cet hôte n'est plus épinglé ») est déjà
		// atteint, ce n'est pas une erreur — mais l'UI doit pouvoir le dire.
		status = "absent"
	} else {
		// Désépingler rouvre la fenêtre TOFU pour cet hôte : c'est exactement le
		// moment qu'un attaquant choisirait, donc la trace doit être explicite.
		go services.LogAudit(h.DB, 0, actor, "SSHHostKeyDelete",
			fmt.Sprintf("Clé hôte épinglée de %s supprimée — le prochain épinglage refera confiance à la clé présentée", req.IP), clientIP)
	}

	writeJSON(w, http.StatusOK, hostKeyResponse{IP: req.IP, Status: status})
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
