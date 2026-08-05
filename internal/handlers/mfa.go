package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"log/slog"
	"net/http"

	"github.com/pquerna/otp/totp"
	"goacore/internal/services"
	"golang.org/x/crypto/bcrypt"
)

// HandleSetupMFA generates a new TOTP secret and QR code.
func (h *Handler) HandleSetupMFA(w http.ResponseWriter, r *http.Request) {
	session, err := h.SessionStore.Get(r, "goacloud-session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoaCore",
		AccountName: username,
	})
	if err != nil {
		slog.Error("MFA Generate Error", "error", err)
		http.Error(w, "Error generating key", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		slog.Error("MFA Image Error", "error", err)
		http.Error(w, "Error generating QR code", http.StatusInternalServerError)
		return
	}
	png.Encode(&buf, img)

	response := map[string]string{
		"secret":  key.Secret(),
		"qr_code": base64.StdEncoding.EncodeToString(buf.Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleVerifyMFA verifies a TOTP code and saves the MFA secret to the database.
func (h *Handler) HandleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := h.SessionStore.Get(r, "goacloud-session")
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
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Code == "" || req.Secret == "" {
		http.Error(w, "Code and Secret are required", http.StatusBadRequest)
		return
	}

	if !totp.Validate(req.Code, req.Secret) {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	// Encrypt MFA secret before storing in DB
	encryptedSecret, err := h.SSHService.EncryptData(req.Secret)
	if err != nil {
		slog.Error("MFA Encrypt Error", "error", err)
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	if _, err = h.DB.Exec("UPDATE users SET mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", encryptedSecret, username); err != nil {
		slog.Error("MFA DB Update Error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	// The TOTP secret NEVER reaches the trail: the event is recorded, not the factor.
	go services.LogAudit(h.DB, 0, username, "MFAEnable", "2FA activée par l'utilisateur", r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleDisableMFA disables MFA for the current user.
//
// Turning the second factor off is itself a sensitive operation: with only a
// session cookie required, anyone who hijacks a session could remove the second
// factor and re-enrol it on their own device. So the caller must PROVE they hold
// one of the two factors right now — the current password OR a valid TOTP code —
// and every existing session is revoked afterwards (session_epoch bump), which
// evicts the very session an attacker would have used.
func (h *Handler) HandleDisableMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := h.SessionStore.Get(r, "goacloud-session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// The body is optional-shaped on purpose: a client may send {"password": …}
	// or {"code": …}. An empty/absent body simply fails the re-authentication.
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Password == "" && req.Code == "" {
		mfaError(w, http.StatusBadRequest, "Mot de passe ou code 2FA requis pour désactiver la double authentification")
		return
	}

	user, err := h.lookupLoginUser(username)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	reauthenticated := false
	if req.Password != "" {
		reauthenticated = bcrypt.CompareHashAndPassword([]byte(user.passwordHash), []byte(req.Password)) == nil
	}
	if !reauthenticated && req.Code != "" && user.mfaSecret.Valid {
		reauthenticated = totp.Validate(req.Code, h.mfaSecretOf(user.mfaSecret.String))
	}
	if !reauthenticated {
		slog.Warn("MFA disable refused: re-authentication failed", "user", username)
		// A failed attempt to strip the second factor is exactly what a hijacked
		// session looks like — it belongs in the trail, not only in the app logs.
		go services.LogAudit(h.DB, 0, username, "MFADisableRefused",
			"Tentative de désactivation de la 2FA refusée (ré-authentification invalide)", r.RemoteAddr)
		mfaError(w, http.StatusUnauthorized, "Mot de passe ou code 2FA invalide")
		return
	}

	if _, err = h.DB.Exec("UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, session_epoch = session_epoch + 1 WHERE username = ?", username); err != nil {
		slog.Error("MFA disable DB error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	go services.LogAudit(h.DB, 0, username, "MFADisable", "2FA désactivée par l'utilisateur (sessions révoquées)", r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "disabled"})
}

// mfaSecretOf returns the usable TOTP secret of a stored value, decrypting it and
// falling back to the raw string for legacy rows written before the secrets were
// encrypted at rest.
func (h *Handler) mfaSecretOf(stored string) string {
	if decrypted, err := h.SSHService.DecryptData(stored); err == nil {
		return decrypted
	}
	return stored
}

// mfaError writes a JSON error the settings page can display as-is.
func mfaError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
