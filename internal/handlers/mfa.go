package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"goacore/internal/services"
	"golang.org/x/crypto/bcrypt"
)

// Server-side enrolment state for the "activate 2FA" flow.
//
// The candidate secret is minted by /api/mfa/setup and parked in the session
// (already encrypted, exactly as it will be stored) instead of being handed to the
// browser and posted back to /api/mfa/verify. A client-supplied secret would let a
// caller enrol a factor of their choosing in one request; here the secret /verify
// commits is one THIS server generated, for THIS session, less than mfaEnrollTTL ago.
const (
	sessionMFAEnrollSecret = "mfa_enroll_secret"
	sessionMFAEnrollExp    = "mfa_enroll_exp"

	// mfaEnrollTTL bounds how long a started enrolment stays committable — long
	// enough to install an authenticator app, short enough not to linger.
	mfaEnrollTTL = 10 * time.Minute
)

// HandleSetupMFA generates a new TOTP secret and QR code, and parks the candidate
// secret server-side (session) until /api/mfa/verify commits it.
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

	// The session cookie is signed, not encrypted: the candidate secret goes in
	// encrypted, like the column it will end up in.
	encryptedSecret, err := h.SSHService.EncryptData(key.Secret())
	if err != nil {
		slog.Error("MFA Encrypt Error", "error", err)
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}
	session.Values[sessionMFAEnrollSecret] = encryptedSecret
	session.Values[sessionMFAEnrollExp] = time.Now().Add(mfaEnrollTTL).Unix()
	if err := session.Save(r, w); err != nil {
		slog.Error("MFA enrolment session save failed", "user", username, "error", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"secret":  key.Secret(),
		"qr_code": base64.StdEncoding.EncodeToString(buf.Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleVerifyMFA commits the pending enrolment: it validates a code produced by
// the candidate secret and writes that secret to the database.
//
// Enrolling is as sensitive as disabling (see HandleDisableMFA): a hijacked session
// that cannot REMOVE the second factor could otherwise simply REPLACE it with one
// the attacker controls. So when the account ALREADY has 2FA on, the caller must
// prove they hold one of the two current factors — the password or a code from the
// CURRENT authenticator — and the re-enrolment revokes every other session.
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

	// Code = the 6 digits read on the NEW authenticator. Password / CurrentCode =
	// the proof required to REPLACE an existing factor (ignored on a first enrolment).
	var req struct {
		Code        string `json:"code"`
		Password    string `json:"password"`
		CurrentCode string `json:"current_code"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Code == "" {
		mfaError(w, http.StatusBadRequest, "Code à 6 chiffres requis")
		return
	}

	encryptedSecret, ok := pendingEnrolment(session)
	if !ok {
		mfaError(w, http.StatusBadRequest, "Aucune configuration 2FA en cours (ou expirée) — relancez « Activer 2FA »")
		return
	}
	secret := h.mfaSecretOf(encryptedSecret)

	user, err := h.lookupLoginUser(username)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Re-enrolment: replacing a live second factor demands the same proof as
	// removing it, otherwise the hardening of /api/mfa/disable is decorative.
	reEnrolment := user.mfaEnabled
	if reEnrolment {
		if req.Password == "" && req.CurrentCode == "" {
			mfaError(w, http.StatusBadRequest, "Mot de passe ou code 2FA actuel requis pour remplacer la double authentification")
			return
		}
		if !h.reauthenticate(user, req.Password, req.CurrentCode) {
			slog.Warn("MFA re-enrolment refused: re-authentication failed", "user", username)
			go services.LogAudit(h.DB, 0, username, "MFAReenrollRefused",
				"Tentative de remplacement de la 2FA refusée (ré-authentification invalide)", r.RemoteAddr)
			mfaError(w, http.StatusUnauthorized, "Mot de passe ou code 2FA actuel invalide")
			return
		}
	}

	if !totp.Validate(req.Code, secret) {
		mfaError(w, http.StatusUnauthorized, "Code invalide")
		return
	}

	if _, err = h.DB.Exec("UPDATE users SET mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", encryptedSecret, username); err != nil {
		slog.Error("MFA DB Update Error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if reEnrolment {
		// Same treatment as a credential change: every other session (including one
		// an attacker could be riding) is revoked, the current one is re-stamped.
		if err := h.RotateSessionAfterCredentialChange(w, r, username); err != nil {
			mfaError(w, http.StatusInternalServerError,
				"2FA remplacée, mais les autres sessions n'ont pas pu être révoquées — utilisez « Déconnecter toutes mes sessions »")
			return
		}
		// The TOTP secret NEVER reaches the trail: the event is recorded, not the factor.
		go services.LogAudit(h.DB, 0, username, "MFAReenroll",
			"2FA remplacée par un nouveau facteur (sessions révoquées)", r.RemoteAddr)
	} else {
		h.clearMFAEnrolment(w, r, session)
		go services.LogAudit(h.DB, 0, username, "MFAEnable", "2FA activée par l'utilisateur", r.RemoteAddr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// pendingEnrolment returns the still-valid candidate secret (encrypted) of the
// enrolment started by /api/mfa/setup, if any.
func pendingEnrolment(session *sessions.Session) (string, bool) {
	secret, _ := session.Values[sessionMFAEnrollSecret].(string)
	if secret == "" {
		return "", false
	}
	exp, _ := session.Values[sessionMFAEnrollExp].(int64)
	if exp <= 0 || time.Now().Unix() > exp {
		return "", false
	}
	return secret, true
}

// clearMFAEnrolment consumes the enrolment state and persists the session.
func (h *Handler) clearMFAEnrolment(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	delete(session.Values, sessionMFAEnrollSecret)
	delete(session.Values, sessionMFAEnrollExp)
	if err := session.Save(r, w); err != nil {
		slog.Error("MFA enrolment session clear failed", "error", err)
	}
}

// reauthenticate reports whether the caller proved, right now, that they hold one
// of the account's two factors: the current password, or a code from the CURRENT
// TOTP secret. It is the gate shared by every operation that touches the second
// factor (disable, re-enrol).
func (h *Handler) reauthenticate(user loginUser, password, code string) bool {
	if password != "" && bcrypt.CompareHashAndPassword([]byte(user.passwordHash), []byte(password)) == nil {
		return true
	}
	if code != "" && user.mfaSecret.Valid {
		return totp.Validate(code, h.mfaSecretOf(user.mfaSecret.String))
	}
	return false
}

// HandleDisableMFA disables MFA for the current user.
//
// Turning the second factor off is itself a sensitive operation: with only a
// session cookie required, anyone who hijacks a session could remove the second
// factor and re-enrol it on their own device. So the caller must PROVE they hold
// one of the two factors right now — the current password OR a valid TOTP code —
// and every existing session is revoked afterwards (session_epoch bump), which
// evicts the very session an attacker would have used. The session that performed
// the disable is re-stamped with the new epoch: the legitimate user stays logged in
// on the device they just acted from, everyone else is signed out.
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

	if !h.reauthenticate(user, req.Password, req.Code) {
		slog.Warn("MFA disable refused: re-authentication failed", "user", username)
		// A failed attempt to strip the second factor is exactly what a hijacked
		// session looks like — it belongs in the trail, not only in the app logs.
		go services.LogAudit(h.DB, 0, username, "MFADisableRefused",
			"Tentative de désactivation de la 2FA refusée (ré-authentification invalide)", r.RemoteAddr)
		mfaError(w, http.StatusUnauthorized, "Mot de passe ou code 2FA invalide")
		return
	}

	if _, err = h.DB.Exec("UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE username = ?", username); err != nil {
		slog.Error("MFA disable DB error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	// The epoch bump lives in the rotation so the CURRENT session is re-issued with
	// the new epoch instead of being silently evicted along with the others.
	if err := h.RotateSessionAfterCredentialChange(w, r, username); err != nil {
		mfaError(w, http.StatusInternalServerError,
			"2FA désactivée, mais les autres sessions n'ont pas pu être révoquées — utilisez « Déconnecter toutes mes sessions »")
		return
	}
	go services.LogAudit(h.DB, 0, username, "MFADisable", "2FA désactivée par l'utilisateur (sessions révoquées)", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
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
