package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"log/slog"
	"net/http"

	"github.com/pquerna/otp/totp"
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
		Issuer:      "GoaCloud",
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

	if _, err = h.DB.Exec("UPDATE users SET mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", req.Secret, username); err != nil {
		slog.Error("MFA DB Update Error", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleDisableMFA disables MFA for the current user.
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

	if _, err = h.DB.Exec("UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE username = ?", username); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "disabled"})
}
