package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// The profile page itself moved into the Paramètres hub (see settings.go:
// HandleSettingsProfil, served at /profile and /parametres/profil). The mutation
// endpoints below stay here and redirect back to /profile (the hub profil section).

// HandleUpdateProfile handles password change requests.
func (h *Handler) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
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

	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if oldPassword == "" || newPassword == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}
	if len(newPassword) < 8 {
		http.Redirect(w, r, "/profile?error=Le mot de passe doit contenir au moins 8 caractères", http.StatusSeeOther)
		return
	}
	if newPassword != confirmPassword {
		http.Error(w, "New passwords do not match", http.StatusBadRequest)
		return
	}

	var storedHash string
	err = h.DB.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(oldPassword)); err != nil {
		http.Redirect(w, r, "/profile?error=Incorrect old password", http.StatusSeeOther)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	if _, err = h.DB.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(hashedPassword), username); err != nil {
		slog.Error("Error updating password", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Changing the password must retire every cookie minted under the old one —
	// including one an attacker may have stolen, which is the whole point of
	// changing it. RotateSessionAfterCredentialChange bumps the revocation epoch and
	// re-stamps THIS session, so the device doing the change stays signed in.
	//
	// The new hash is already written: a rotation failure cannot be undone, so it is
	// reported to the user (their other sessions are still live) instead of being
	// swallowed or turned into a 500 that would suggest nothing happened.
	if err := h.RotateSessionAfterCredentialChange(w, r, username); err != nil {
		http.Redirect(w, r, "/profile?error=Mot de passe modifié, mais les autres sessions n'ont pas pu être révoquées — utilisez « Déconnecter toutes mes sessions »", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/profile?success=true", http.StatusSeeOther)
}

// HandleUpdateGithub updates the GitHub URL for the current user.
func (h *Handler) HandleUpdateGithub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	githubURL := strings.TrimSpace(r.FormValue("github_url"))
	if githubURL != "" && !strings.HasPrefix(githubURL, "http://") && !strings.HasPrefix(githubURL, "https://") {
		http.Redirect(w, r, "/profile?error=URL invalide", http.StatusSeeOther)
		return
	}
	if _, err := h.DB.Exec("UPDATE users SET github_url = ? WHERE username = ?", githubURL, username); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile?success=true", http.StatusSeeOther)
}

// HandleMe returns the current user's GitHub URL as JSON.
func (h *Handler) HandleMe(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	var githubURL string
	h.DB.QueryRow("SELECT github_url FROM users WHERE username = ?", username).Scan(&githubURL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"github_url": githubURL})
}
