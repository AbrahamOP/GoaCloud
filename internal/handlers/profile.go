package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"goacloud/internal/models"
)

// HandleProfile renders the user profile page.
func (h *Handler) HandleProfile(w http.ResponseWriter, r *http.Request) {
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

	var user models.User
	var mfaSecret sql.NullString
	err = h.DB.QueryRow("SELECT id, username, email, role, created_at, mfa_enabled, mfa_secret, github_url FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.CreatedAt, &user.MFAEnabled, &mfaSecret, &user.GithubURL)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	user.MFASecret = mfaSecret.String

	h.Templates.ExecuteTemplate(w, "profile.html", user)
}

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
