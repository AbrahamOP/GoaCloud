package handlers

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"goacloud/internal/services"
)

// HandleLogin handles GET (show form) and POST (authenticate) for /login.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	count, _ := h.countUsers()
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		h.Templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		return
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if h.RateLimiter.IsBlocked(clientIP) {
		http.Error(w, "Trop de tentatives de connexion. Réessayez dans 15 minutes.", http.StatusTooManyRequests)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	mfaCode := r.FormValue("mfa_code")

	var hashedPassword string
	var mfaEnabled bool
	var mfaSecret sql.NullString

	err := h.DB.QueryRow("SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE username = ?", username).
		Scan(&hashedPassword, &mfaEnabled, &mfaSecret)
	if err != nil {
		n, blocked := h.RateLimiter.RecordFailure(clientIP)
		go h.notifyLoginFailure(clientIP, username, "Utilisateur inconnu", n, blocked)
		h.renderError(w, "login.html", "Utilisateur inconnu")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		n, blocked := h.RateLimiter.RecordFailure(clientIP)
		go h.notifyLoginFailure(clientIP, username, "Mot de passe incorrect", n, blocked)
		h.renderError(w, "login.html", "Mot de passe incorrect")
		return
	}

	if mfaEnabled {
		if mfaCode == "" {
			data := map[string]interface{}{
				"Error":       "Code MFA requis",
				"MFARequired": true,
				"Username":    username,
			}
			h.Templates.ExecuteTemplate(w, "login.html", data)
			return
		}
		valid := totp.Validate(mfaCode, mfaSecret.String)
		if !valid {
			n, blocked := h.RateLimiter.RecordFailure(clientIP)
			go h.notifyLoginFailure(clientIP, username, "Code MFA invalide", n, blocked)
			h.renderError(w, "login.html", "Code MFA invalide")
			return
		}
	}

	session, _ := h.SessionStore.Get(r, "goacloud-session")
	session.Values["authenticated"] = true
	session.Values["username"] = username
	session.Save(r, w)

	h.RateLimiter.Reset(clientIP)
	go services.LogAudit(h.DB, 0, username, "Login", "Successful login", r.RemoteAddr)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleLogout clears the session and redirects to /login.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	session.Values["authenticated"] = false
	session.Values["username"] = ""
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleSetup handles the initial admin user creation.
func (h *Handler) HandleSetup(w http.ResponseWriter, r *http.Request) {
	count, err := h.countUsers()
	if err != nil && !strings.Contains(err.Error(), "doesn't exist") {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		h.Templates.ExecuteTemplate(w, "setup.html", nil)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm_password")

		if username == "" || password == "" {
			h.Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Tous les champs sont requis"})
			return
		}
		if len(password) < 8 {
			h.Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Le mot de passe doit contenir au moins 8 caractères"})
			return
		}
		if password != confirm {
			h.Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Les mots de passe ne correspondent pas"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		_, err = h.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", username, string(hashedPassword), "Admin")
		if err != nil {
			slog.Error("Error creating admin user", "error", err)
			h.Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{"Error": "Erreur base de données: " + err.Error()})
			return
		}

		slog.Info("First run setup completed", "admin", username)
		http.Redirect(w, r, "/login?setup=success", http.StatusSeeOther)
	}
}

// DeriveSSHEncKey derives the AES-256 key for SSH key encryption from the session secret.
func DeriveSSHEncKey(sessionSecret string) [32]byte {
	return sha256.Sum256([]byte(sessionSecret + ":goacloud-ssh-keys"))
}

func (h *Handler) notifyLoginFailure(ip, username, reason string, attempt int, blocked bool) {
	if h.Discord == nil || !h.Discord.IsReady() {
		return
	}
	title := "Échec de connexion"
	msg := fmt.Sprintf("**IP:** `%s`\n**Utilisateur:** `%s`\n**Raison:** %s\n**Tentatives:** %d/5", ip, username, reason, attempt)
	if blocked {
		title = "⛔ IP Bloquée"
		msg += "\n\n> L'adresse IP a été bloquée pendant **15 minutes** suite à trop d'échecs."
	}
	h.Discord.SendAuthAlert(title, msg, blocked)
}
