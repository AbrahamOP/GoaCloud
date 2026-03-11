package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"goacloud/internal/middleware"
	"goacloud/internal/models"
	"goacloud/internal/services"
)

// HandleUsers renders the user management page.
func (h *Handler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Erreur base de données", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			slog.Error("Error scanning user", "error", err)
			continue
		}
		users = append(users, u)
	}

	data := struct {
		Users []models.User
	}{Users: users}

	if err := h.Templates.ExecuteTemplate(w, "users.html", data); err != nil {
		slog.Error("Template execution error", "error", err)
		http.Error(w, "Render error", http.StatusInternalServerError)
	}
}

// HandleAddUser creates a new user (Admin only).
func (h *Handler) HandleAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	role := r.FormValue("role")
	if role != "Admin" && role != "Viewer" {
		role = "Viewer"
	}

	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}
	if len(password) < 8 {
		http.Error(w, "Le mot de passe doit contenir au moins 8 caractères", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	if _, err = h.DB.Exec("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)", username, string(hashedPassword), email, role); err != nil {
		slog.Error("Error adding user", "error", err)
		http.Error(w, "Error saving user (duplicate?)", http.StatusInternalServerError)
		return
	}

	if sess, err := h.SessionStore.Get(r, "goacloud-session"); err == nil {
		if u, ok := sess.Values["username"].(string); ok && u != "" {
			go services.LogAudit(h.DB, 0, u, "AddUser", fmt.Sprintf("Added user: %s (Role: %s)", username, role), r.RemoteAddr)
		}
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// HandleDeleteUser deletes a user by ID (Admin only).
func (h *Handler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	userID := r.FormValue("user_id")
	if userID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	var role string
	if err := h.DB.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role); err != nil {
		slog.Error("Error fetching user role", "error", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if role == "Admin" {
		var adminCount int
		if err := h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'Admin'").Scan(&adminCount); err != nil {
			slog.Error("Error counting admins", "error", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		if adminCount <= 1 {
			http.Error(w, "Impossible de supprimer le dernier administrateur", http.StatusBadRequest)
			return
		}
	}

	if _, err := h.DB.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		slog.Error("Error deleting user", "error", err)
		http.Error(w, "Error deleting user", http.StatusInternalServerError)
		return
	}

	if sess, err := h.SessionStore.Get(r, "goacloud-session"); err == nil {
		if u, ok := sess.Values["username"].(string); ok && u != "" {
			go services.LogAudit(h.DB, 0, u, "DeleteUser", fmt.Sprintf("Deleted user ID: %s", userID), r.RemoteAddr)
		}
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// HandleUpdateUser updates a user's role (Admin only).
func (h *Handler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !middleware.RequireAdmin(w, r, h.SessionStore, h.DB) {
		return
	}

	userID := r.FormValue("user_id")
	role := r.FormValue("role")
	if role != "Admin" && role != "Viewer" {
		http.Error(w, "Rôle invalide", http.StatusBadRequest)
		return
	}
	if userID == "" || role == "" {
		http.Error(w, "User ID and Role are required", http.StatusBadRequest)
		return
	}

	if _, err := h.DB.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID); err != nil {
		slog.Error("Error updating user role", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if sess, err := h.SessionStore.Get(r, "goacloud-session"); err == nil {
		if u, ok := sess.Values["username"].(string); ok && u != "" {
			go services.LogAudit(h.DB, 0, u, "UpdateUserRole", fmt.Sprintf("Updated user ID %s to role %s", userID, role), r.RemoteAddr)
		}
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
