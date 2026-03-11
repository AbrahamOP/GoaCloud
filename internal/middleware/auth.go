package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

// AuthMiddleware checks if the user is authenticated and redirects to setup/login if not.
func AuthMiddleware(store *sessions.CookieStore, db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/setup" && !strings.HasPrefix(r.URL.Path, "/static") {
			count, err := countUsers(db)
			if (err == nil && count == 0) || (err != nil && strings.Contains(err.Error(), "doesn't exist")) {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
		}

		session, err := store.Get(r, "goacloud-session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AdminOnly checks that the current user has the Admin role (403 otherwise).
func AdminOnly(store *sessions.CookieStore, db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "goacloud-session")
		username, _ := session.Values["username"].(string)
		var role string
		if err := db.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role); err != nil {
			http.Error(w, "Accès refusé.", http.StatusForbidden)
			return
		}
		if role != "Admin" {
			http.Error(w, "Accès refusé. Réservé aux administrateurs.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin is a helper that checks admin role inline (returns false and writes 403 on failure).
func RequireAdmin(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore, db *sql.DB) bool {
	session, _ := store.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	var role string
	if err := db.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role); err != nil {
		http.Error(w, "Accès refusé.", http.StatusForbidden)
		return false
	}
	if role != "Admin" {
		http.Error(w, "Accès refusé. Réservé aux administrateurs.", http.StatusForbidden)
		return false
	}
	return true
}

// GetSessionUser returns the username stored in the session.
func GetSessionUser(r *http.Request, store *sessions.CookieStore) string {
	session, _ := store.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	return username
}

func countUsers(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}
