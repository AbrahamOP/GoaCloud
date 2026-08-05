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

		// Revalidate user still exists in DB with current role AND that the session
		// has not been revoked. Revocation is stateless-friendly: users.session_epoch
		// is a counter bumped on password change, MFA disable/reset and "log out all
		// my sessions"; the epoch in force at login travels in the cookie, so a cookie
		// minted before a bump no longer matches any row and dies here — which is what
		// makes a stolen 24h cookie revocable at all.
		//
		// The epoch is part of the SAME lookup (no extra round trip): a row that
		// matches the username but not the epoch simply does not come back, and a
		// missing row already means "invalidate the session".
		username, _ := session.Values["username"].(string)
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		epoch, _ := session.Values["session_epoch"].(int)
		var dbRole string
		if err := db.QueryRow("SELECT role FROM users WHERE username = ? AND session_epoch = ?", username, epoch).Scan(&dbRole); err != nil {
			// User deleted, session revoked (epoch bumped) or DB error — invalidate session
			session.Values["authenticated"] = false
			session.Options.MaxAge = -1
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Keep session role in sync with DB
		session.Values["role"] = dbRole
		session.Save(r, w)

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

// GetSessionRole returns the role stored in the session ("Admin"/"Viewer"/"").
// AuthMiddleware keeps session.Values["role"] in sync with the DB on every request,
// so this is a lock-free read suitable for role-aware view rendering (e.g. hiding
// admin-only nav entries). It is NOT an authorization gate on its own — the
// admin-only routes are still enforced by AdminOnly/RequireAdmin at the router level.
func GetSessionRole(r *http.Request, store *sessions.CookieStore) string {
	session, _ := store.Get(r, "goacloud-session")
	role, _ := session.Values["role"].(string)
	return role
}

func countUsers(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}
