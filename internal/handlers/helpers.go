package handlers

import (
	"net/http"

	"github.com/gorilla/sessions"
)

// renderError renders a template with an error message.
func (h *Handler) renderError(w http.ResponseWriter, templateName string, errorMsg string) {
	h.Templates.ExecuteTemplate(w, templateName, map[string]interface{}{
		"Error": errorMsg,
	})
}

// getSessionUser extracts the username from the session.
func getSessionUser(r *http.Request, store *sessions.CookieStore) string {
	session, _ := store.Get(r, "goacloud-session")
	username, _ := session.Values["username"].(string)
	return username
}

// countUsers returns the number of users in the database.
func (h *Handler) countUsers() (int, error) {
	var count int
	err := h.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}
