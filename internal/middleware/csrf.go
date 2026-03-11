package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

const (
	csrfTokenLength  = 32
	csrfSessionKey   = "csrf_token"
	csrfCookieName   = "_csrf"
	csrfHeaderName   = "X-CSRF-Token"
	csrfFormField    = "csrf_token"
)

// CSRFProtection is a middleware that validates CSRF tokens on state-changing requests.
func CSRFProtection(store *sessions.CookieStore, cookieSecure bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "goacloud-session")

			// Ensure a CSRF token exists in the session
			token, ok := session.Values[csrfSessionKey].(string)
			if !ok || token == "" {
				token = generateCSRFToken()
				session.Values[csrfSessionKey] = token
				session.Save(r, w)
			}

			// Set a readable cookie so JS can include the token in requests
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/",
				Secure:   cookieSecure,
				HttpOnly: false, // JS must read this
				SameSite: http.SameSiteStrictMode,
			})

			// Validate on state-changing methods
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				// Skip CSRF check for login and setup (no session yet)
				path := r.URL.Path
				if path == "/login" || path == "/setup" {
					next.ServeHTTP(w, r)
					return
				}

				// Get the submitted token from header or form field
				submitted := r.Header.Get(csrfHeaderName)
				if submitted == "" {
					// Try form field (works for both multipart and urlencoded)
					ct := r.Header.Get("Content-Type")
					if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
						submitted = r.FormValue(csrfFormField)
					}
				}
				if submitted == "" {
					// Also check form value for JSON endpoints that may send it
					submitted = r.URL.Query().Get(csrfFormField)
				}

				if submitted == "" || submitted != token {
					http.Error(w, "CSRF token invalid", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func generateCSRFToken() string {
	b := make([]byte, csrfTokenLength)
	if _, err := rand.Read(b); err != nil {
		panic("csrf: failed to generate random token: " + err.Error())
	}
	return hex.EncodeToString(b)
}
