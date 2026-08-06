package handlers

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"goacore/internal/middleware"
	"goacore/internal/services"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a valid bcrypt hash of a random string, compared against
// when the supplied username doesn't exist so login timing stays constant and
// doesn't leak whether an account exists.
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// Server-side pre-authentication state for the two-step MFA login.
//
// Step 1 validates login+password and, when MFA is required, records WHO is
// half-way through the login in the session together with a short expiry. Step 2
// posts the TOTP code ALONE and is checked against that state.
//
// The password deliberately never travels back to the browser: the MFA step used
// to re-post it from a hidden field, which both echoed the cleartext password in
// the served HTML and — because the field was never populated — made every MFA
// login fail with "Identifiants invalides".
const (
	sessionMFAPendingUser = "mfa_pending_user"
	sessionMFAPendingExp  = "mfa_pending_exp"
	sessionEpochKey       = "session_epoch"

	// mfaPendingTTL bounds how long a half-finished login stays usable.
	mfaPendingTTL = 5 * time.Minute
)

// loginUser is the row HandleLogin needs to authenticate a user.
type loginUser struct {
	passwordHash string
	mfaEnabled   bool
	mfaSecret    sql.NullString
	sessionEpoch int
}

// HandleLogin handles GET (show form) and POST (authenticate) for /login.
//
// The POST arm serves the two steps of the login: username+password (step 1) and,
// for an MFA account, the TOTP code alone (step 2, recognised by the absence of
// credentials in the form and resolved against the pre-auth session state).
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	count, _ := h.countUsers()
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		h.renderLogin(w, loginPageData("", "", false))
		return
	}

	if r.Method != http.MethodPost {
		return
	}

	clientIP := middleware.RealIP(r)
	if h.RateLimiter.IsBlocked(clientIP) {
		http.Error(w, middleware.BlockedMessage(), http.StatusTooManyRequests)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Step 2: the MFA form (login.html) posts the code with NO credential field,
	// so an empty username+password means "finish the pending login".
	if username == "" && password == "" {
		h.finishMFALogin(w, r, clientIP, r.FormValue("mfa_code"))
		return
	}

	user, err := h.lookupLoginUser(username)
	if err != nil {
		// Run a bcrypt compare against a dummy hash so an unknown user takes the
		// same time as a wrong password, and return an identical message — no
		// account enumeration by response content or timing.
		bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
		n, blocked := h.RateLimiter.RecordFailure(clientIP)
		go h.notifyLoginFailure(clientIP, username, "Utilisateur inconnu", n, blocked)
		h.dropMFAPending(w, r)
		h.renderLogin(w, loginPageData("Identifiants invalides", username, false))
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.passwordHash), []byte(password)); err != nil {
		n, blocked := h.RateLimiter.RecordFailure(clientIP)
		go h.notifyLoginFailure(clientIP, username, "Mot de passe incorrect", n, blocked)
		h.dropMFAPending(w, r)
		h.renderLogin(w, loginPageData("Identifiants invalides", username, false))
		return
	}

	// Credentials are good. An MFA account is NOT logged in yet: park the identity
	// server-side and ask for the code.
	if user.mfaEnabled {
		h.startMFAChallenge(w, r, username)
		return
	}

	h.establishSession(w, r, username, user.sessionEpoch)
	h.RateLimiter.Reset(clientIP)
	go services.LogAudit(h.DB, 0, username, "Login", "Successful login", r.RemoteAddr)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startMFAChallenge records the pre-auth state (user + expiry) in the session and
// renders the MFA step. Nothing about the password is kept — the second step only
// ever needs to know WHO is authenticating.
func (h *Handler) startMFAChallenge(w http.ResponseWriter, r *http.Request, username string) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	session.Values[sessionMFAPendingUser] = username
	session.Values[sessionMFAPendingExp] = time.Now().Add(mfaPendingTTL).Unix()
	// Half-way through a login is NOT logged in.
	session.Values["authenticated"] = false
	if err := session.Save(r, w); err != nil {
		slog.Error("MFA pre-auth session save failed", "error", err)
		h.renderLogin(w, loginPageData("Erreur de session, veuillez réessayer", "", false))
		return
	}
	h.renderLogin(w, loginPageData("Code MFA requis", "", true))
}

// finishMFALogin completes a login whose password step already succeeded. The
// identity comes from the pre-auth session state — never from the request — and
// the state must still be within its TTL.
func (h *Handler) finishMFALogin(w http.ResponseWriter, r *http.Request, clientIP, mfaCode string) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	pendingUser, ok := mfaPending(session)
	if !ok {
		// No pending login, or it expired: start over from the credentials form.
		h.clearMFAPending(w, r, session)
		h.renderLogin(w, loginPageData("Session d'authentification expirée, veuillez vous reconnecter", "", false))
		return
	}

	if mfaCode == "" {
		h.renderLogin(w, loginPageData("Code MFA requis", "", true))
		return
	}

	user, err := h.lookupLoginUser(pendingUser)
	if err != nil || !user.mfaEnabled {
		// The account was deleted, or MFA was turned off, since step 1.
		h.clearMFAPending(w, r, session)
		h.renderLogin(w, loginPageData("Identifiants invalides", "", false))
		return
	}

	if !totp.Validate(mfaCode, h.mfaSecretOf(user.mfaSecret.String)) {
		n, blocked := h.RateLimiter.RecordFailure(clientIP)
		go h.notifyLoginFailure(clientIP, pendingUser, "Code MFA invalide", n, blocked)
		if blocked {
			// Out of attempts: the failure is definitive, so the half-login dies
			// with it instead of staying redeemable for the rest of its TTL.
			h.clearMFAPending(w, r, session)
			h.renderLogin(w, loginPageData("Code MFA invalide, veuillez recommencer la connexion", "", false))
			return
		}
		// Keep the pending state so the user can retry within the same TTL window.
		h.renderLogin(w, loginPageData("Code MFA invalide", "", true))
		return
	}

	// establishSession regenerates the session, which consumes the pre-auth state.
	h.establishSession(w, r, pendingUser, user.sessionEpoch)
	h.RateLimiter.Reset(clientIP)
	go services.LogAudit(h.DB, 0, pendingUser, "Login", "Successful login (MFA)", r.RemoteAddr)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// mfaPending returns the user of a still-valid pre-auth state, if any.
func mfaPending(session *sessions.Session) (string, bool) {
	username, _ := session.Values[sessionMFAPendingUser].(string)
	if username == "" {
		return "", false
	}
	exp, _ := session.Values[sessionMFAPendingExp].(int64)
	if exp <= 0 || time.Now().Unix() > exp {
		return "", false
	}
	return username, true
}

// dropMFAPending consumes any half-finished login carried by the request.
//
// A pre-auth state must not outlive the step that created it: left in place, a
// FAILED credentials step would keep the previous "password already verified"
// marker redeemable for the rest of its TTL, so a bare TOTP code could still
// finish the login the browser just failed to start again.
func (h *Handler) dropMFAPending(w http.ResponseWriter, r *http.Request) {
	session, err := h.SessionStore.Get(r, "goacloud-session")
	if err != nil {
		return
	}
	if _, exists := session.Values[sessionMFAPendingUser]; !exists {
		return
	}
	h.clearMFAPending(w, r, session)
}

// clearMFAPending drops the pre-auth state and persists the session.
func (h *Handler) clearMFAPending(w http.ResponseWriter, r *http.Request, session *sessions.Session) {
	delete(session.Values, sessionMFAPendingUser)
	delete(session.Values, sessionMFAPendingExp)
	if err := session.Save(r, w); err != nil {
		slog.Error("MFA pre-auth session clear failed", "error", err)
	}
}

// establishSession opens the authenticated session: it regenerates the cookie
// (session fixation), drops any leftover pre-auth state and stamps the user's
// current revocation epoch, which AuthMiddleware re-checks on every request.
func (h *Handler) establishSession(w http.ResponseWriter, r *http.Request, username string, epoch int) {
	if oldSession, err := h.SessionStore.Get(r, "goacloud-session"); err == nil {
		oldSession.Options.MaxAge = -1
		oldSession.Save(r, w)
	}
	session, _ := h.SessionStore.New(r, "goacloud-session")
	// New() re-decodes the incoming cookie, so the transient MFA state (pre-auth
	// login AND pending enrolment) must go explicitly, or it would survive into the
	// fresh session and stay redeemable.
	delete(session.Values, sessionMFAPendingUser)
	delete(session.Values, sessionMFAPendingExp)
	delete(session.Values, sessionMFAEnrollSecret)
	delete(session.Values, sessionMFAEnrollExp)
	session.Values["authenticated"] = true
	session.Values["username"] = username
	session.Values[sessionEpochKey] = epoch
	if err := session.Save(r, w); err != nil {
		slog.Error("Session save failed", "user", username, "error", err)
	}
}

// lookupLoginUser reads everything the login flow needs about a user in one query.
func (h *Handler) lookupLoginUser(username string) (loginUser, error) {
	var u loginUser
	err := h.DB.QueryRow("SELECT password_hash, mfa_enabled, mfa_secret, session_epoch FROM users WHERE username = ?", username).
		Scan(&u.passwordHash, &u.mfaEnabled, &u.mfaSecret, &u.sessionEpoch)
	return u, err
}

// bumpSessionEpoch revokes every cookie already minted for a user by advancing the
// revocation counter AuthMiddleware validates on each request. The CookieStore keeps
// no server-side state, so this counter is the ONLY thing that can retire a stolen
// 24h cookie: bump it whenever the account's authentication material changes
// (password, MFA) or when the user asks to be logged out everywhere.
func (h *Handler) bumpSessionEpoch(username string) error {
	if _, err := h.DB.Exec("UPDATE users SET session_epoch = session_epoch + 1 WHERE username = ?", username); err != nil {
		slog.Error("Session epoch bump failed", "user", username, "error", err)
		return err
	}
	return nil
}

// RotateSessionAfterCredentialChange revokes every session of a user and re-stamps
// the CURRENT one with the new epoch — so changing your password signs out every
// other device (and any stolen cookie) without signing out the device you are
// changing it from.
//
// This is the call the password-change handler (profile.go, HandleUpdateProfile)
// must make right after it writes the new hash; the session revocation is only as
// good as the places that remember to bump.
func (h *Handler) RotateSessionAfterCredentialChange(w http.ResponseWriter, r *http.Request, username string) error {
	if err := h.bumpSessionEpoch(username); err != nil {
		return err
	}
	var epoch int
	if err := h.DB.QueryRow("SELECT session_epoch FROM users WHERE username = ?", username).Scan(&epoch); err != nil {
		slog.Error("Session epoch read-back failed", "user", username, "error", err)
		return err
	}
	h.establishSession(w, r, username, epoch)
	return nil
}

// loginPageData builds the data map login.html is executed with. EVERY key the
// template reads must be present: html/template renders a missing map key as
// "<no value>", which is what the (now removed) "clear the field on first focus"
// script used to hide — at the cost of breaking password managers.
func loginPageData(errMsg, username string, mfaRequired bool) map[string]interface{} {
	return map[string]interface{}{
		"Error":       errMsg,
		"Username":    username,
		"MFARequired": mfaRequired,
	}
}

// renderLogin executes login.html with a complete data map.
func (h *Handler) renderLogin(w http.ResponseWriter, data map[string]interface{}) {
	if err := h.Templates.ExecuteTemplate(w, "login.html", data); err != nil {
		slog.Error("Template error (login.html)", "error", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// HandleLogout clears the session and redirects to /login.
//
// It deliberately does NOT bump the revocation epoch: logging out on one device
// must not sign the user out of their other devices. The explicit
// "déconnecter toutes mes sessions" action (HandleLogoutAll) is the one that
// retires every cookie, including one that was stolen.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := h.SessionStore.Get(r, "goacloud-session")
	session.Values["authenticated"] = false
	session.Values["username"] = ""
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleLogoutAll revokes EVERY session of the current user — including the
// current one and any cookie an attacker may have stolen — by bumping the
// revocation epoch. This is the user-facing remedy for a suspected session theft.
func (h *Handler) HandleLogoutAll(w http.ResponseWriter, r *http.Request) {
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

	if err := h.bumpSessionEpoch(username); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	go services.LogAudit(h.DB, 0, username, "LogoutAll", "Révocation de toutes les sessions", r.RemoteAddr)

	session.Values["authenticated"] = false
	session.Values["username"] = ""
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleSetup handles the initial admin user creation.
//
// The route is public by necessity (there is no account yet to authenticate
// against), so it is hardened twice: the POST is rate limited like /login, and the
// account is created inside a transaction that holds a locking read on users —
// two simultaneous POSTs can no longer both pass the "no user yet" check and end
// up creating two admins.
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
		if err := h.Templates.ExecuteTemplate(w, "setup.html", nil); err != nil {
			slog.Error("Template error (setup.html)", "error", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		// Same budget as /login against someone hammering the window between
		// `docker compose up` and the operator's first visit — but ONLY abuse is
		// counted. A typo in the install form (empty field, short password,
		// mismatched confirmation) is not an attack: counting it used to lock the
		// operator's own IP out of their brand-new instance for 15 minutes, at the
		// one moment there is no account to recover from.
		clientIP := middleware.RealIP(r)
		if h.RateLimiter.IsBlocked(clientIP) {
			http.Error(w, middleware.BlockedMessage(), http.StatusTooManyRequests)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm_password")

		// invalidForm re-renders the form WITHOUT charging the rate limiter.
		invalidForm := func(msg string) {
			h.renderError(w, "setup.html", msg)
		}
		// setupAbuse is the other kind of failure: a POST that had no business
		// succeeding (the instance is already installed, or the write blew up).
		setupAbuse := func(msg string) {
			h.RateLimiter.RecordFailure(clientIP)
			h.renderError(w, "setup.html", msg)
		}

		if username == "" || password == "" {
			invalidForm("Tous les champs sont requis")
			return
		}
		if len(password) < 8 {
			invalidForm("Le mot de passe doit contenir au moins 8 caractères")
			return
		}
		if password != confirm {
			invalidForm("Les mots de passe ne correspondent pas")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		created, err := h.createFirstAdmin(username, string(hashedPassword))
		if err != nil {
			slog.Error("Error creating admin user", "error", err)
			setupAbuse("Erreur lors de la création du compte")
			return
		}
		if !created {
			// Another request won the race — the instance is already set up.
			h.RateLimiter.RecordFailure(clientIP)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		h.RateLimiter.Reset(clientIP)
		slog.Info("First run setup completed", "admin", username)
		http.Redirect(w, r, "/login?setup=success", http.StatusSeeOther)
	}
}

// createFirstAdmin inserts the initial Admin account and reports whether it did.
//
// The emptiness check and the INSERT run in ONE transaction, and the check is a
// locking read (SELECT ... FOR UPDATE): on InnoDB it holds the gap on the empty
// users table, so a concurrent /setup POST waits and then sees the freshly created
// admin instead of racing past a stale COUNT of zero.
func (h *Handler) createFirstAdmin(username, passwordHash string) (bool, error) {
	tx, err := h.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM users FOR UPDATE").Scan(&count); err != nil {
		return false, err
	}
	if count > 0 {
		return false, nil
	}

	if _, err := tx.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", username, passwordHash, "Admin"); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// DeriveSSHEncKey derives the AES-256 key for SSH key encryption from the session secret.
func DeriveSSHEncKey(sessionSecret string) [32]byte {
	return sha256.Sum256([]byte(sessionSecret + ":goacloud-ssh-keys"))
}

func (h *Handler) notifyLoginFailure(ip, username, reason string, attempt int, blocked bool) {
	// Read the live Discord bot from the registry at emit time (hot-reloadable, nil-safe).
	discord := h.Registry.Discord()
	if discord == nil || !discord.IsReady() {
		return
	}
	title := "Échec de connexion"
	msg := fmt.Sprintf("**IP:** `%s`\n**Utilisateur:** `%s`\n**Raison:** %s\n**Tentatives:** %d/5", ip, username, reason, attempt)
	if blocked {
		title = "⛔ IP Bloquée"
		msg += "\n\n> L'adresse IP a été bloquée pendant **15 minutes** suite à trop d'échecs."
	}
	discord.SendAuthAlert(title, msg, blocked)
}
