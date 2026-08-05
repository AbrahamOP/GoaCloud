package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"goacore/internal/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// Role filtering in the search palette.
//
// The palette answered every caller with the full index of the administration
// screens and their URLs. The screens themselves 403 a Viewer, but handing one
// the map (which admin surfaces exist, where) is a free reconnaissance step: a
// trainee or a contractor typing "a" learned that /ansible, /audit-logs and a
// web console exist on this instance. The palette must mirror the router's
// boundary, not advertise past it.
// ─────────────────────────────────────────────────────────────────────────────

const searchTestSessionSecret = "search-rbac-test-session-secret-0123456789"

// searchAs runs a palette query as a user carrying the given role and returns the
// page-type results.
func searchAs(t *testing.T, role, query string) []SearchResult {
	t.Helper()
	db, _ := newAuthFakeDB(t)
	store := sessions.NewCookieStore([]byte(searchTestSessionSecret))
	h := &Handler{DB: db, SessionStore: store, ProxmoxCache: &models.ProxmoxCache{}}

	req := httptest.NewRequest(http.MethodGet, "/api/search?q="+query, nil)
	// Seed the session exactly as AuthMiddleware does (it re-syncs the role from
	// the DB on every request, so this is the state the handler really sees).
	sess, _ := store.New(req, "goacloud-session")
	sess.Values["authenticated"] = true
	sess.Values["username"] = "u"
	sess.Values["role"] = role
	seed := httptest.NewRecorder()
	if err := sess.Save(req, seed); err != nil {
		t.Fatalf("save session: %v", err)
	}
	for _, c := range seed.Result().Cookies() {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	h.HandleSearch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("search as %s: got %d, want 200", role, rec.Code)
	}

	var all []SearchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatalf("search as %s: non-JSON body %q: %v", role, rec.Body.String(), err)
	}
	var pages []SearchResult
	for _, r := range all {
		if r.Type == "page" {
			pages = append(pages, r)
		}
	}
	return pages
}

func namesOf(results []SearchResult) map[string]string {
	out := map[string]string{}
	for _, r := range results {
		out[r.Name] = r.URL
	}
	return out
}

func TestSearch_ViewerDoesNotSeeAdminPages(t *testing.T) {
	// Every admin-only entry, queried by a substring that matches it.
	adminQueries := map[string]string{
		"Cles SSH":     "ssh",
		"Ansible":      "ansible",
		"Console Web":  "console",
		"Utilisateurs": "utilis",
		"Audit Logs":   "audit",
	}
	for name, query := range adminQueries {
		pages := searchAs(t, "Viewer", query)
		if url, found := namesOf(pages)[name]; found {
			t.Fatalf("a Viewer searching %q is told %q lives at %s — the palette leaks the admin map", query, name, url)
		}
		// Same query as an Admin MUST return it, otherwise the test would pass on
		// a palette that simply stopped indexing pages.
		if _, found := namesOf(searchAs(t, "Admin", query))[name]; !found {
			t.Fatalf("an Admin searching %q no longer finds %q — the filter is over-broad", query, name)
		}
	}
}

func TestSearch_ViewerKeepsReadOnlyPages(t *testing.T) {
	// The negative control: filtering must not blank the palette for a Viewer.
	// These pages are in the authenticated group — a Viewer can genuinely open them.
	readOnly := map[string]string{
		"Proxmox":          "proxmox",
		"Securite (Wazuh)": "wazuh",
		"SOAR":             "soar",
		"Profil":           "profil",
		"Applications":     "applications",
	}
	for name, query := range readOnly {
		if _, found := namesOf(searchAs(t, "Viewer", query))[name]; !found {
			t.Fatalf("a Viewer searching %q no longer finds %q — the read-only surface must stay searchable", query, name)
		}
	}
}

// TestSearch_UnknownRoleIsTreatedAsViewer: the filter is a whitelist on "Admin",
// so an empty or unexpected role degrades closed rather than open.
func TestSearch_UnknownRoleIsTreatedAsViewer(t *testing.T) {
	for _, role := range []string{"", "Operator", "admin"} {
		if _, found := namesOf(searchAs(t, role, "audit"))["Audit Logs"]; found {
			t.Fatalf("role %q sees the admin pages — the filter must only open for the exact \"Admin\" role", role)
		}
	}
}

// TestSearch_PageIndexMatchesRouterGroups guards the sync the filter depends on:
// every page the palette marks as reachable by a Viewer must NOT be one of the
// known admin paths, and vice versa. It is a cheap tripwire for the day a page is
// added to searchPages with the wrong flag.
func TestSearch_PageIndexMatchesRouterGroups(t *testing.T) {
	adminPaths := map[string]bool{
		"/ssh": true, "/ansible": true, "/console": true,
		"/users": true, "/audit-logs": true, "/backups": true,
	}
	for _, p := range searchPages {
		if adminPaths[p.url] && !p.adminOnly {
			t.Fatalf("%s (%s) is an Admin-only route but is indexed for everyone", p.name, p.url)
		}
		if !adminPaths[p.url] && p.adminOnly {
			t.Fatalf("%s (%s) is hidden from Viewers but is not an Admin-only route", p.name, p.url)
		}
	}
}
