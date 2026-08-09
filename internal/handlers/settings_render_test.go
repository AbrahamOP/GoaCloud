package handlers

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"goacore/internal/models"
)

// loadSettingsTemplates parses the on-disk template set exactly the way cmd/server
// boots it (same "json" FuncMap, same glob), so this test exercises the REAL parse +
// execute pipeline. The settings hub renders settings.html → {{template "settings-<section>"}}
// purely from the data map the handler builds; html/template only surfaces a missing
// define or a bad method/type call at EXECUTE time (build/vet stay green), so this is
// the one guard that catches a 500-on-render regression in any settings section.
func loadSettingsTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("").Funcs(TemplateFuncMap()).ParseGlob("../../assets/templates/*.html")
	if err != nil {
		t.Fatalf("parsing templates failed: %v", err)
	}
	return tmpl
}

// settingsScaffold mirrors the keys settingsBase always sets, so each case only adds
// its section-specific keys on top — the same contract the handlers honour.
func settingsScaffold(section, subtitle string, admin bool) map[string]any {
	return map[string]any{
		"Section":        section,
		"Active":         section,
		"IsAdmin":        admin,
		"HeaderSubtitle": subtitle,
		"User":           "alice",
		"Error":          "",
		"Success":        "",
	}
}

// TestSettingsHubSectionsRender executes settings.html for every section of the
// Paramètres hub with a data map built like the matching handler. A panic or a
// non-nil ExecuteTemplate error means the section would 500 in production; an empty
// body means the section dispatch silently rendered nothing.
func TestSettingsHubSectionsRender(t *testing.T) {
	tmpl := loadSettingsTemplates(t)

	card := func(svc, source, status string) serviceCardData {
		return serviceCardData{
			Service: svc, Source: source, Status: status, Configured: true,
			SecretPresent: true, CanRollback: true, Wired: true,
			URL: "https://192.0.2.20:9200", User: "admin",
		}
	}

	cases := []struct {
		name    string
		data    map[string]any
		wantStr string // a marker that must appear once the section body rendered
	}{
		{
			name: "profil",
			data: func() map[string]any {
				d := settingsScaffold("profil", "Gérez vos informations personnelles.", false)
				d["Username"] = "alice"
				d["Email"] = "alice@example.com"
				d["Role"] = "Viewer"
				d["GithubURL"] = "https://github.com/alice"
				return d
			}(),
			wantStr: "alice@example.com",
		},
		{
			name: "securite",
			data: func() map[string]any {
				d := settingsScaffold("securite", "Protégez l'accès à votre compte.", false)
				d["MFAEnabled"] = false
				return d
			}(),
			// Marqueur EXCLUSIF au corps de la section (settings-securite), surtout PAS
			// "Paramètres" qui est rendu inconditionnellement par le header/title du
			// scaffold AVANT le dispatch : sinon le test resterait vert même si la
			// section securite ne rendait rien (régression 500/section-vide non détectée).
			wantStr: "Authentification à deux facteurs",
		},
		{
			name: "services",
			data: func() map[string]any {
				d := settingsScaffold("services", "Reliez GoaCore à vos services.", true)
				d["WazuhIndexer"] = card("wazuh-indexer", "db", "ok")
				d["Wazuh"] = card("wazuh", "env", "unknown")
				d["AI"] = card("ai", "unconfigured", "unknown")
				d["Discord"] = card("discord", "unconfigured", "unknown")
				d["Selected"] = "wazuh-indexer"
				return d
			}(),
			wantStr: "192.0.2.20",
		},
		{
			name: "utilisateurs",
			data: func() map[string]any {
				d := settingsScaffold("utilisateurs", "Gérez les comptes et les accès.", true)
				d["Users"] = []models.User{
					{ID: 1, Username: "alice", Email: "alice@example.com", Role: "Admin", CreatedAt: "2026-01-01"},
					{ID: 2, Username: "bob", Email: "bob@example.com", Role: "Viewer", CreatedAt: "2026-02-02"},
				}
				return d
			}(),
			wantStr: "bob@example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, "settings.html", tc.data); err != nil {
				t.Fatalf("section %q failed to render: %v", tc.name, err)
			}
			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("section %q rendered an empty body", tc.name)
			}
			if !strings.Contains(out, tc.wantStr) {
				t.Fatalf("section %q body missing expected marker %q (dispatch likely rendered the wrong/no section)", tc.name, tc.wantStr)
			}
		})
	}
}

// TestSettingsAccountSecurityUI pins the entry points the account sections MUST
// expose. Each assertion below stands for a feature that existed only in the
// router before: the hardened /api/mfa/disable rejects a body-less POST (so the
// page needs a proof field), /logout-all and /api/users/reset-mfa were reachable
// by hand only, and the activation toast was destroyed by an immediate reload.
func TestSettingsAccountSecurityUI(t *testing.T) {
	tmpl := loadSettingsTemplates(t)

	render := func(t *testing.T, data map[string]any) string {
		t.Helper()
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, "settings.html", data); err != nil {
			t.Fatalf("render: %v", err)
		}
		return buf.String()
	}

	t.Run("securite", func(t *testing.T) {
		d := settingsScaffold("securite", "Protégez l'accès à votre compte.", false)
		d["MFAEnabled"] = true
		out := render(t, d)

		for _, want := range []string{
			`id="mfa-disable-proof"`, // the password / TOTP proof the API demands
			`application/json`,       // the disable call now carries a JSON body
			`action="/logout-all"`,   // "déconnecter toutes mes sessions"
			`reloadAfterToast`,       // the confirmation survives long enough to be read
		} {
			if !strings.Contains(out, want) {
				t.Errorf("securite section is missing %q", want)
			}
		}
		// The old body-less call is exactly what the hardened endpoint 400s on.
		if strings.Contains(out, "'/api/mfa/disable', { method: 'POST' }") {
			t.Error("the disable button still POSTs without a body — the endpoint rejects it with a 400")
		}
		// A single reload site (inside reloadAfterToast): any other occurrence is an
		// immediate reload that would wipe the toast before it is seen.
		if n := strings.Count(out, "window.location.reload"); n != 1 {
			t.Errorf("%d reload sites in the securite section, want 1 (the delayed one)", n)
		}
		// The candidate secret is server-side state now; the page must not post one.
		if strings.Contains(out, `id="temp-secret"`) {
			t.Error("the page still carries a client-side candidate secret for /api/mfa/verify")
		}
	})

	t.Run("utilisateurs", func(t *testing.T) {
		users := []models.User{{ID: 1, Username: "alice", Email: "a@example.com", Role: "Admin", CreatedAt: "2026-01-01"}}

		d := settingsScaffold("utilisateurs", "Gérez les comptes et les accès.", true)
		d["Users"] = users
		if out := render(t, d); !strings.Contains(out, `action="/api/users/reset-mfa"`) {
			t.Error("an Admin has no way to reset a locked-out user's 2FA")
		}

		d = settingsScaffold("utilisateurs", "Gérez les comptes et les accès.", false)
		d["Users"] = users
		if out := render(t, d); strings.Contains(out, `action="/api/users/reset-mfa"`) {
			t.Error("the MFA reset action is offered to a non-Admin")
		}
	})
}

// TestRechromedOnboardingPagesRender extends the anti-500 guard to the two onboarding
// pages re-chromed into the Paramètres hub: onboarding-proxmox.html (/parametres/proxmox)
// and onboarding-canal.html (/parametres/sauvegarde). They are NOT settings.html sections
// — they render their own scaffold but now include {{template "settings-nav" .}}, so they
// MUST carry the hub chrome keys (Active/IsAdmin/HeaderSubtitle) or settings-nav breaks.
// The data maps below mirror renderOnboardingProxmox / renderChannel exactly.
func TestRechromedOnboardingPagesRender(t *testing.T) {
	tmpl := loadSettingsTemplates(t)

	cases := []struct {
		name     string
		template string
		data     map[string]any
		wantStr  string
	}{
		{
			name:     "proxmox",
			template: "onboarding-proxmox.html",
			data: map[string]any{
				"URL": "https://192.0.2.10:8006", "Node": "node", "TokenID": "id@pam!t",
				"Storage": "local", "Bridge": "vmbr0", "SandboxBridge": "vmbr1",
				"SandboxVlan": 99, "RestoreStorage": "local", "CryptRemote": "gcrypt:",
				"SecretPresent": true, "Configured": true, "Source": "db",
				"EnvImportable": false, "EnvPresent": false, "CanRollback": true,
				"Error": "", "Success": "", "User": "alice",
				"Active": "proxmox", "IsAdmin": true,
				"HeaderSubtitle": "Reliez GoaCore à votre hyperviseur Proxmox VE.",
			},
			wantStr: "Proxmox",
		},
		{
			name:     "canal",
			template: "onboarding-canal.html",
			data: map[string]any{
				"User": "alice", "Error": "", "Success": "",
				"Channel": channelCardData{
					Configured: true, Source: "db", Status: "ok", SecretPresent: true,
					Host: "192.0.2.10", User: "goabackup", Fingerprint: "SHA256:abc",
					KeyType: "ssh-ed25519", HasInAppKey: true,
				},
				"InstallerURL": "https://192.0.2.20:8443/api/onboarding/canal/installer.sh",
				"ChannelUser":  "goabackup", "RevokeCommand": "rm -f ~goabackup/.ssh/authorized_keys",
				"Active": "sauvegarde", "IsAdmin": true,
				"HeaderSubtitle": "Canal de sauvegarde et stockage cloud (off-site).",
			},
			wantStr: "sauvegarde",
		},
		{
			name:     "audit",
			template: "audit_logs.html",
			data: map[string]any{
				"Username": "alice", "Role": "Admin", "Active": "audit", "IsAdmin": true,
				"HeaderSubtitle": "Journal d'activité et événements de sécurité.",
				"Logs": []map[string]any{
					{"ID": 1, "Username": "alice", "Action": "Login", "Details": "ok", "IPAddress": "192.0.2.5", "CreatedAt": "2026-06-26"},
				},
			},
			wantStr: "Journal",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, tc.template, tc.data); err != nil {
				t.Fatalf("re-chromed page %q failed to render: %v", tc.template, err)
			}
			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("re-chromed page %q rendered an empty body", tc.template)
			}
			// settings-nav is the shared hub chrome the re-chrome introduced; its presence
			// proves the page carries the chrome keys without a render error.
			if !strings.Contains(out, "/parametres/services") {
				t.Fatalf("re-chromed page %q missing the hub nav (settings-nav not rendered — chrome keys likely absent)", tc.template)
			}
			if !strings.Contains(strings.ToLower(out), strings.ToLower(tc.wantStr)) {
				t.Fatalf("re-chromed page %q body missing expected marker %q", tc.template, tc.wantStr)
			}
		})
	}
}
