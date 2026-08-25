package services

import (
	"strings"
	"testing"
)

// mkAlert fabrique une WazuhAlert de test (IP fictives RFC5737).
func mkAlert(ruleID, agentName, desc, path, dstUser string) WazuhAlert {
	var a WazuhAlert
	a.Rule.ID = ruleID
	a.Rule.Description = desc
	a.Agent.Name = agentName
	a.Agent.IP = "192.0.2.10"
	a.Syscheck.Path = path
	a.Data.DstUser = dstUser
	a.Data.SrcIP = "192.0.2.77"
	return a
}

// TestTriageFingerprintFormat verrouille le format de l'empreinte : 64 hex
// minuscules, déterministe. C'est le contrat des custom_id Discord (validation
// par isTriageFingerprint) et de la clé primaire soar_triage (CHAR(64)).
func TestTriageFingerprintFormat(t *testing.T) {
	a := mkAlert("5710", "srv", "sshd auth failed", "", "")
	fp := TriageFingerprint(a)
	if len(fp) != 64 {
		t.Fatalf("empreinte de longueur %d, attendu 64", len(fp))
	}
	if !isTriageFingerprint(fp) {
		t.Fatalf("l'empreinte produite %q n'est pas acceptée par isTriageFingerprint", fp)
	}
	if fp != TriageFingerprint(a) {
		t.Fatal("empreinte non déterministe pour une même alerte")
	}
}

// TestTriageFingerprintFamilies verrouille le champ-clé par famille de règle :
// un « by design » doit viser exactement ce que l'opérateur regarde (le fichier
// pour la FIM, le compte pour l'auth) — jamais plus large (sur-suppression =
// alerte réelle avalée), jamais plus étroit (le classement ne supprime rien).
func TestTriageFingerprintFamilies(t *testing.T) {
	cases := []struct {
		name      string
		a, b      WazuhAlert
		wantEqual bool
	}{
		{
			name:      "FIM : chemins différents = empreintes différentes",
			a:         mkAlert("550", "srv", "Integrity checksum changed.", "/etc/passwd", ""),
			b:         mkAlert("550", "srv", "Integrity checksum changed.", "/etc/shadow", ""),
			wantEqual: false,
		},
		{
			name:      "FIM : même chemin = même empreinte",
			a:         mkAlert("550", "srv", "Integrity checksum changed.", "/etc/passwd", ""),
			b:         mkAlert("550", "srv", "Integrity checksum changed.", "/etc/passwd", ""),
			wantEqual: true,
		},
		{
			name:      "FIM : la casse d'un chemin compte (fichiers distincts sous Linux)",
			a:         mkAlert("553", "srv", "File deleted.", "/opt/App/config", ""),
			b:         mkAlert("553", "srv", "File deleted.", "/opt/app/config", ""),
			wantEqual: false,
		},
		{
			name:      "auth : l'IP source ne discrimine PAS (elle varie légitimement)",
			a:         withSrcIP(mkAlert("5710", "srv", "sshd: attempt to login using a non-existent user", "", "backup"), "192.0.2.1"),
			b:         withSrcIP(mkAlert("5710", "srv", "sshd: attempt to login using a non-existent user", "", "backup"), "192.0.2.2"),
			wantEqual: true,
		},
		{
			name:      "auth : le compte visé discrimine",
			a:         mkAlert("5710", "srv", "sshd: attempt to login using a non-existent user", "", "backup"),
			b:         mkAlert("5710", "srv", "sshd: attempt to login using a non-existent user", "", "root"),
			wantEqual: false,
		},
		{
			name:      "sudo : le compte QUI élève discrimine (srcuser)",
			a:         withSrcUser(mkAlert("5402", "srv", "Successful sudo to ROOT executed.", "", "root"), "abraham"),
			b:         withSrcUser(mkAlert("5402", "srv", "Successful sudo to ROOT executed.", "", "root"), "www-data"),
			wantEqual: false,
		},
		{
			name:      "sudo : dstuser (toujours root) ne discrimine PAS — sinon un by_design muterait toutes les élévations de l'agent",
			a:         withSrcUser(mkAlert("5402", "srv", "Successful sudo to ROOT executed.", "", "root"), "abraham"),
			b:         withSrcUser(mkAlert("5402", "srv", "Successful sudo to ROOT executed.", "", "abraham"), "abraham"),
			wantEqual: true,
		},
		{
			name:      "agents différents = empreintes différentes (le classement est par machine)",
			a:         mkAlert("2902", "srv-a", "New dpkg (Debian Package) installed.", "", ""),
			b:         mkAlert("2902", "srv-b", "New dpkg (Debian Package) installed.", "", ""),
			wantEqual: false,
		},
		{
			name:      "règles différentes = empreintes différentes",
			a:         mkAlert("2902", "srv", "same description", "", ""),
			b:         mkAlert("2903", "srv", "same description", "", ""),
			wantEqual: false,
		},
		{
			name:      "famille auth sans dstuser (vieux mapping) : repli sur la description",
			a:         mkAlert("5710", "srv", "sshd auth failed", "", ""),
			b:         mkAlert("5710", "srv", "sshd auth failed", "", ""),
			wantEqual: true,
		},
		{
			name:      "hors familles : la description discrimine",
			a:         mkAlert("9999", "srv", "custom rule A", "", ""),
			b:         mkAlert("9999", "srv", "custom rule B", "", ""),
			wantEqual: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fa, fb := TriageFingerprint(tc.a), TriageFingerprint(tc.b)
			if (fa == fb) != tc.wantEqual {
				t.Errorf("empreintes a=%s b=%s, égalité attendue: %v", fa, fb, tc.wantEqual)
			}
		})
	}
}

func withSrcIP(a WazuhAlert, ip string) WazuhAlert {
	a.Data.SrcIP = ip
	return a
}

func withSrcUser(a WazuhAlert, u string) WazuhAlert {
	a.Data.SrcUser = u
	return a
}

// TestTriageFingerprintWhitespace : la normalisation ne porte QUE sur les
// espaces (trim + réduction), pour qu'une variation d'espacement dans une
// description Wazuh ne fasse pas muter l'empreinte — sans casse-folding.
func TestTriageFingerprintWhitespace(t *testing.T) {
	a := mkAlert("9999", "srv", "  sshd:   auth  failed ", "", "")
	b := mkAlert("9999", "srv", "sshd: auth failed", "", "")
	if TriageFingerprint(a) != TriageFingerprint(b) {
		t.Fatal("une variation d'espaces dans la description change l'empreinte")
	}
	c := mkAlert("9999", "srv", "SSHD: AUTH FAILED", "", "")
	if TriageFingerprint(b) == TriageFingerprint(c) {
		t.Fatal("le casse-folding ne doit pas être appliqué (deux textes distincts fusionnés)")
	}
}

// TestTriageAgentStatusFingerprint : chaque direction (perdu/retrouvé) a sa
// propre empreinte — classer « by design » la perte d'un agent ne doit jamais
// supprimer implicitement son retour.
func TestTriageAgentStatusFingerprint(t *testing.T) {
	lost := TriageAgentStatusFingerprint("worker-ct", "disconnected")
	back := TriageAgentStatusFingerprint("worker-ct", "active")
	if lost == back {
		t.Fatal("perte et retour d'agent partagent une empreinte")
	}
	if lost != TriageAgentStatusFingerprint("worker-ct", "disconnected") {
		t.Fatal("empreinte de statut non déterministe")
	}
	if !isTriageFingerprint(lost) || !isTriageFingerprint(back) {
		t.Fatal("empreinte de statut au mauvais format")
	}
	other := TriageAgentStatusFingerprint("autre-machine", "disconnected")
	if lost == other {
		t.Fatal("deux agents distincts partagent une empreinte de statut")
	}
}

// TestTriageStatusSuppresses verrouille QUELS verdicts suppriment : uniquement
// les deux « bruit ». « investigating » et « resolved » continuent de poster —
// une récidive pendant ou après traitement est une information.
func TestTriageStatusSuppresses(t *testing.T) {
	for status, want := range map[string]bool{
		TriageByDesign:      true,
		TriageFalsePositive: true,
		TriageInvestigating: false,
		TriageResolved:      false,
		TriageOpen:          false,
		"":                  false,
		"garbage":           false,
	} {
		if got := TriageStatusSuppresses(status); got != want {
			t.Errorf("TriageStatusSuppresses(%q) = %v, attendu %v", status, got, want)
		}
	}
}

// TestValidTriageDecision : « open » est l'état par défaut, jamais un verdict
// assignable depuis un bouton (un custom_id forgé "triage:open:…" doit être rejeté).
func TestValidTriageDecision(t *testing.T) {
	for _, s := range []string{TriageByDesign, TriageFalsePositive, TriageInvestigating, TriageResolved} {
		if !validTriageDecision(s) {
			t.Errorf("verdict légitime %q rejeté", s)
		}
	}
	for _, s := range []string{TriageOpen, "", "root", "by-design"} {
		if validTriageDecision(s) {
			t.Errorf("%q accepté comme verdict", s)
		}
	}
}

// TestIsTriageFingerprint : l'empreinte revient dans un custom_id contrôlé par
// le client Discord — tout ce qui n'est pas 64 hex minuscules est rejeté.
func TestIsTriageFingerprint(t *testing.T) {
	valid := strings.Repeat("ab12", 16)
	if !isTriageFingerprint(valid) {
		t.Fatalf("%q rejeté à tort", valid)
	}
	for _, s := range []string{
		"",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("A", 64),          // hex majuscule : pas notre format
		strings.Repeat("g", 64),          // hors alphabet hex
		strings.Repeat("a", 60) + "'--x", // tentative d'injection
		strings.Repeat("a", 62) + "é",    // multibyte
	} {
		if isTriageFingerprint(s) {
			t.Errorf("%q accepté à tort", s)
		}
	}
}
