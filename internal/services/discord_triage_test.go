package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"
)

const testFP = "abababababababababababababababababababababababababababababababab"

// TestTriageCustomIDRoundTrip : le custom_id est le seul lien entre un clic et
// une empreinte — il doit survivre à l'aller-retour et rester sous la limite
// Discord de 100 caractères pour chacun des quatre verdicts.
func TestTriageCustomIDRoundTrip(t *testing.T) {
	for _, status := range []string{TriageByDesign, TriageFalsePositive, TriageInvestigating, TriageResolved} {
		id := triageCustomID(status, testFP)
		if len(id) > 100 {
			t.Errorf("custom_id %q dépasse la limite Discord de 100 caractères (%d)", id, len(id))
		}
		gotStatus, gotFP, ok := parseTriageCustomID(id)
		if !ok || gotStatus != status || gotFP != testFP {
			t.Errorf("aller-retour cassé pour %q : (%q, %q, %v)", status, gotStatus, gotFP, ok)
		}
	}
}

// TestParseTriageCustomIDRejects : le custom_id revient du client Discord
// (entrée non fiable) — tout id forgé ou étranger doit être ignoré sans effet.
func TestParseTriageCustomIDRejects(t *testing.T) {
	for _, id := range []string{
		"",
		"autre:by_design:" + testFP,                   // pas notre préfixe
		"triage:" + testFP,                            // pas de statut
		"triage:open:" + testFP,                       // open n'est pas un verdict
		"triage:by_design:",                           // empreinte vide
		"triage:by_design:" + testFP[:63],             // empreinte trop courte
		"triage:by_design:" + testFP + "a",            // trop longue
		"triage:BY_DESIGN:" + testFP,                  // statut inconnu (casse)
		"triage:by_design:" + strings.ToUpper(testFP), // hex majuscule
	} {
		if _, _, ok := parseTriageCustomID(id); ok {
			t.Errorf("custom_id forgé accepté : %q", id)
		}
	}
}

// containerOf extrait le Container unique d'un arbre de composants d'alerte.
func containerOf(t *testing.T, comps []discordgo.MessageComponent) *discordgo.Container {
	t.Helper()
	if len(comps) != 1 {
		t.Fatalf("attendu 1 composant racine, reçu %d", len(comps))
	}
	c := asContainer(comps[0])
	if c == nil {
		t.Fatalf("racine inattendue %T, attendu Container", comps[0])
	}
	return c
}

// buttonsOf extrait les boutons de l'unique ActionsRow d'un Container ("" si absente).
func buttonsOf(t *testing.T, cont *discordgo.Container) []discordgo.Button {
	t.Helper()
	var rows []discordgo.ActionsRow
	for _, ic := range cont.Components {
		switch v := ic.(type) {
		case discordgo.ActionsRow:
			rows = append(rows, v)
		case *discordgo.ActionsRow:
			rows = append(rows, *v)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if len(rows) > 1 {
		t.Fatalf("attendu au plus 1 ActionsRow, reçu %d", len(rows))
	}
	var out []discordgo.Button
	for _, bc := range rows[0].Components {
		switch b := bc.(type) {
		case discordgo.Button:
			out = append(out, b)
		case *discordgo.Button:
			out = append(out, *b)
		}
	}
	return out
}

// textContents liste les contenus des TextDisplay d'un Container.
func textContents(cont *discordgo.Container) []string {
	var out []string
	for _, ic := range cont.Components {
		switch v := ic.(type) {
		case discordgo.TextDisplay:
			out = append(out, v.Content)
		case *discordgo.TextDisplay:
			out = append(out, v.Content)
		}
	}
	return out
}

// TestSoarAlertComponentsTriageButtons : une alerte avec empreinte porte les
// quatre boutons de triage aux custom_id attendus ; sans empreinte (alerte de
// test), l'arbre reste celui d'avant le triage — aucun bouton.
func TestSoarAlertComponentsTriageButtons(t *testing.T) {
	withFP := soarAlertComponents(soarAlertView{
		Title: "Alerte", Message: "msg", Severity: "high", Fingerprint: testFP,
	})
	buttons := buttonsOf(t, containerOf(t, withFP))
	if len(buttons) != 4 {
		t.Fatalf("attendu 4 boutons, reçu %d", len(buttons))
	}
	wantIDs := []string{
		"triage:by_design:" + testFP,
		"triage:false_positive:" + testFP,
		"triage:investigating:" + testFP,
		"triage:resolved:" + testFP,
	}
	for i, b := range buttons {
		if b.CustomID != wantIDs[i] {
			t.Errorf("bouton %d : custom_id %q, attendu %q", i, b.CustomID, wantIDs[i])
		}
		if b.Style != discordgo.SecondaryButton {
			t.Errorf("bouton %d : style %v, attendu Secondary pour une alerte non classée", i, b.Style)
		}
	}

	sans := soarAlertComponents(soarAlertView{Title: "Alerte", Message: "msg", Severity: "high"})
	if got := buttonsOf(t, containerOf(t, sans)); got != nil {
		t.Fatalf("une alerte sans empreinte porte %d bouton(s)", len(got))
	}
}

// TestSoarAlertComponentsClassified : une alerte déjà classée au rendu (post ou
// ré-édition d'enrichissement) porte l'étiquette, la couleur du statut, et le
// bouton du verdict marqué — le classement ne doit pas s'effacer à l'édition IA.
func TestSoarAlertComponentsClassified(t *testing.T) {
	comps := soarAlertComponents(soarAlertView{
		Title: "Alerte", Message: "msg", Severity: "critical", Analysis: "analyse",
		Fingerprint: testFP, TriageStatus: TriageByDesign, DecidedBy: "abraham",
	})
	cont := containerOf(t, comps)

	if cont.AccentColor == nil || *cont.AccentColor != 0x808080 {
		t.Errorf("couleur %v, attendu le gris by_design (0x808080)", cont.AccentColor)
	}
	var label string
	for _, txt := range textContents(cont) {
		if strings.HasPrefix(txt, triageLabelPrefix) {
			label = txt
		}
	}
	if !strings.Contains(label, "By design") || !strings.Contains(label, "abraham") {
		t.Errorf("étiquette %q : attendu le verdict et le décideur", label)
	}
	var selected int
	for _, b := range buttonsOf(t, cont) {
		if b.Style == discordgo.PrimaryButton {
			selected++
			if wantID := "triage:by_design:" + testFP; b.CustomID != wantID {
				t.Errorf("bouton marqué %q, attendu %q", b.CustomID, wantID)
			}
		}
	}
	if selected != 1 {
		t.Errorf("%d bouton(s) marqué(s), attendu exactement 1", selected)
	}
}

// gatewayRoundTrip simule la livraison d'un arbre par le gateway Discord :
// marshal JSON puis désérialisation discordgo — qui produit des POINTEURS
// (*Container, *TextDisplay…) là où notre construction produit des valeurs.
func gatewayRoundTrip(t *testing.T, comps []discordgo.MessageComponent) []discordgo.MessageComponent {
	t.Helper()
	out := make([]discordgo.MessageComponent, 0, len(comps))
	for _, c := range comps {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		mc, err := discordgo.MessageComponentFromJSON(raw)
		if err != nil {
			t.Fatalf("unmarshal gateway: %v", err)
		}
		out = append(out, mc)
	}
	return out
}

// TestRetagSoarComponentsGatewayRoundTrip : au clic, l'arbre reçu du gateway
// (pointeurs) est reconstruit — étiquette posée, boutons remplacés avec le
// verdict marqué, Container recoloré, textes d'origine intacts. C'est le chemin
// réel du handler d'interaction.
func TestRetagSoarComponentsGatewayRoundTrip(t *testing.T) {
	original := soarAlertComponents(soarAlertView{
		Title: "SSH brute force", Message: "**Machine:** srv", Severity: "high",
		Analysis: "analyse IA", Fingerprint: testFP,
	})
	received := gatewayRoundTrip(t, original)

	retagged := retagSoarComponents(received, TriageFalsePositive, "abraham", testFP)
	cont := containerOf(t, retagged)

	if cont.AccentColor == nil || *cont.AccentColor != 0x808080 {
		t.Errorf("couleur %v après classement faux positif, attendu 0x808080", cont.AccentColor)
	}

	texts := textContents(cont)
	joined := strings.Join(texts, "\n")
	for _, want := range []string{"SSH brute force", "**Machine:** srv", "analyse IA"} {
		if !strings.Contains(joined, want) {
			t.Errorf("texte d'origine %q perdu au retag", want)
		}
	}
	var labels int
	for _, txt := range texts {
		if strings.HasPrefix(txt, triageLabelPrefix) {
			labels++
			if !strings.Contains(txt, "Faux positif") {
				t.Errorf("étiquette %q sans le verdict", txt)
			}
		}
	}
	if labels != 1 {
		t.Fatalf("%d étiquette(s) de statut, attendu 1", labels)
	}

	var selected string
	for _, b := range buttonsOf(t, cont) {
		if b.Style == discordgo.PrimaryButton {
			selected = b.CustomID
		}
	}
	if want := "triage:false_positive:" + testFP; selected != want {
		t.Errorf("bouton marqué %q, attendu %q", selected, want)
	}

	// Reclassement (correction d'un mauvais clic) : le retag doit être
	// idempotent — une seule étiquette, une seule rangée de boutons.
	reretagged := retagSoarComponents(gatewayRoundTrip(t, retagged), TriageInvestigating, "abraham", testFP)
	cont2 := containerOf(t, reretagged)
	labels = 0
	for _, txt := range textContents(cont2) {
		if strings.HasPrefix(txt, triageLabelPrefix) {
			labels++
			if !strings.Contains(txt, "Enquête en cours") {
				t.Errorf("étiquette après reclassement : %q", txt)
			}
		}
	}
	if labels != 1 {
		t.Fatalf("%d étiquette(s) après reclassement, attendu 1 (accumulation)", labels)
	}
	if got := len(buttonsOf(t, cont2)); got != 4 {
		t.Fatalf("%d bouton(s) après reclassement, attendu 4", got)
	}
	if cont2.AccentColor == nil || *cont2.AccentColor != 0x3498db {
		t.Errorf("couleur %v après « j'enquête », attendu 0x3498db", cont2.AccentColor)
	}
}

// TestTriageDigestComponents : le digest détaille au plus 10 empreintes, agrège
// le reste, et neutralise les textes issus de Wazuh (titre/agent non fiables).
func TestTriageDigestComponents(t *testing.T) {
	rows := make([]TriageDigestRow, 0, 12)
	for i := 0; i < 12; i++ {
		status := TriageByDesign
		if i == 0 {
			status = TriageOpen // rouverte par récidive APRÈS ses suppressions
		}
		rows = append(rows, TriageDigestRow{
			Fingerprint: testFP, RuleID: "5710", AgentName: "srv",
			Title: "@everyone alerte", Status: status,
			SinceDigest: 12 - i, TotalSuppressed: 20,
		})
	}
	cont := containerOf(t, triageDigestComponents(rows))
	joined := strings.Join(textContents(cont), "\n")

	// total = 12+11+…+1 = 78 ; reste agrégé = 2+1 = 3 sur 2 empreintes.
	if !strings.Contains(joined, "**78**") || !strings.Contains(joined, "**12**") {
		t.Errorf("totaux absents du digest :\n%s", joined)
	}
	if !strings.Contains(joined, "2 autre(s) empreinte(s), 3 suppression(s)") {
		t.Errorf("ligne d'agrégat absente :\n%s", joined)
	}
	if !strings.Contains(joined, "20 au total") {
		t.Errorf("total vie-entière absent :\n%s", joined)
	}
	if !strings.Contains(joined, "réouverte") {
		t.Errorf("une row rouverte (open) doit être étiquetée « réouverte », pas vide :\n%s", joined)
	}
	if strings.Contains(joined, "@everyone") {
		t.Error("mention @everyone non neutralisée dans le digest")
	}
}
