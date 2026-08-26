package services

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/bwmarrin/discordgo"
)

// Triage SOAR côté Discord : chaque alerte porte quatre boutons (By design /
// Faux positif / J'enquête / Résolu). Un clic enregistre le verdict en DB
// (TriageStore.SetDecision) puis ré-édite le message cliqué via la réponse
// d'interaction UpdateMessage : Container recoloré, étiquette de statut, boutons
// reconstruits avec le choix marqué. L'arbre Components V2 étant remplacé en
// entier à chaque édition, la reconstruction part des composants du message reçu
// dans l'interaction — jamais d'état à persister côté serveur pour re-rendre.

const (
	// triageCustomIDPrefix préfixe les custom_id des boutons : "triage:<status>:<fingerprint>".
	triageCustomIDPrefix = "triage:"
	// triageLabelPrefix ouvre la ligne d'étiquette de statut dans le message ; il
	// sert aussi de marqueur pour la retrouver (et la remplacer) au clic suivant.
	triageLabelPrefix = "-# 🏷️ "
)

// triageCustomID builds the custom_id of one triage button. 22 chars de préfixe +
// statut + 64 hex restent sous la limite Discord de 100.
func triageCustomID(status, fingerprint string) string {
	return triageCustomIDPrefix + status + ":" + fingerprint
}

// parseTriageCustomID splits "triage:<status>:<fingerprint>". Le custom_id
// revient du client Discord (entrée non fiable) : tout id qui n'est pas
// exactement un verdict connu portant une empreinte plausible est rejeté.
func parseTriageCustomID(id string) (status, fingerprint string, ok bool) {
	rest, found := strings.CutPrefix(id, triageCustomIDPrefix)
	if !found {
		return "", "", false
	}
	status, fingerprint, found = strings.Cut(rest, ":")
	if !found || !validTriageDecision(status) || !isTriageFingerprint(fingerprint) {
		return "", "", false
	}
	return status, fingerprint, true
}

// triageStatusName is the operator-facing French name of a triage status.
func triageStatusName(status string) string {
	switch status {
	case TriageByDesign:
		return "By design"
	case TriageFalsePositive:
		return "Faux positif"
	case TriageInvestigating:
		return "Enquête en cours"
	case TriageResolved:
		return "Résolue"
	}
	return ""
}

// triageStatusLabel renders the status line shown under a classified alert
// ("" pour une alerte non classée). decidedBy est un username Discord (non
// fiable) → neutralisé ici, l'unique point de rendu.
func triageStatusLabel(status, decidedBy string) string {
	name := triageStatusName(status)
	if name == "" {
		return ""
	}
	if decidedBy != "" {
		return triageLabelPrefix + name + " — classée par " + truncateRunes(neutralizeDiscord(decidedBy), 80)
	}
	return triageLabelPrefix + name
}

// triageStatusColor returns the Container accent color of a classified alert.
// ok=false pour "open"/"" : la couleur de sévérité d'origine reste.
func triageStatusColor(status string) (int, bool) {
	switch status {
	case TriageByDesign, TriageFalsePositive:
		return 0x8B8D98, true // gris : bruit classé, volontairement éteint
	case TriageInvestigating:
		return 0x3E63DD, true // bleu : pris en charge
	case TriageResolved:
		return 0x1D9E75, true // vert Goa : traité
	}
	return 0, false
}

// triageButtonsRow builds the four triage buttons of an alert. selected marque
// le verdict courant (style Primary) ; tous les boutons restent actifs pour
// permettre de corriger un clic.
func triageButtonsRow(fingerprint, selected string) discordgo.ActionsRow {
	mk := func(label, status string) discordgo.Button {
		style := discordgo.SecondaryButton
		if status == selected {
			style = discordgo.PrimaryButton
		}
		return discordgo.Button{Label: label, Style: style, CustomID: triageCustomID(status, fingerprint)}
	}
	return discordgo.ActionsRow{Components: []discordgo.MessageComponent{
		mk("By design", TriageByDesign),
		mk("Faux positif", TriageFalsePositive),
		mk("J'enquête", TriageInvestigating),
		mk("Résolu", TriageResolved),
	}}
}

// asContainer normalizes the two shapes a Container takes: value when built
// locally, pointer when unmarshaled from a gateway payload (discordgo produces
// pointers). Returns a copy, nil si le composant n'est pas un Container.
func asContainer(c discordgo.MessageComponent) *discordgo.Container {
	switch v := c.(type) {
	case discordgo.Container:
		cc := v
		return &cc
	case *discordgo.Container:
		cc := *v
		return &cc
	}
	return nil
}

// isActionsRow matches both the value and pointer shapes of an ActionsRow.
func isActionsRow(c discordgo.MessageComponent) bool {
	switch c.(type) {
	case discordgo.ActionsRow, *discordgo.ActionsRow:
		return true
	}
	return false
}

// isTriageLabel reports whether a component is the triage status line.
func isTriageLabel(c discordgo.MessageComponent) bool {
	switch v := c.(type) {
	case discordgo.TextDisplay:
		return strings.HasPrefix(v.Content, triageLabelPrefix)
	case *discordgo.TextDisplay:
		return strings.HasPrefix(v.Content, triageLabelPrefix)
	}
	return false
}

// retagSoarComponents rebuilds an alert's component tree after a triage click:
// Container recoloré, étiquette de statut remplacée, boutons reconstruits avec
// le verdict marqué. Tout le reste (titre, message, analyse IA, séparateurs) est
// conservé tel quel — c'est ce qui rend l'opération idempotente et sûre quel que
// soit l'état du message (brut ou déjà enrichi, déjà classé ou non).
func retagSoarComponents(existing []discordgo.MessageComponent, status, decidedBy, fingerprint string) []discordgo.MessageComponent {
	out := make([]discordgo.MessageComponent, 0, len(existing))
	for _, c := range existing {
		cont := asContainer(c)
		if cont == nil {
			out = append(out, c)
			continue
		}
		inner := make([]discordgo.MessageComponent, 0, len(cont.Components)+2)
		for _, ic := range cont.Components {
			if isActionsRow(ic) || isTriageLabel(ic) {
				continue
			}
			inner = append(inner, ic)
		}
		if label := triageStatusLabel(status, decidedBy); label != "" {
			inner = append(inner, discordgo.TextDisplay{Content: label})
		}
		inner = append(inner, triageButtonsRow(fingerprint, status))

		color := cont.AccentColor
		if c2, ok := triageStatusColor(status); ok {
			color = &c2
		}
		out = append(out, discordgo.Container{AccentColor: color, Spoiler: cont.Spoiler, Components: inner})
	}
	return out
}

// interactionUser extracts the clicking user (guild member en salon, user en
// DM). Le username est une entrée non fiable, neutralisée au rendu ; l'ID est
// l'identifiant Discord immuable, gardé pour la traçabilité (un username se
// change à volonté).
func interactionUser(i *discordgo.InteractionCreate) (username, id string) {
	if i.Member != nil && i.Member.User != nil {
		return i.Member.User.Username, i.Member.User.ID
	}
	if i.User != nil {
		return i.User.Username, i.User.ID
	}
	return "", ""
}

// canTriage dit si le cliqueur a le droit de classer des alertes. Un verdict
// « by design » ÉTEINT des alertes de sécurité : le simple accès en lecture au
// canal ne suffit pas. Barre retenue : la permission « Gérer les messages » sur
// le canal d'alertes (le payload d'interaction porte les permissions calculées
// du membre dans le canal) — le modérateur du canal est l'opérateur. En DM
// (pas de Member), refus.
func canTriage(i *discordgo.InteractionCreate) bool {
	return i.Member != nil && i.Member.Permissions&discordgo.PermissionManageMessages != 0
}

// respondEphemeral répond au clic par un message visible du seul cliqueur.
func respondEphemeral(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: msg,
			Flags:   discordgo.MessageFlagsEphemeral,
		},
	}); err != nil {
		slog.Error("SOAR triage: réponse éphémère impossible", "error", err)
	}
}

// handleTriageInteraction is the InteractionCreate handler of the triage buttons.
// Il est IDEMPOTENT par construction : l'upsert DB ré-applique le même verdict et
// Discord n'accepte qu'UNE réponse par interaction — c'est ce qui rend inoffensive
// la double-session transitoire d'un hot-reload ApplyDiscord (les deux sessions
// reçoivent l'événement, une seule ack gagne, l'autre abandonne proprement).
//
// Après l'ack, le message est re-rendu depuis son état FRAIS (re-fetch) et la
// DERNIÈRE décision en DB — deux clics rapprochés ou une édition d'enrichissement
// concurrente convergent ainsi vers l'état réel au lieu de figer le snapshot du
// clic (l'analyse IA arrivée entre-temps est préservée).
func (d *DiscordBot) handleTriageInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionMessageComponent || d == nil || d.triage == nil {
		return
	}
	status, fingerprint, ok := parseTriageCustomID(i.MessageComponentData().CustomID)
	if !ok {
		return
	}
	// Défense en profondeur : les boutons ne vivent que sur le canal d'alertes.
	if i.ChannelID != d.channelID {
		return
	}
	user, userID := interactionUser(i)
	if !canTriage(i) {
		slog.Warn("SOAR triage: clic refusé (permission insuffisante)", "user_id", userID, "status", status)
		respondEphemeral(s, i, "⛔ Classement réservé aux opérateurs (permission « Gérer les messages » sur ce canal).")
		return
	}

	if err := d.triage.SetDecision(fingerprint, status, user, userID); err != nil {
		slog.Error("SOAR triage: enregistrement du verdict impossible", "error", err, "status", status)
		// Prévenir le cliqueur plutôt que d'échouer en silence : le bouton n'a
		// PAS pris effet, la suppression n'aura pas lieu.
		respondEphemeral(s, i, "⚠️ Classement non enregistré (erreur base de données), réessaie.")
		return
	}
	slog.Info("SOAR triage: verdict enregistré", "status", status, "fingerprint", fingerprint, "user", user, "user_id", userID)

	if i.Message == nil {
		return
	}
	// Ack différé : si elle échoue, l'autre session du hot-reload a déjà pris
	// l'interaction (le verdict EST enregistré) — l'édition lui revient.
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredMessageUpdate,
	}); err != nil {
		slog.Warn("SOAR triage: interaction déjà prise en charge (hot-reload ?)", "error", err)
		return
	}

	// Converger vers la dernière décision (un clic concurrent a pu committer
	// après le nôtre) et l'état frais du message (une édition d'enrichissement
	// a pu remplacer l'arbre depuis le snapshot du clic).
	renderStatus, renderBy := status, user
	if st, by, err := d.triage.Decision(fingerprint); err == nil && st != "" {
		renderStatus, renderBy = st, by
	}
	components := i.Message.Components
	if fresh, err := s.ChannelMessage(i.ChannelID, i.Message.ID); err == nil && fresh != nil {
		components = fresh.Components
	} else if err != nil {
		slog.Warn("SOAR triage: re-fetch du message impossible, rendu depuis le snapshot du clic", "error", err)
	}
	updated := retagSoarComponents(components, renderStatus, renderBy, fingerprint)
	if _, err := s.ChannelMessageEditComplex(&discordgo.MessageEdit{
		Channel:    i.ChannelID,
		ID:         i.Message.ID,
		Flags:      discordgo.MessageFlagsIsComponentsV2,
		Components: &updated,
	}); err != nil {
		slog.Warn("SOAR triage: édition du message d'alerte non appliquée", "error", err)
	}
}

// triageDigestComponents builds the weekly digest message (Components V2) from
// the suppression counters. rows est trié le plus supprimé d'abord ; les 10
// premières empreintes sont détaillées, le reste est agrégé. Fonction pure,
// testable sans session.
func triageDigestComponents(rows []TriageDigestRow) []discordgo.MessageComponent {
	const maxDetailed = 10
	divider := true
	color := 0x808080

	total := 0
	for _, r := range rows {
		total += r.SinceDigest
	}

	inner := []discordgo.MessageComponent{
		discordgo.TextDisplay{Content: "## 🔕 Digest triage SOAR — 7 derniers jours"},
		discordgo.TextDisplay{Content: fmt.Sprintf(
			"**%d** alerte(s) supprimée(s) sur **%d** empreinte(s) classée(s). Rien n'est perdu : chaque ligne reste réactivable en reclassant l'alerte d'origine.",
			total, len(rows))},
		discordgo.Separator{Divider: &divider},
	}

	var b strings.Builder
	for idx, r := range rows {
		if idx >= maxDetailed {
			break
		}
		title := r.Title
		if title == "" {
			title = "(sans titre)"
		}
		// Une row peut avoir été reclassée (voire rouverte par récidive) APRÈS
		// ses suppressions : le compteur est un historique, le statut affiché
		// est l'état courant.
		statusName := triageStatusName(r.Status)
		if statusName == "" {
			statusName = "réouverte"
		}
		fmt.Fprintf(&b, "**%d×** %s — %s · règle %s · %s · %d au total\n",
			r.SinceDigest,
			truncateRunes(neutralizeDiscord(title), 80),
			truncateRunes(neutralizeDiscord(r.AgentName), 40),
			neutralizeDiscord(r.RuleID),
			statusName,
			r.TotalSuppressed)
	}
	if len(rows) > maxDetailed {
		rest := 0
		for _, r := range rows[maxDetailed:] {
			rest += r.SinceDigest
		}
		fmt.Fprintf(&b, "-# … et %d autre(s) empreinte(s), %d suppression(s)\n", len(rows)-maxDetailed, rest)
	}
	inner = append(inner,
		discordgo.TextDisplay{Content: truncateRunes(strings.TrimRight(b.String(), "\n"), 1800)},
		discordgo.Separator{Divider: &divider},
		discordgo.TextDisplay{Content: "-# GoaCore Security — triage apprenant"},
	)

	return []discordgo.MessageComponent{
		discordgo.Container{AccentColor: &color, Components: inner},
	}
}

// SendTriageDigest posts the weekly suppression digest to the main channel —
// le contrat « jamais de silence aveugle » : tout ce que le triage a éteint
// depuis le dernier digest redevient visible ici.
func (d *DiscordBot) SendTriageDigest(rows []TriageDigestRow) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	if len(rows) == 0 {
		return nil
	}
	_, err := d.session.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Flags:      discordgo.MessageFlagsIsComponentsV2,
		Components: triageDigestComponents(rows),
	})
	return err
}
