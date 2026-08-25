package services

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/bwmarrin/discordgo"
)

// neutralizeDiscord defuses user-controlled text before it is embedded in a
// Discord message. It strips backticks (which would break out of code spans /
// fences), disarms mentions (@everyone, @here, <@id>, <@&role>) by inserting a
// zero-width space after each "@", and breaks markdown links ("](" → "]​(")
// so untrusted Wazuh/LLM text cannot inject a clickable phishing link.
func neutralizeDiscord(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "@", "@​")
	s = strings.ReplaceAll(s, "](", "]​(")
	return s
}

// DiscordBot wraps a discordgo session for sending alerts.
//
// token is retained ONLY so the registry's hot-reload (ApplyDiscord) can detect a
// token change for its no-op short-circuit; it is never logged, echoed, or sent to a
// template. The struct is immutable after NewDiscordBot, so the whole *DiscordBot is
// swapped on a reload (never a field), and every Send*/IsReady nil-guards on the
// session — so no per-send lock is needed.
type DiscordBot struct {
	session          *discordgo.Session
	token            string
	channelID        string
	authChannelID    string
	ansibleChannelID string
	// triage is the SOAR triage store backing the alert buttons (nil = triage off:
	// no inbound handler is registered and alerts ship without buttons).
	triage *TriageStore
}

// NewDiscordBot creates and opens a new Discord bot session. triage may be nil
// (tests, DB-less paths): the bot is then send-only, exactly the pre-triage
// behaviour. When non-nil, the SOAR triage InteractionCreate handler is attached
// BEFORE Open so no early click can slip past it.
func NewDiscordBot(token, channelID, authChannelID, ansibleChannelID string, triage *TriageStore) (*DiscordBot, error) {
	if token == "" || channelID == "" {
		return nil, fmt.Errorf("missing token or channel ID")
	}

	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}

	bot := &DiscordBot{
		session:          session,
		token:            token,
		channelID:        channelID,
		authChannelID:    authChannelID,
		ansibleChannelID: ansibleChannelID,
		triage:           triage,
	}
	if triage != nil {
		session.AddHandler(bot.handleTriageInteraction)
	}

	if err := session.Open(); err != nil {
		return nil, fmt.Errorf("error opening connection: %v", err)
	}

	slog.Info("Discord Bot is now running", "channel", channelID, "auth_channel", authChannelID, "ansible_channel", ansibleChannelID)
	return bot, nil
}

// Close closes the Discord session.
func (d *DiscordBot) Close() {
	if d.session != nil {
		d.session.Close()
	}
}

// IsReady returns true if the Discord session is initialized.
func (d *DiscordBot) IsReady() bool {
	return d != nil && d.session != nil
}

// severityColor maps a SOAR severity to the container accent color.
func severityColor(severity string) int {
	switch severity {
	case "critical":
		return 0xff0000
	case "high":
		return 0xffa500
	case "medium":
		return 0xffff00
	}
	return 0x00ff00 // Green (Info)
}

// truncateRunes caps user/LLM-provided text so the message stays under the
// Components V2 limit (4000 characters cumulés sur les TextDisplay).
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// soarAlertView is the render input of a SOAR alert message: the alert text plus
// its triage state. Fingerprint == "" → alerte sans triage (ex. alerte de test),
// rendue exactement comme avant l'arrivée du triage.
type soarAlertView struct {
	Title, Message, Severity, Analysis string
	Fingerprint                        string
	TriageStatus                       string // "" ou "open" → non classée
	DecidedBy                          string
}

// soarAlertComponents builds the Components V2 payload of a SOAR alert.
// v.Analysis == "" → alerte brute (post immédiat) ; non vide → version enrichie
// (utilisée par l'édition du même message une fois l'analyse IA disponible).
// Title/Message/Analysis doivent déjà être passés par neutralizeDiscord.
func soarAlertComponents(v soarAlertView) []discordgo.MessageComponent {
	color := severityColor(v.Severity)
	if c, ok := triageStatusColor(v.TriageStatus); ok {
		color = c
	}
	divider := true

	inner := []discordgo.MessageComponent{
		discordgo.TextDisplay{Content: "## 🛡️ SOAR Alert: " + truncateRunes(v.Title, 150)},
		discordgo.TextDisplay{Content: truncateRunes(v.Message, 1500)},
	}
	if v.Analysis != "" {
		inner = append(inner,
			discordgo.Separator{Divider: &divider},
			discordgo.TextDisplay{Content: "🤖 **Analyse IA :**\n" + truncateRunes(v.Analysis, 1800)},
		)
	}
	inner = append(inner,
		discordgo.Separator{Divider: &divider},
		discordgo.TextDisplay{Content: "-# GoaCore Security"},
	)
	if v.Fingerprint != "" {
		if label := triageStatusLabel(v.TriageStatus, v.DecidedBy); label != "" {
			inner = append(inner, discordgo.TextDisplay{Content: label})
		}
		inner = append(inner, triageButtonsRow(v.Fingerprint, v.TriageStatus))
	}

	return []discordgo.MessageComponent{
		discordgo.Container{AccentColor: &color, Components: inner},
	}
}

// soarAlertViewFor assembles the render view of an alert: neutralizes the
// untrusted text and reads the live triage decision (label « classée par X » et
// couleur) — utile quand un clic de triage est arrivé entre le post et l'édition
// d'enrichissement, pour ne pas effacer le classement au re-rendu. Une erreur de
// lecture triage dégrade en « non classée », jamais en échec d'envoi.
func (d *DiscordBot) soarAlertViewFor(title, message, severity, analysis, fingerprint string) soarAlertView {
	v := soarAlertView{
		Title:       neutralizeDiscord(title),
		Message:     neutralizeDiscord(message),
		Severity:    severity,
		Analysis:    neutralizeDiscord(analysis),
		Fingerprint: fingerprint,
	}
	if fingerprint != "" && d.triage != nil {
		status, decidedBy, err := d.triage.Decision(fingerprint)
		if err != nil {
			slog.Error("SOAR triage: lecture du classement impossible, rendu non classé", "error", err)
		} else {
			v.TriageStatus = status
			v.DecidedBy = decidedBy
		}
	}
	return v
}

// SendSoarAlert posts a SOAR alert (Components V2) to the main channel and
// returns the Discord message ID, so the caller can enrich the SAME message
// later via EditSoarAlertAnalysis. The alert is sent raw (no AI analysis):
// posting first guarantees the notification latency never depends on the LLM.
// fingerprint est l'empreinte de triage ("" = pas de boutons de triage).
func (d *DiscordBot) SendSoarAlert(title, message, severity, fingerprint string) (string, error) {
	if d == nil || d.session == nil {
		return "", fmt.Errorf("discord session not initialized")
	}
	// title/message proviennent de Wazuh (non fiables) → neutralisés dans la vue.
	m, err := d.session.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Flags:      discordgo.MessageFlagsIsComponentsV2,
		Components: soarAlertComponents(d.soarAlertViewFor(title, message, severity, "", fingerprint)),
	})
	if err != nil {
		return "", err
	}
	return m.ID, nil
}

// EditSoarAlertAnalysis rewrites a previously posted SOAR alert to append the
// AI analysis section. title/message/severity/fingerprint must be the same values
// passed to SendSoarAlert (a Components V2 edit replaces the whole components
// tree) ; le statut de triage est relu au moment de l'édition pour préserver un
// classement cliqué pendant l'enrichissement.
func (d *DiscordBot) EditSoarAlertAnalysis(messageID, title, message, severity, analysis, fingerprint string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	components := soarAlertComponents(d.soarAlertViewFor(title, message, severity, analysis, fingerprint))
	_, err := d.session.ChannelMessageEditComplex(&discordgo.MessageEdit{
		Channel:    d.channelID,
		ID:         messageID,
		Flags:      discordgo.MessageFlagsIsComponentsV2,
		Components: &components,
	})
	return err
}

// SendAnsibleAlert sends an Ansible scheduled playbook execution notification to the main channel.
func (d *DiscordBot) SendAnsibleAlert(playbook, vmName string, vmid int, status, output string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	// output (sortie brute du playbook) et vmName sont non fiables → neutraliser.
	playbook = neutralizeDiscord(playbook)
	vmName = neutralizeDiscord(vmName)
	output = neutralizeDiscord(output)

	color := 0x00ff00 // Green — success
	emoji := "✅"
	if status == "error" {
		color = 0xff0000
		emoji = "❌"
	}

	// Truncate output for Discord embed (max ~1000 chars)
	if len(output) > 1000 {
		output = output[len(output)-1000:]
	}

	description := fmt.Sprintf("**Playbook:** `%s`\n**Cible:** %s (%d)\n**Statut:** %s %s", playbook, vmName, vmid, emoji, status)
	if output != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", output)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📋 Ansible: " + playbook,
		Description: description,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Ansible Scheduler",
		},
	}

	channelID := d.ansibleChannelID
	if channelID == "" {
		channelID = d.channelID
	}

	_, err := d.session.ChannelMessageSendEmbed(channelID, embed)
	return err
}

// SendBackupAlert sends a backup execution notification embed to the main channel.
// status: "started", "completed" or "failed".
func (d *DiscordBot) SendBackupAlert(target string, vmid int, backupType, status, details string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	color := 0x808080 // Grey — started
	emoji := "⏳"
	switch status {
	case "completed":
		color = 0x00ff00 // Green — success
		emoji = "✅"
	case "failed":
		color = 0xff0000 // Red — failure
		emoji = "❌"
	}

	// Neutralize untrusted fields (target name comes from Proxmox guest config,
	// details may embed a Proxmox API error message) before building Markdown.
	target = neutralizeDiscord(target)
	details = neutralizeDiscord(details)

	// Truncate details for Discord embed.
	if len(details) > 1000 {
		details = details[len(details)-1000:]
	}

	description := fmt.Sprintf("**Cible:** %s (%d)\n**Type:** `%s`\n**Statut:** %s %s", target, vmid, backupType, emoji, status)
	if details != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", details)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📦 Backup: " + target,
		Description: description,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Backup",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendRestoreTestAlert sends a restore-test verdict embed to the main channel.
// verdict: "passed" or "failed" (anything else renders as a neutral state).
func (d *DiscordBot) SendRestoreTestAlert(target string, vmid int, level, verdict string, rtoSec int, detail string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	color := 0x808080 // Grey — neutral / running
	emoji := "🧪"
	switch verdict {
	case "passed":
		color = 0x00ff00 // Green
		emoji = "✅"
	case "failed":
		color = 0xff0000 // Red
		emoji = "❌"
	}

	// Neutralize untrusted fields (target name from Proxmox guest config; detail
	// may embed a Proxmox API error message) before building Markdown.
	target = neutralizeDiscord(target)
	detail = neutralizeDiscord(detail)
	if len(detail) > 1000 {
		detail = detail[len(detail)-1000:]
	}

	description := fmt.Sprintf("**Cible:** %s\n**Niveau:** `%s`\n**Verdict:** %s %s", target, level, emoji, verdict)
	if vmid > 0 {
		description += fmt.Sprintf("\n**Sandbox VMID:** `%d`", vmid)
	}
	if rtoSec > 0 {
		description += fmt.Sprintf("\n**RTO:** %ds", rtoSec)
	}
	if detail != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", detail)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🧪 Test de restauration: " + target,
		Description: description,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Restore Test",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendZombieSandboxAlert warns that a disposable restore-test sandbox guest could
// not be destroyed and is now leaking on the host — a human must intervene before
// it accumulates and fills the disk. vmid is always in the sandbox range.
func (d *DiscordBot) SendZombieSandboxAlert(vmid int, detail string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	// detail may embed a Proxmox API error message — neutralize before Markdown.
	detail = neutralizeDiscord(detail)
	if len(detail) > 1000 {
		detail = detail[len(detail)-1000:]
	}

	description := fmt.Sprintf(
		"⚠️ Le sandbox de test de restauration **VMID `%d`** n'a pas pu être détruit.\n"+
			"Intervention manuelle requise (ce guest jetable consomme du disque).", vmid)
	if detail != "" {
		description += fmt.Sprintf("\n\n```\n%s\n```", detail)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🧟 Sandbox zombie non détruit",
		Description: description,
		Color:       0xff0000, // Red — needs intervention
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Restore Test",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(d.channelID, embed)
	return err
}

// SendAuthAlert sends an authentication alert to the dedicated auth channel (or main channel as fallback).
func (d *DiscordBot) SendAuthAlert(title, message string, blocked bool) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}
	// message contient le nom d'utilisateur d'une tentative de login (fourni par un
	// client NON authentifié) → neutraliser les mentions/markdown (anti @everyone).
	title = neutralizeDiscord(title)
	message = neutralizeDiscord(message)

	channelID := d.authChannelID
	if channelID == "" {
		channelID = d.channelID
	}

	color := 0xffa500 // Orange — single failure
	if blocked {
		color = 0xff0000 // Red — IP blocked
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🔐 Auth: " + title,
		Description: message,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCore Auth Monitor",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(channelID, embed)
	return err
}
