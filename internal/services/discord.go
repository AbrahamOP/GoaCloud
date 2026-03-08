package services

import (
	"fmt"
	"log/slog"

	"github.com/bwmarrin/discordgo"
)

// DiscordBot wraps a discordgo session for sending alerts.
type DiscordBot struct {
	session       *discordgo.Session
	channelID     string
	authChannelID string
}

// NewDiscordBot creates and opens a new Discord bot session.
func NewDiscordBot(token, channelID, authChannelID string) (*DiscordBot, error) {
	if token == "" || channelID == "" {
		return nil, fmt.Errorf("missing token or channel ID")
	}

	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}

	if err := session.Open(); err != nil {
		return nil, fmt.Errorf("error opening connection: %v", err)
	}

	slog.Info("Discord Bot is now running")
	return &DiscordBot{
		session:       session,
		channelID:     channelID,
		authChannelID: authChannelID,
	}, nil
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

// SendAlert sends a formatted SOAR alert embed to the main channel.
func (d *DiscordBot) SendAlert(title, message, severity string) error {
	if d == nil || d.session == nil {
		return fmt.Errorf("discord session not initialized")
	}

	color := 0x00ff00 // Green (Info)
	switch severity {
	case "critical":
		color = 0xff0000
	case "high":
		color = 0xffa500
	case "medium":
		color = 0xffff00
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🛡️ SOAR Alert: " + title,
		Description: message,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCloud Security",
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
			Text: "GoaCloud Auth Monitor",
		},
	}

	_, err := d.session.ChannelMessageSendEmbed(channelID, embed)
	return err
}
