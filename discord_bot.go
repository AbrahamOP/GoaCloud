package main

import (
	"fmt"
	"log"

	"github.com/bwmarrin/discordgo"
)

var discordSession *discordgo.Session
var discordChannelID string

// InitDiscordBot initializes the Discord session
func InitDiscordBot(token, channelID string) error {
	if token == "" || channelID == "" {
		return fmt.Errorf("missing token or channel ID")
	}

	var err error
	discordSession, err = discordgo.New("Bot " + token)
	if err != nil {
		return err
	}

	err = discordSession.Open()
	if err != nil {
		return fmt.Errorf("error opening connection: %v", err)
	}

	discordChannelID = channelID
	log.Println("Discord Bot is now running.")
	return nil
}

// SendDiscordAlert sends a formatted alert to the configured channel
func SendDiscordAlert(title, message, severity string) error {
	if discordSession == nil {
		return fmt.Errorf("discord session not initialized")
	}

	// Color logic based on severity
	color := 0x00ff00 // Green (Info)
	switch severity {
	case "critical":
		color = 0xff0000 // Red
	case "high":
		color = 0xffa500 // Orange
	case "medium":
		color = 0xffff00 // Yellow
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🛡️ SOAR Alert: " + title,
		Description: message,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "GoaCloud Security",
		},
	}

	_, err := discordSession.ChannelMessageSendEmbed(discordChannelID, embed)
	return err
}

// CloseDiscordBot closes the session
func CloseDiscordBot() {
	if discordSession != nil {
		discordSession.Close()
	}
}
