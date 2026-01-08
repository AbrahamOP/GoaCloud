package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// AIAlertContext holds metadata for better analysis
type AIAlertContext struct {
    Title       string
    Description string
    AgentName   string
    AgentIP     string
    RuleID      string
    RuleLevel   int
    FullLog     string
    SourceIP    string
}

// AIClient defines the interface for AI providers
type AIClient interface {
	EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error)
}

// --- Ollama Implementation ---

type OllamaClient struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func NewOllamaClient(url, model string) *OllamaClient {
	if url == "" {
		url = "http://localhost:11434/api/generate"
	} else if !strings.HasSuffix(url, "/api/generate") {
        // Ensure the URL points to the generate endpoint if only base is given
        // But user might provide full path. Let's assume user provides full URL or base.
		// Common pattern: http://localhost:11434 -> append /api/generate
        if !strings.Contains(url, "/api/") {
             url = strings.TrimRight(url, "/") + "/api/generate"
        }
	}
    
	return &OllamaClient{
		BaseURL: url,
		Model:   model,
		Client:  &http.Client{Timeout: 90 * time.Second},
	}
}

func (c *OllamaClient) EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error) {
	prompt := fmt.Sprintf(`Analyse l'alerte de sécurité suivante:

CONTEXTE AGENT:
- Machine: %s
- IP: %s

DÉTAILS ALERTE:
- Titre: %s
- Description: %s
- Règle ID: %s (Niveau %d)
- IP Source: %s
- Log Brut: %s

TA MISSION:
Agis comme un expert SOC. Analyse ces données pour déterminer si c'est un faux positif ou une menace réelle.

FORMAT DE RÉPONSE OBLIGATOIRE:
**Analyse:** [Explication technique concise de ce qui s'est passé]
**Gravité:** [Faible/Moyenne/Élevée/Critique]
**Action:** [Action curative immédiate]

Sois direct. Pas de bla-bla.`,
    alertCtx.AgentName, alertCtx.AgentIP,
    alertCtx.Title, alertCtx.Description,
    alertCtx.RuleID, alertCtx.RuleLevel,
    alertCtx.SourceIP,
    alertCtx.FullLog,
)

	reqBody := OllamaRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama API error: %s - %s", resp.Status, string(body))
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return cleanAIResponse(ollamaResp.Response), nil
}

func cleanAIResponse(response string) string {
	// 1. Aggressively strip "think" blocks.
    // Some models omit the opening <think> tag or put text before it.
    // We assume the real answer comes AFTER the last </think> tag.
    lowerResp := strings.ToLower(response)
    if idx := strings.LastIndex(lowerResp, "</think>"); idx != -1 {
        response = response[idx+8:] // Skip past </think>
    } else {
        // Fallback: standard regex if specific closing tag isn't found simple (e.g. valid pair)
        reThink := regexp.MustCompile(`(?si)<think>.*?</think>`)
        response = reThink.ReplaceAllString(response, "")
    }

	// 2. Locate the start of the valid breakdown
	startKey := "**Analyse:**"
	idx := strings.Index(response, startKey)
	if idx != -1 {
		response = response[idx:]
	}

	// 3. Trim extra whitespace
	return strings.TrimSpace(response)
}

// --- OpenAI Implementation ---

type OpenAIClient struct {
	APIKey string
	Model  string
	Client *http.Client
}

type OpenAIRequest struct {
	Model    string          `json:"model"`
	Messages []OpenAIMessage `json:"messages"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message OpenAIMessage `json:"message"`
	} `json:"choices"`
}

func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		APIKey: apiKey,
		Model:  model,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *OpenAIClient) EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error) {
	systemPrompt := "Tu es un expert en cybersécurité (SOC Analyst). Ton but est d'analyser les alertes et de fournir des recommandations concises."
	userPrompt := fmt.Sprintf(`Analyse l'alerte de sécurité suivante:
Titre: %s
Détails: %s
Machine: %s (%s)
Log: %s

Format de réponse attendu:
**Analyse:** [Résumé de la menace]
**Gravité:** [Niveau estimé]
**Action:** [Recommandation immédiate]
`, alertCtx.Title, alertCtx.Description, alertCtx.AgentName, alertCtx.AgentIP, alertCtx.FullLog)

	reqBody := OpenAIRequest{
		Model: c.Model,
		Messages: []OpenAIMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("openai API error: %s - %s", resp.Status, string(body))
	}

	var openAIResp OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return "", err
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}

	return openAIResp.Choices[0].Message.Content, nil
}

// --- Factory ---

func NewAIClient(provider, url, apiKey, model string) AIClient {
	log.Printf("Initializing AI Client. Provider: %s, Model: %s", provider, model)
	
	switch strings.ToLower(provider) {
	case "openai":
		if apiKey == "" {
			log.Println("Error: OpenAI API Key missing.")
			return nil
		}
		if model == "" { model = "gpt-3.5-turbo" }
		return NewOpenAIClient(apiKey, model)
	
	case "ollama":
		if url == "" { url = "http://localhost:11434" }
		if model == "" { model = "mistral" } // Default model
		return NewOllamaClient(url, model)
		
	default:
		// Default to Ollama if unspecified or unknown, for backward compatibility
		// But only if we have a URL or default to localhost
		log.Printf("Unknown or empty provider '%s', defaulting to Ollama.", provider)
		if url == "" { url = "http://localhost:11434" }
		if model == "" { model = "mistral" }
		return NewOllamaClient(url, model)
	}
}
