package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// AIAlertContext holds metadata for AI-based alert analysis.
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

// AIClient defines the interface for AI providers.
type AIClient interface {
	EnrichAlert(ctx context.Context, alertCtx AIAlertContext) (string, error)
}

// --- Ollama Implementation ---

// OllamaClient is an AI client backed by Ollama.
type OllamaClient struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// NewOllamaClient creates a new Ollama client.
func NewOllamaClient(url, model string) *OllamaClient {
	if url == "" {
		url = "http://localhost:11434/api/generate"
	} else if !strings.HasSuffix(url, "/api/generate") {
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

// EnrichAlert sends an alert to Ollama for analysis.
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

	reqBody := ollamaRequest{
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

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return cleanAIResponse(ollamaResp.Response), nil
}

func cleanAIResponse(response string) string {
	lowerResp := strings.ToLower(response)
	if idx := strings.LastIndex(lowerResp, "</think>"); idx != -1 {
		response = response[idx+8:]
	} else {
		reThink := regexp.MustCompile(`(?si)<think>.*?</think>`)
		response = reThink.ReplaceAllString(response, "")
	}

	startKey := "**Analyse:**"
	idx := strings.Index(response, startKey)
	if idx != -1 {
		response = response[idx:]
	}

	return strings.TrimSpace(response)
}

// --- OpenAI Implementation ---

// OpenAIClient is an AI client backed by OpenAI.
type OpenAIClient struct {
	APIKey string
	Model  string
	Client *http.Client
}

type openAIRequest struct {
	Model    string           `json:"model"`
	Messages []openAIMessage  `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

// NewOpenAIClient creates a new OpenAI client.
func NewOpenAIClient(apiKey, model string) *OpenAIClient {
	return &OpenAIClient{
		APIKey: apiKey,
		Model:  model,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

// EnrichAlert sends an alert to OpenAI for analysis.
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

	reqBody := openAIRequest{
		Model: c.Model,
		Messages: []openAIMessage{
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

	var openAIResp openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return "", err
	}

	if len(openAIResp.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}

	return openAIResp.Choices[0].Message.Content, nil
}

// --- Factory ---

// NewAIClient creates an AIClient based on the provider name.
func NewAIClient(provider, url, apiKey, model string) AIClient {
	slog.Info("Initializing AI Client", "provider", provider, "model", model)

	switch strings.ToLower(provider) {
	case "openai":
		if apiKey == "" {
			slog.Error("OpenAI API Key missing")
			return nil
		}
		if model == "" {
			model = "gpt-3.5-turbo"
		}
		return NewOpenAIClient(apiKey, model)

	case "ollama":
		if url == "" {
			url = "http://localhost:11434"
		}
		if model == "" {
			model = "mistral"
		}
		return NewOllamaClient(url, model)

	default:
		slog.Warn("Unknown AI provider, defaulting to Ollama", "provider", provider)
		if url == "" {
			url = "http://localhost:11434"
		}
		if model == "" {
			model = "mistral"
		}
		return NewOllamaClient(url, model)
	}
}
