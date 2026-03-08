package services

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goacloud/internal/models"
)

// WazuhAuthResponse is the authentication response from the Wazuh API.
type WazuhAuthResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

// WazuhAgentsResponse is the response from the Wazuh agents endpoint.
type WazuhAgentsResponse struct {
	Data struct {
		Items              []models.WazuhAgent `json:"affected_items"`
		TotalAffectedItems int                 `json:"total_affected_items"`
	} `json:"data"`
}

// WazuhVulnSummaryResponse is the response from the Wazuh vulnerability summary endpoint.
type WazuhVulnSummaryResponse struct {
	Data struct {
		SevSummary struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
			Total    int `json:"total"`
		} `json:"severity_summary"`
	} `json:"data"`
}

// WazuhVulnListResponse is the response from the Wazuh vulnerability list endpoint.
type WazuhVulnListResponse struct {
	Data struct {
		Items []models.WazuhVuln `json:"affected_items"`
	} `json:"data"`
}

// WazuhClient is an HTTP client for the Wazuh Manager API.
type WazuhClient struct {
	BaseURL  string
	User     string
	Password string
	Token    string
	Client   *http.Client
}

// NewWazuhClient creates a new WazuhClient.
func NewWazuhClient(rawURL, user, password string, skipTLS bool) *WazuhClient {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}
	slog.Info("WazuhClient baseURL", "url", baseURL)
	return &WazuhClient{
		BaseURL:  baseURL,
		User:     user,
		Password: password,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
			},
		},
	}
}

// Authenticate obtains a JWT token from the Wazuh API.
func (w *WazuhClient) Authenticate() error {
	req, err := http.NewRequest("GET", w.BaseURL+"/security/user/authenticate", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(w.User, w.Password)

	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Wazuh Auth Failed (Status %d): %s", resp.StatusCode, string(body))
	}

	var authResp WazuhAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return err
	}

	w.Token = authResp.Data.Token
	return nil
}

// GetAgents returns the list of Wazuh agents.
func (w *WazuhClient) GetAgents() ([]models.WazuhAgent, error) {
	if w.Token == "" {
		if err := w.Authenticate(); err != nil {
			return nil, err
		}
	}

	reqURL := w.BaseURL + "/agents?pretty=true&select=id,name,ip,status,os.name,os.platform,version,node_name,lastKeepAlive"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+w.Token)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		resp.Body.Close()
		if err := w.Authenticate(); err != nil {
			return nil, fmt.Errorf("Re-authentication failed: %v", err)
		}
		req2, err2 := http.NewRequest("GET", reqURL, nil)
		if err2 != nil {
			return nil, err2
		}
		req2.Header.Add("Authorization", "Bearer "+w.Token)
		resp, err = w.Client.Do(req2)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Status %d: %s", resp.StatusCode, string(body))
	}

	var agentsResp WazuhAgentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&agentsResp); err != nil {
		return nil, err
	}

	return agentsResp.Data.Items, nil
}

// GetAgentVulnerabilitiesList returns the vulnerability list for a given agent (legacy API).
func (w *WazuhClient) GetAgentVulnerabilitiesList(agentID string) ([]models.WazuhVuln, error) {
	if w.Token == "" {
		w.Authenticate()
	}

	apiURL := fmt.Sprintf("%s/vulnerability/%s?limit=100&sort=-severity", w.BaseURL, agentID)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+w.Token)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		resp.Body.Close()
		w.Authenticate()
		req2, _ := http.NewRequest("GET", apiURL, nil)
		req2.Header.Add("Authorization", "Bearer "+w.Token)
		resp, err = w.Client.Do(req2)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 400 {
		return []models.WazuhVuln{}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API Error %d", resp.StatusCode)
	}

	var vulnResp WazuhVulnListResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, err
	}

	return vulnResp.Data.Items, nil
}
