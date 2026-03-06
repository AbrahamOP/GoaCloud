package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WazuhClient struct {
	BaseURL  string
	User     string
	Password string
	Token    string
	Client   *http.Client
}

type WazuhAuthResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

type WazuhAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	NodeName      string `json:"node_name"`
	LastKeepAlive string `json:"lastKeepAlive"`
	OS            struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	} `json:"os"`
	VulnSummary struct {
		Total    int `json:"total"`
		High     int `json:"high"`
		Critical int `json:"critical"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"vuln_summary"` // Custom field we will populate
}

type WazuhAgentsResponse struct {
	Data struct {
		Items              []WazuhAgent `json:"affected_items"`
		TotalAffectedItems int          `json:"total_affected_items"`
	} `json:"data"`
}

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

func NewWazuhClient(rawURL, user, password string) *WazuhClient {
	// Normalise l'URL : enlève les slashes finaux et tout path parasite
	// L'API Wazuh doit être de la forme https://host:55000
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		// Ne conserver que scheme + host (port inclus), ignorer tout path
		baseURL = u.Scheme + "://" + u.Host
	}
	log.Printf("WazuhClient baseURL: %s", baseURL)
	return &WazuhClient{
		BaseURL:  baseURL,
		User:     user,
		Password: password,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: newTLSConfig(),
			},
		},
	}
}

func (w *WazuhClient) ConstructHeaders(req *http.Request) {
	req.Header.Add("Content-Type", "application/json")
	if w.Token != "" {
		req.Header.Add("Authorization", "Bearer "+w.Token)
	} else {
		// Basic Auth for initial token request usually, but Wazuh uses a specific endpoint with Basic Auth in header
		req.SetBasicAuth(w.User, w.Password)
	}
}

func (w *WazuhClient) Authenticate() error {
	req, err := http.NewRequest("GET", w.BaseURL+"/security/user/authenticate", nil)
	if err != nil {
		return err
	}
	// For Authentication endpoint, we use Basic Auth (User/Pass) which setBasicAuth handles
	// BUT subsequent requests use Bearer Token.
	// We need to be careful not to set Bearer if we have none, relying on Basic Auth for this call.
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

func (w *WazuhClient) GetAgents() ([]WazuhAgent, error) {
	if w.Token == "" {
		if err := w.Authenticate(); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest("GET", w.BaseURL+"/agents?pretty=true&select=id,name,ip,status,os.name,os.platform,version,node_name,lastKeepAlive", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+w.Token)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		// Token expiré : fermer l'ancienne réponse avant de réessayer
		resp.Body.Close()
		if err := w.Authenticate(); err != nil {
			return nil, fmt.Errorf("Re-authentication failed: %v", err)
		}
		req2, err2 := http.NewRequest("GET", w.BaseURL+"/agents?pretty=true&select=id,name,ip,status,os.name,os.platform,version,node_name,lastKeepAlive", nil)
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

// GetAgentVulnerabilities gets the summary for a specific agent
func (w *WazuhClient) GetAgentVulnerabilities(agentID string) (int, int, int, int, int, error) {
    if w.Token == "" {
        w.Authenticate()
    }
    
    // Using standard endpoint for 4.x
    url := fmt.Sprintf("%s/vulnerability/%s/summary", w.BaseURL, agentID)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return 0, 0, 0, 0, 0, err
    }
    req.Header.Add("Authorization", "Bearer "+w.Token)
    
    resp, err := w.Client.Do(req)
    if err != nil {
        return 0, 0, 0, 0, 0, err
    }

    if resp.StatusCode == 401 {
        resp.Body.Close()
        w.Authenticate()
        req2, _ := http.NewRequest("GET", url, nil)
        req2.Header.Add("Authorization", "Bearer "+w.Token)
        resp, err = w.Client.Do(req2)
        if err != nil {
            return 0, 0, 0, 0, 0, err
        }
    }
    defer resp.Body.Close()
    
	if resp.StatusCode == 404 || resp.StatusCode == 400 {
		// Module likely disabled or no data, return 0s gracefully
		return 0, 0, 0, 0, 0, nil
	}

	if resp.StatusCode != 200 {
		return 0, 0, 0, 0, 0, fmt.Errorf("API Error %d", resp.StatusCode)
	}
    
    	var summary WazuhVulnSummaryResponse
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return 0, 0, 0, 0, 0, err
	}

	s := summary.Data.SevSummary
	return s.Total, s.Critical, s.High, s.Medium, s.Low, nil
}

type WazuhVuln struct {
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Condition string `json:"condition"`
	Package  struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

type WazuhVulnListResponse struct {
	Data struct {
		Items []WazuhVuln `json:"affected_items"`
	} `json:"data"`
}

func (w *WazuhClient) GetAgentVulnerabilitiesList(agentID string) ([]WazuhVuln, error) {
	if w.Token == "" {
		w.Authenticate()
	}

	// Fetch up to 100 items for now
	url := fmt.Sprintf("%s/vulnerability/%s?limit=100&sort=-severity", w.BaseURL, agentID)
	req, err := http.NewRequest("GET", url, nil)
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
		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Add("Authorization", "Bearer "+w.Token)
		resp, err = w.Client.Do(req2)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 400 {
		// Module likely disabled or no data, return empty list gracefully
		return []WazuhVuln{}, nil
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
