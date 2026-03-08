package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goacloud/internal/models"
)

// WazuhIndexerClient is an HTTP client for the Wazuh Indexer (OpenSearch) API.
type WazuhIndexerClient struct {
	BaseURL  string
	User     string
	Password string
	Client   *http.Client
}

// IndexerVulnSource is the _source of a vulnerability hit from the indexer.
type IndexerVulnSource struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Title       string `json:"title"`
		Scanner     struct {
			Condition string `json:"condition"`
		} `json:"scanner"`
	} `json:"vulnerability"`
	Package struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

// IndexerHit is a single hit from an indexer search response.
type IndexerHit struct {
	Source IndexerVulnSource `json:"_source"`
}

// IndexerResponse is the response from an indexer search query.
type IndexerResponse struct {
	Hits struct {
		Hits []IndexerHit `json:"hits"`
	} `json:"hits"`
}

// IndexerAggregations holds aggregation results from the indexer.
type IndexerAggregations struct {
	Agents struct {
		Buckets []struct {
			Key      string `json:"key"`
			Severity struct {
				Buckets []struct {
					Key   string `json:"key"`
					Count int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"severity"`
		} `json:"buckets"`
	} `json:"agents"`
}

// IndexerAggResponse is the response from an aggregation query.
type IndexerAggResponse struct {
	Aggregations IndexerAggregations `json:"aggregations"`
}

// AgentVulnSummary holds a per-agent vulnerability count summary.
type AgentVulnSummary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

// IndexerAlertResponse is the response from the alerts index search.
type IndexerAlertResponse struct {
	Hits struct {
		Hits []struct {
			Source WazuhAlert `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// WazuhAlert represents a security alert from the Wazuh indexer.
type WazuhAlert struct {
	Timestamp string `json:"timestamp"`
	Rule      struct {
		ID          string `json:"id"`
		Level       int    `json:"level"`
		Description string `json:"description"`
	} `json:"rule"`
	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`
	Data struct {
		SrcIP   string `json:"srcip"`
		DstUser string `json:"dstuser"`
	} `json:"data"`
	Syscheck struct {
		Path string `json:"path"`
	} `json:"syscheck"`
	FullLog string `json:"full_log"`
}

// NewWazuhIndexerClient creates a new WazuhIndexerClient.
func NewWazuhIndexerClient(rawURL, user, password string, skipTLS bool) *WazuhIndexerClient {
	baseURL := strings.TrimRight(rawURL, "/")
	if u, err := url.Parse(baseURL); err == nil {
		baseURL = u.Scheme + "://" + u.Host
	}
	return &WazuhIndexerClient{
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

// GetVulnerabilities fetches vulnerabilities for a given agent from the indexer.
func (w *WazuhIndexerClient) GetVulnerabilities(agentID string) ([]models.WazuhVuln, error) {
	query := map[string]interface{}{
		"size": 1000,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{"term": map[string]interface{}{"agent.id": agentID}},
				},
			},
		},
		"sort": []map[string]interface{}{
			{"vulnerability.severity": map[string]interface{}{"order": "desc"}},
		},
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/wazuh-states-vulnerabilities-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(queryBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(w.User, w.Password)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Indexer Error %d: %s", resp.StatusCode, string(body))
	}

	var indexerResp IndexerResponse
	if err := json.NewDecoder(resp.Body).Decode(&indexerResp); err != nil {
		return nil, err
	}

	var vulns []models.WazuhVuln
	for _, hit := range indexerResp.Hits.Hits {
		v := models.WazuhVuln{
			CVE:       hit.Source.Vulnerability.ID,
			Severity:  hit.Source.Vulnerability.Severity,
			Title:     hit.Source.Vulnerability.Title,
			Condition: hit.Source.Vulnerability.Scanner.Condition,
		}
		if v.Title == "" {
			v.Title = hit.Source.Vulnerability.Description
		}
		v.Package.Name = hit.Source.Package.Name
		v.Package.Version = hit.Source.Package.Version
		vulns = append(vulns, v)
	}

	return vulns, nil
}

// GetVulnSummary fetches vulnerability counts per agent using aggregations.
func (w *WazuhIndexerClient) GetVulnSummary(agentIDs []string) (map[string]AgentVulnSummary, error) {
	if len(agentIDs) == 0 {
		return map[string]AgentVulnSummary{}, nil
	}

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{"terms": map[string]interface{}{"agent.id": agentIDs}},
				},
			},
		},
		"aggs": map[string]interface{}{
			"agents": map[string]interface{}{
				"terms": map[string]interface{}{"field": "agent.id", "size": 1000},
				"aggs": map[string]interface{}{
					"severity": map[string]interface{}{
						"terms": map[string]interface{}{"field": "vulnerability.severity"},
					},
				},
			},
		},
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/wazuh-states-vulnerabilities-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(queryBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(w.User, w.Password)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 404 {
			return map[string]AgentVulnSummary{}, nil
		}
		return nil, fmt.Errorf("Indexer Error %d: %s", resp.StatusCode, string(body))
	}

	var aggResp IndexerAggResponse
	if err := json.NewDecoder(resp.Body).Decode(&aggResp); err != nil {
		return nil, err
	}

	results := make(map[string]AgentVulnSummary)
	for _, agentBucket := range aggResp.Aggregations.Agents.Buckets {
		summary := AgentVulnSummary{}
		for _, sevBucket := range agentBucket.Severity.Buckets {
			count := sevBucket.Count
			summary.Total += count
			switch sevBucket.Key {
			case "Critical":
				summary.Critical = count
			case "High":
				summary.High = count
			case "Medium":
				summary.Medium = count
			case "Low":
				summary.Low = count
			}
		}
		results[agentBucket.Key] = summary
	}

	return results, nil
}

// GetRecentAlerts fetches recent security alerts from the Wazuh alerts index.
func (w *WazuhIndexerClient) GetRecentAlerts(duration time.Duration) ([]WazuhAlert, error) {
	startTime := time.Now().Add(-duration).Format(time.RFC3339)

	query := map[string]interface{}{
		"size": 50,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{"range": map[string]interface{}{
						"timestamp": map[string]interface{}{"gte": startTime},
					}},
					{"terms": map[string]interface{}{
						"rule.id": []string{
							"5716", "5710", "5712", "5503",
							"5402",
							"550", "553", "554",
							"2902", "2903",
						},
					}},
				},
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/wazuh-alerts-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(queryBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(w.User, w.Password)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return []WazuhAlert{}, nil
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Indexer Alerts Error %d: %s", resp.StatusCode, string(body))
	}

	var alertResp IndexerAlertResponse
	if err := json.NewDecoder(resp.Body).Decode(&alertResp); err != nil {
		return nil, err
	}

	var alerts []WazuhAlert
	for _, hit := range alertResp.Hits.Hits {
		alerts = append(alerts, hit.Source)
	}

	return alerts, nil
}
