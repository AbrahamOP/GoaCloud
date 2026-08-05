package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goacore/internal/models"
)

// Alert-window paging. GetRecentAlerts used to ask for a single page of 50 hits while
// its caller (the SOAR worker) advanced its cursor past the whole window: during an
// attack peak — exactly when it matters — every alert beyond the 50th was dropped
// silently. The window is now paged through to exhaustion, up to a hard cap that
// bounds memory and the indexer load; reaching that cap is LOUD (slog.Warn), never
// silent.
const (
	alertPageSize    = 500
	maxAlertsPerPoll = 5000
)

// defaultAlertRuleIDs is the built-in selection of Wazuh rules the SOAR pipeline
// reacts to: SSH authentication (5716/5710/5712/5503), privilege escalation (5402),
// file integrity (550/553/554) and package management (2902/2903). It is the DEFAULT,
// not a hard-coded fate: a deployment can replace it per client via SetAlertRuleIDs.
var defaultAlertRuleIDs = []string{
	"5716", "5710", "5712", "5503",
	"5402",
	"550", "553", "554",
	"2902", "2903",
}

// WazuhIndexerClient is an HTTP client for the Wazuh Indexer (OpenSearch) API.
type WazuhIndexerClient struct {
	BaseURL  string
	User     string
	Password string
	Client   *http.Client
	// AlertRuleIDs is the set of rule.id values GetRecentAlerts filters on. Seeded
	// with defaultAlertRuleIDs by the constructor; override with SetAlertRuleIDs.
	AlertRuleIDs []string
}

// SetAlertRuleIDs overrides the rules GetRecentAlerts watches. An empty (or all-blank)
// list is ignored and keeps the built-in selection: a misconfiguration must never
// silence the SOAR pipeline entirely.
func (w *WazuhIndexerClient) SetAlertRuleIDs(ids []string) {
	cleaned := make([]string, 0, len(ids))
	for _, id := range ids {
		if v := strings.TrimSpace(id); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	if len(cleaned) == 0 {
		slog.Warn("Indexer: empty alert rule list ignored, keeping the built-in selection")
		return
	}
	w.AlertRuleIDs = cleaned
}

// alertRuleIDs returns the effective rule filter (configured or built-in).
func (w *WazuhIndexerClient) alertRuleIDs() []string {
	if len(w.AlertRuleIDs) > 0 {
		return w.AlertRuleIDs
	}
	return defaultAlertRuleIDs
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

// IndexerAlertResponse is the response from the alerts index search. Total is the
// indexer's own count for the query (capped at 10 000 by OpenSearch's default
// track_total_hits): it is only used to report how many alerts a truncated window
// left behind.
type IndexerAlertResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
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
		BaseURL:      baseURL,
		User:         user,
		Password:     password,
		AlertRuleIDs: append([]string(nil), defaultAlertRuleIDs...),
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
		if resp.StatusCode == http.StatusNotFound {
			return []models.WazuhVuln{}, nil
		}
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

// buildAlertQuery builds ONE page of the alert search: the watched rules over the
// [startTime, now] window, newest first, at offset `from`. Pure and table-testable.
func buildAlertQuery(startTime string, ruleIDs []string, from, size int) map[string]interface{} {
	return map[string]interface{}{
		"from": from,
		"size": size,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{"range": map[string]interface{}{
						"timestamp": map[string]interface{}{"gte": startTime},
					}},
					{"terms": map[string]interface{}{"rule.id": ruleIDs}},
				},
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
			// Tie-breaker: alerts sharing a timestamp (an attack burst produces plenty)
			// would otherwise be ordered non-deterministically between two pages, which
			// duplicates some hits and skips others.
			{"rule.id": map[string]interface{}{"order": "desc"}},
		},
	}
}

// GetRecentAlerts fetches the security alerts of the last `duration` from the Wazuh
// alerts index, paging through the WHOLE window (up to maxAlertsPerPoll) instead of
// returning a single truncated page. Alerts are returned newest first.
//
// Why it matters: the SOAR worker advances its cursor past the window it just polled.
// A silently truncated window is a permanently lost alert — and truncation happens
// precisely during an attack peak. If the hard cap is ever reached, the truncation is
// logged explicitly with the number of alerts left behind.
func (w *WazuhIndexerClient) GetRecentAlerts(duration time.Duration) ([]WazuhAlert, error) {
	startTime := time.Now().Add(-duration).Format(time.RFC3339)
	ruleIDs := w.alertRuleIDs()

	var alerts []WazuhAlert
	for from := 0; from < maxAlertsPerPoll; from += alertPageSize {
		size := alertPageSize
		if remaining := maxAlertsPerPoll - from; remaining < size {
			size = remaining
		}

		page, total, err := w.fetchAlertPage(startTime, ruleIDs, from, size)
		if err != nil {
			// A mid-window failure must not hide what has already been collected: the
			// caller decides (the SOAR worker keeps its cursor on error).
			return nil, err
		}
		alerts = append(alerts, page...)
		if len(page) < size {
			// Last page: the window is exhausted.
			return alerts, nil
		}
		if from+size >= maxAlertsPerPoll {
			slog.Warn("Indexer: alert window truncated at the hard cap — older alerts of this window were NOT returned",
				"cap", maxAlertsPerPoll, "window", duration.String(), "total_reported", total)
		}
	}
	return alerts, nil
}

// fetchAlertPage runs one page of the alert search and returns its hits plus the
// indexer's total count for the query.
func (w *WazuhIndexerClient) fetchAlertPage(startTime string, ruleIDs []string, from, size int) ([]WazuhAlert, int, error) {
	queryBytes, err := json.Marshal(buildAlertQuery(startTime, ruleIDs, from, size))
	if err != nil {
		return nil, 0, err
	}

	apiURL := fmt.Sprintf("%s/wazuh-alerts-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(queryBytes))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(w.User, w.Password)

	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return nil, 0, nil
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("Indexer Alerts Error %d: %s", resp.StatusCode, string(body))
	}

	var alertResp IndexerAlertResponse
	if err := json.NewDecoder(resp.Body).Decode(&alertResp); err != nil {
		return nil, 0, err
	}

	alerts := make([]WazuhAlert, 0, len(alertResp.Hits.Hits))
	for _, hit := range alertResp.Hits.Hits {
		alerts = append(alerts, hit.Source)
	}
	return alerts, alertResp.Hits.Total.Value, nil
}
