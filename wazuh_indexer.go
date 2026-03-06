package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type WazuhIndexerClient struct {
	BaseURL  string
	User     string
	Password string
	Client   *http.Client
}

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

type IndexerHit struct {
	Source IndexerVulnSource `json:"_source"`
}


type IndexerResponse struct {
	Hits struct {
		Hits []IndexerHit `json:"hits"`
	} `json:"hits"`
}

func NewWazuhIndexerClient(url, user, password string) *WazuhIndexerClient {
	return &WazuhIndexerClient{
		BaseURL:  url,
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

func (w *WazuhIndexerClient) GetVulnerabilities(agentID string) ([]WazuhVuln, error) {
	// Query to fetch vulnerabilities for specific agent
	// Index pattern usually: wazuh-states-vulnerabilities-*
	query := map[string]interface{}{
		"size": 1000, // Limit results: Increased for better aggregation accuracy
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{
						"term": map[string]interface{}{
							"agent.id": agentID,
						},
					},
					// Status filter might need to be specific, or removed if not needed.
					// Found "status": "VALID" in some docs, but field might be nested.
                    // Omitting status filter for now to be safe, or checking schema if available.
                    // Let's assume Valid for now or just filter by agent.
				},
			},
		},
		"sort": []map[string]interface{}{
			{
				"vulnerability.severity": map[string]interface{}{
					"order": "desc",
				},
			},
		},
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/wazuh-states-vulnerabilities-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(queryBytes))
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

	var vulns []WazuhVuln
	for _, hit := range indexerResp.Hits.Hits {
        // Map Indexer Source to UI Struct
		v := WazuhVuln{
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

type IndexerAggregations struct {
	Agents struct {
		Buckets []struct {
			Key      string `json:"key"` // Agent ID
			Severity struct {
				Buckets []struct {
					Key   string `json:"key"` // Severity (Critical, High, etc.)
					Count int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"severity"`
		} `json:"buckets"`
	} `json:"agents"`
}

type IndexerAggResponse struct {
	Aggregations IndexerAggregations `json:"aggregations"`
}

type AgentVulnSummary struct {
    Total    int
    Critical int
    High     int
    Medium   int
    Low      int
}

func (w *WazuhIndexerClient) GetVulnSummary(agentIDs []string) (map[string]AgentVulnSummary, error) {
    if len(agentIDs) == 0 {
        return map[string]AgentVulnSummary{}, nil
    }

    // Aggregation query: Filter by agents -> Terms Agg on agent.id -> Terms Agg on vulnerability.severity
    query := map[string]interface{}{
        "size": 0, // We only want aggregations
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "filter": []map[string]interface{}{
                    {
                        "terms": map[string]interface{}{
                            "agent.id": agentIDs,
                        },
                    },
                },
            },
        },
        "aggs": map[string]interface{}{
            "agents": map[string]interface{}{
                "terms": map[string]interface{}{
                    "field": "agent.id",
                    "size":  1000, // Max agents to aggregate
                },
                "aggs": map[string]interface{}{
                    "severity": map[string]interface{}{
                        "terms": map[string]interface{}{
                            "field": "vulnerability.severity",
                        },
                    },
                },
            },
        },
    }

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/wazuh-states-vulnerabilities-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(queryBytes))
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
		// If index is missing (e.g. no vulns yet), it might return 404 or specific error. Handle gracefully?
        // OpenSearch usually returns 404 for missing index on search unless configured otherwise.
        if resp.StatusCode == 404 {
             return map[string]AgentVulnSummary{}, nil
        }
		return nil, fmt.Errorf("Indexer Error %d: %s", resp.StatusCode, string(body))
	}

	var aggResp IndexerAggResponse
	if err := json.NewDecoder(resp.Body).Decode(&aggResp); err != nil {
		return nil, err
	}
    
    // Process results
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

// Alerting Query

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
        SrcIP string `json:"srcip"`
        DstUser string `json:"dstuser"` // Target user of SSH attempt
    } `json:"data"`
    Syscheck struct {
        Path string `json:"path"`
    } `json:"syscheck"`
    FullLog string `json:"full_log"`
}

type IndexerAlertResponse struct {
    Hits struct {
        Hits []struct {
            Source WazuhAlert `json:"_source"`
        } `json:"hits"`
    } `json:"hits"`
}

func (w *WazuhIndexerClient) GetRecentAlerts(duration time.Duration) ([]WazuhAlert, error) {
    // Query Wazuh Alerts index for specific security rules
    // SSH: 5716, 5710, 5712, 5503
    // Sudo: 5402
    // FIM: 550, 553, 554
    // Packages: 2902, 2903
    
    startTime := time.Now().Add(-duration).Format(time.RFC3339)
    
    query := map[string]interface{}{
        "size": 50, // Get recent 50
        "query": map[string]interface{}{
            "bool": map[string]interface{}{
                "filter": []map[string]interface{}{
                    {
                        "range": map[string]interface{}{
                            "timestamp": map[string]interface{}{
                                "gte": startTime,
                            },
                        },
                    },
                    {
                        "terms": map[string]interface{}{
                            "rule.id": []string{
                                "5716", "5710", "5712", "5503", // SSH
                                "5402", // Sudo
                                "550", "553", "554", // FIM
                                "2902", "2903", // Packages
                            },
                        },
                    },
                },
            },
        },
        "sort": []map[string]interface{}{
            {
                "timestamp": map[string]interface{}{
                    "order": "desc",
                },
            },
        },
    }

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/wazuh-alerts-*/_search", w.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(queryBytes))
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
        // 404 is fine (no alerts index yet for today)
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
