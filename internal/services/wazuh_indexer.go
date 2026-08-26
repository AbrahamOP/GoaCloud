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
//
// Sort carries the sort values of each hit: they are the cursor fed back to the
// indexer as `search_after` for the next page (see buildAlertQuery).
type IndexerAlertResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source WazuhAlert    `json:"_source"`
			Sort   []interface{} `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

// WazuhAlert represents a security alert from the Wazuh indexer.
type WazuhAlert struct {
	// ID is Wazuh's own alert identifier ("<epoch>.<offset>"): unique per alert, it
	// is the tie-breaker that makes the pagination order total (alertSortTiebreaker).
	ID        string `json:"id"`
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
		SrcUser string `json:"srcuser"`
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

// alertSortTiebreaker is the field that turns the alert sort into a TOTAL order.
// It must be unique per document: rule.id is not (a hundred SSH failures in the same
// second share a timestamp AND a rule.id), so their relative order was left to the
// indexer's whim — and a from/size walk over an unstable order skips and duplicates
// hits.
//
// `id` is Wazuh's own alert identifier ("<epoch>.<offset>", a keyword field of the
// wazuh-alerts template), unique per alert. It is preferred over the document's `_id`
// because sorting on `_id` needs fielddata on that field, which an indexer may
// forbid (indices.id_field_data.enabled): the whole alert pipeline would then fail
// hard instead of merely paging imperfectly. It is queried with unmapped_type so an
// exotic mapping degrades the order instead of erroring out.
const alertSortTiebreaker = "id"

// buildAlertQuery builds ONE page of the alert search: the watched rules over the
// [startTime, now] window, newest first. Paging is done with `search_after` (the
// sort values of the last hit of the previous page) rather than `from`, because a
// deep `from` walk re-runs the whole sort on every page: any document indexed
// meanwhile shifts the offsets and silently skips alerts. Pure and table-testable.
func buildAlertQuery(startTime string, ruleIDs []string, size int, searchAfter []interface{}) map[string]interface{} {
	q := map[string]interface{}{
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
			// Départage sur un champ UNIQUE : sans lui l'ordre n'est pas total et la
			// pagination saute ou duplique des alertes en plein pic d'attaque.
			{alertSortTiebreaker: map[string]interface{}{"order": "desc", "unmapped_type": "keyword"}},
		},
	}
	if len(searchAfter) > 0 {
		q["search_after"] = searchAfter
	}
	return q
}

// AlertWindow is the result of one poll of the alerts index. It carries what the
// caller needs to advance a cursor SAFELY:
//
//   - Alerts, newest first;
//   - Truncated, true when the hard cap (or an unusable sort) stopped the walk
//     before the window was exhausted — older alerts of the window were NOT read;
//   - OldestReturned, the timestamp of the oldest alert actually returned.
//
// A caller that polls "since the last cursor" must, on a truncated window, place its
// cursor on OldestReturned and NOT on the end of the window: everything older than
// the last alert read has not been seen yet, and a security alert skipped is skipped
// for good.
type AlertWindow struct {
	Alerts         []WazuhAlert
	Truncated      bool
	OldestReturned string
	// TotalReported is the indexer's own count for the query (capped at 10 000 by
	// OpenSearch's default track_total_hits), useful to size what a truncated window
	// left behind.
	TotalReported int
}

// alertTimestampLayouts are the shapes a Wazuh alert timestamp takes across
// versions ("+0000" and "+00:00" offsets, with or without milliseconds).
var alertTimestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999-0700",
	"2006-01-02T15:04:05-0700",
}

// parseAlertTimestamp tries every known layout on a raw alert timestamp.
func parseAlertTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range alertTimestampLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Time parses the alert's own timestamp. ok=false quand il est absent ou d'un
// format inconnu — l'appelant rend alors le message sans horodatage plutôt que
// d'en inventer un.
func (a WazuhAlert) Time() (time.Time, bool) {
	return parseAlertTimestamp(a.Timestamp)
}

// OldestReturnedTime parses OldestReturned into a time.Time. The second result is
// false when the window is empty or the timestamp is unparsable — in which case a
// caller must keep its previous cursor rather than invent one.
func (a AlertWindow) OldestReturnedTime() (time.Time, bool) {
	return parseAlertTimestamp(a.OldestReturned)
}

// sealOldest records the timestamp of the oldest alert actually returned. The sort
// is timestamp desc, so it is the last element.
func (a *AlertWindow) sealOldest() {
	if n := len(a.Alerts); n > 0 {
		a.OldestReturned = a.Alerts[n-1].Timestamp
	}
}

// GetRecentAlerts fetches the security alerts of the last `duration` from the Wazuh
// alerts index, paging through the WHOLE window (up to maxAlertsPerPoll). Alerts are
// returned newest first. Callers that advance a cursor should prefer
// GetRecentAlertsWindow, which also says whether the window was truncated.
func (w *WazuhIndexerClient) GetRecentAlerts(duration time.Duration) ([]WazuhAlert, error) {
	win, err := w.GetRecentAlertsWindow(duration)
	if err != nil {
		return nil, err
	}
	return win.Alerts, nil
}

// GetRecentAlertsWindow fetches the alerts of the last `duration`, paging with
// search_after over a TOTAL order (timestamp desc, _id desc) up to maxAlertsPerPoll.
//
// Why search_after and not from/size: the SOAR worker advances its cursor past the
// window it just polled, so a skipped alert is a permanently lost alert. A from/size
// walk re-sorts the whole result set on every page — any alert indexed between two
// pages shifts the offsets — and the previous tie-breaker (rule.id) does not
// discriminate at all during a burst (a hundred SSH failures share timestamp AND
// rule.id). search_after resumes exactly on the sort values of the last hit read.
//
// Truncation is never silent: it is logged AND reported in the returned window so
// the caller can hold its cursor on the oldest alert actually read.
func (w *WazuhIndexerClient) GetRecentAlertsWindow(duration time.Duration) (AlertWindow, error) {
	startTime := time.Now().Add(-duration).Format(time.RFC3339)
	ruleIDs := w.alertRuleIDs()

	var win AlertWindow
	var searchAfter []interface{}
	for {
		if len(win.Alerts) >= maxAlertsPerPoll {
			slog.Warn("Indexer: alert window truncated at the hard cap — older alerts of this window were NOT returned",
				"cap", maxAlertsPerPoll, "window", duration.String(),
				"total_reported", win.TotalReported, "oldest_returned", win.Alerts[len(win.Alerts)-1].Timestamp)
			win.Truncated = true
			break
		}
		size := alertPageSize
		if remaining := maxAlertsPerPoll - len(win.Alerts); remaining < size {
			size = remaining
		}

		hits, total, err := w.fetchAlertPage(startTime, ruleIDs, size, searchAfter)
		if err != nil {
			// A mid-window failure must not hide what has already been collected: the
			// caller decides (the SOAR worker keeps its cursor on error).
			return AlertWindow{}, err
		}
		win.TotalReported = total
		for _, hit := range hits {
			win.Alerts = append(win.Alerts, hit.Source)
		}
		if len(hits) < size {
			// Last page: the window is exhausted.
			win.sealOldest()
			return win, nil
		}

		last := hits[len(hits)-1]
		if len(last.Sort) == 0 {
			// Sans valeurs de tri, impossible de reprendre sans risquer de sauter ou de
			// dupliquer des alertes : on s'arrête en le disant, plutôt que de retomber
			// sur un from/size instable.
			slog.Warn("Indexer: hits sans valeurs de tri — pagination interrompue, la fenêtre est incomplète",
				"collected", len(win.Alerts), "window", duration.String(), "total_reported", total)
			win.Truncated = true
			break
		}
		searchAfter = last.Sort
	}
	win.sealOldest()
	return win, nil
}

// alertHit is one hit of the alerts search: its source document plus the sort values
// that let the next page resume exactly after it.
type alertHit struct {
	Source WazuhAlert
	Sort   []interface{}
}

// fetchAlertPage runs one page of the alert search and returns its hits plus the
// indexer's total count for the query. searchAfter is nil for the first page.
func (w *WazuhIndexerClient) fetchAlertPage(startTime string, ruleIDs []string, size int, searchAfter []interface{}) ([]alertHit, int, error) {
	queryBytes, err := json.Marshal(buildAlertQuery(startTime, ruleIDs, size, searchAfter))
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

	hits := make([]alertHit, 0, len(alertResp.Hits.Hits))
	for _, hit := range alertResp.Hits.Hits {
		sortVals := hit.Sort
		if len(sortVals) == 0 && hit.Source.ID != "" {
			// Repli : certains proxys d'indexer omettent `sort` dans la réponse. Le
			// couple (timestamp, id) est exactement la clé de tri demandée, donc il
			// reconstitue un search_after valide.
			sortVals = []interface{}{hit.Source.Timestamp, hit.Source.ID}
		}
		hits = append(hits, alertHit{Source: hit.Source, Sort: sortVals})
	}
	return hits, alertResp.Hits.Total.Value, nil
}
