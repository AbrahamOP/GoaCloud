package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// alertSearchStub monte un faux Indexer qui répond aux recherches d'alertes avec un
// jeu de `total` hits paginé, et enregistre les offsets `from` demandés. Il permet de
// vérifier que la fenêtre est parcourue en ENTIER (une alerte de sécurité perdue est
// perdue pour de bon : le worker SOAR avance son curseur derrière).
func alertSearchStub(t *testing.T, total int) (*WazuhIndexerClient, *[]int) {
	t.Helper()
	var offsets []int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			From int `json:"from"`
			Size int `json:"size"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("requête illisible: %v", err)
		}
		offsets = append(offsets, body.From)

		count := total - body.From
		if count > body.Size {
			count = body.Size
		}
		if count < 0 {
			count = 0
		}
		hits := make([]map[string]any, 0, count)
		for i := 0; i < count; i++ {
			hits = append(hits, map[string]any{
				"_source": map[string]any{
					"timestamp": "2026-08-04T10:00:00Z",
					"rule":      map[string]any{"id": fmt.Sprintf("%d", 5700+body.From+i)},
				},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": total},
				"hits":  hits,
			},
		})
	}))
	t.Cleanup(srv.Close)

	return NewWazuhIndexerClient(srv.URL, "user", "pass", true), &offsets
}

// TestGetRecentAlerts_PagesTheWholeWindow : au-delà d'une page, les alertes suivantes
// doivent être récupérées, pas abandonnées silencieusement.
func TestGetRecentAlerts_PagesTheWholeWindow(t *testing.T) {
	const total = alertPageSize*2 + 10
	client, offsets := alertSearchStub(t, total)

	alerts, err := client.GetRecentAlerts(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlerts: %v", err)
	}
	if len(alerts) != total {
		t.Fatalf("%d alertes récupérées sur %d — des alertes ont été perdues", len(alerts), total)
	}
	want := []int{0, alertPageSize, 2 * alertPageSize}
	if len(*offsets) != len(want) {
		t.Fatalf("offsets demandés %v, attendu %v", *offsets, want)
	}
	for i, off := range want {
		if (*offsets)[i] != off {
			t.Fatalf("offsets demandés %v, attendu %v", *offsets, want)
		}
	}
}

// TestGetRecentAlerts_SinglePartialPage : une fenêtre plus petite qu'une page ne doit
// coûter qu'une seule requête.
func TestGetRecentAlerts_SinglePartialPage(t *testing.T) {
	client, offsets := alertSearchStub(t, 3)

	alerts, err := client.GetRecentAlerts(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlerts: %v", err)
	}
	if len(alerts) != 3 {
		t.Fatalf("%d alertes, attendu 3", len(alerts))
	}
	if len(*offsets) != 1 {
		t.Fatalf("%d requêtes émises, attendu 1", len(*offsets))
	}
}

// TestGetRecentAlerts_StopsAtHardCap : la pagination est bornée (mémoire + charge
// Indexer) mais s'arrête net au plafond au lieu de boucler.
func TestGetRecentAlerts_StopsAtHardCap(t *testing.T) {
	client, offsets := alertSearchStub(t, maxAlertsPerPoll*2)

	alerts, err := client.GetRecentAlerts(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlerts: %v", err)
	}
	if len(alerts) != maxAlertsPerPoll {
		t.Fatalf("%d alertes, attendu le plafond %d", len(alerts), maxAlertsPerPoll)
	}
	if want := maxAlertsPerPoll / alertPageSize; len(*offsets) != want {
		t.Fatalf("%d requêtes émises, attendu %d", len(*offsets), want)
	}
}

// TestGetRecentAlerts_MissingIndex : un index absent (404) reste un cas non-erreur.
func TestGetRecentAlerts_MissingIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "index_not_found_exception", http.StatusNotFound)
	}))
	defer srv.Close()

	client := NewWazuhIndexerClient(srv.URL, "user", "pass", true)
	alerts, err := client.GetRecentAlerts(time.Hour)
	if err != nil {
		t.Fatalf("un index absent ne doit pas être une erreur: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("%d alertes retournées sur un index absent", len(alerts))
	}
}

// TestBuildAlertQuery vérifie la pagination et le filtre de règles injectés dans la
// requête, y compris le départage de tri (sans lui, deux alertes de même horodatage —
// le cas normal en pic d'attaque — se dupliquent ou disparaissent entre deux pages).
func TestBuildAlertQuery(t *testing.T) {
	q := buildAlertQuery("2026-08-04T10:00:00Z", []string{"5710", "5402"}, 500, 250)

	if q["from"] != 500 || q["size"] != 250 {
		t.Fatalf("from/size = %v/%v, attendu 500/250", q["from"], q["size"])
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)
	for _, needle := range []string{`"5710"`, `"5402"`, `"2026-08-04T10:00:00Z"`, `"timestamp"`, `"rule.id"`} {
		if !strings.Contains(body, needle) {
			t.Fatalf("requête sans %s: %s", needle, body)
		}
	}
	sorts, ok := q["sort"].([]map[string]interface{})
	if !ok || len(sorts) != 2 {
		t.Fatalf("tri = %v, attendu un tri principal + un départage", q["sort"])
	}
}

// TestSetAlertRuleIDs : le filtre de règles est configurable, mais une liste vide ne
// doit jamais rendre le pipeline SOAR muet.
func TestSetAlertRuleIDs(t *testing.T) {
	c := NewWazuhIndexerClient("https://indexer.example:9200", "u", "p", true)
	if len(c.alertRuleIDs()) != len(defaultAlertRuleIDs) {
		t.Fatalf("sélection par défaut = %v", c.alertRuleIDs())
	}

	c.SetAlertRuleIDs([]string{" 100200 ", "", "100201"})
	got := c.alertRuleIDs()
	if len(got) != 2 || got[0] != "100200" || got[1] != "100201" {
		t.Fatalf("règles configurées = %v, attendu [100200 100201]", got)
	}

	c.SetAlertRuleIDs([]string{"  ", ""})
	if got := c.alertRuleIDs(); len(got) != 2 || got[0] != "100200" {
		t.Fatalf("une liste vide a écrasé la configuration: %v", got)
	}

	// Le défaut du paquet ne doit pas avoir été altéré par une configuration.
	fresh := NewWazuhIndexerClient("https://indexer.example:9200", "u", "p", true)
	if len(fresh.alertRuleIDs()) != len(defaultAlertRuleIDs) {
		t.Fatalf("la sélection par défaut a été mutée: %v", fresh.alertRuleIDs())
	}
}
