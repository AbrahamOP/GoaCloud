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

// alertStubHit est une alerte du faux Indexer : son horodatage et son _id (le
// départage unique du tri).
type alertStubHit struct {
	timestamp string
	id        string
	ruleID    string
}

// alertSearchStub monte un faux Indexer qui sert `total` alertes paginées par
// search_after, et enregistre les curseurs reçus. Il permet de vérifier que la
// fenêtre est parcourue en ENTIER (une alerte de sécurité perdue est perdue pour de
// bon : le worker SOAR avance son curseur derrière) et que la pagination reprend
// exactement là où elle s'était arrêtée.
//
// Toutes les alertes partagent le MÊME horodatage et la MÊME règle : c'est le pic
// d'attaque (100 échecs SSH dans la seconde) qui rendait l'ancien tri instable.
func alertSearchStub(t *testing.T, total int) (*WazuhIndexerClient, *[][]interface{}) {
	t.Helper()
	corpus := make([]alertStubHit, 0, total)
	for i := 0; i < total; i++ {
		corpus = append(corpus, alertStubHit{
			timestamp: "2026-08-04T10:00:00Z",
			// id décroissant : le corpus est déjà dans l'ordre du tri demandé.
			id:     fmt.Sprintf("id-%06d", total-i),
			ruleID: "5710",
		})
	}
	return alertSearchStubCorpus(t, corpus)
}

// alertSearchStubCorpus sert un corpus explicite, dans l'ordre donné.
func alertSearchStubCorpus(t *testing.T, corpus []alertStubHit) (*WazuhIndexerClient, *[][]interface{}) {
	t.Helper()
	var cursors [][]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Size        int           `json:"size"`
			SearchAfter []interface{} `json:"search_after"`
			From        *int          `json:"from"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("requête illisible: %v", err)
		}
		if body.From != nil {
			t.Errorf("la pagination ne doit plus utiliser `from` (tri instable), reçu %d", *body.From)
		}
		cursors = append(cursors, body.SearchAfter)

		// Reprise du curseur : on repart juste après le _id transmis.
		start := 0
		if len(body.SearchAfter) == 2 {
			lastID, _ := body.SearchAfter[1].(string)
			for i, h := range corpus {
				if h.id == lastID {
					start = i + 1
					break
				}
			}
		}
		hits := make([]map[string]any, 0, body.Size)
		for i := start; i < len(corpus) && len(hits) < body.Size; i++ {
			h := corpus[i]
			hits = append(hits, map[string]any{
				"sort": []any{h.timestamp, h.id},
				"_source": map[string]any{
					"id":        h.id,
					"timestamp": h.timestamp,
					"rule":      map[string]any{"id": h.ruleID},
				},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": len(corpus)},
				"hits":  hits,
			},
		}); err != nil {
			t.Errorf("encodage de la réponse: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	return NewWazuhIndexerClient(srv.URL, "user", "pass", true), &cursors
}

// TestGetRecentAlerts_PagesTheWholeWindow : au-delà d'une page, les alertes suivantes
// doivent être récupérées, pas abandonnées silencieusement.
func TestGetRecentAlerts_PagesTheWholeWindow(t *testing.T) {
	const total = alertPageSize*2 + 10
	client, cursors := alertSearchStub(t, total)

	alerts, err := client.GetRecentAlerts(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlerts: %v", err)
	}
	if len(alerts) != total {
		t.Fatalf("%d alertes récupérées sur %d — des alertes ont été perdues", len(alerts), total)
	}
	if len(*cursors) != 3 {
		t.Fatalf("%d requêtes émises, attendu 3", len(*cursors))
	}
	if (*cursors)[0] != nil {
		t.Fatalf("la première page ne doit pas porter de curseur, reçu %v", (*cursors)[0])
	}
	for i := 1; i < len(*cursors); i++ {
		if len((*cursors)[i]) != 2 {
			t.Fatalf("page %d sans search_after complet: %v", i, (*cursors)[i])
		}
	}
}

// TestGetRecentAlerts_NoDuplicateNorGapOnIdenticalTimestamps est le cœur du correctif :
// 100 échecs SSH de même rule.id dans la même seconde. L'ancien tri (timestamp desc,
// rule.id desc) ne départageait rien, et une pagination from/size sautait ou dupliquait
// des alertes. Avec search_after sur un champ unique, chaque alerte est vue une fois.
func TestGetRecentAlerts_NoDuplicateNorGapOnIdenticalTimestamps(t *testing.T) {
	const total = alertPageSize + 37
	corpus := make([]alertStubHit, 0, total)
	for i := 0; i < total; i++ {
		corpus = append(corpus, alertStubHit{
			timestamp: "2026-08-04T10:00:00.000Z",
			id:        fmt.Sprintf("burst-%04d", total-i),
			ruleID:    "5710",
		})
	}
	client, _ := alertSearchStubCorpus(t, corpus)

	win, err := client.GetRecentAlertsWindow(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlertsWindow: %v", err)
	}
	if len(win.Alerts) != total {
		t.Fatalf("%d alertes sur %d — la pagination saute ou duplique", len(win.Alerts), total)
	}
	if win.Truncated {
		t.Fatal("fenêtre marquée tronquée alors qu'elle a été épuisée")
	}
}

// TestGetRecentAlerts_SinglePartialPage : une fenêtre plus petite qu'une page ne doit
// coûter qu'une seule requête.
func TestGetRecentAlerts_SinglePartialPage(t *testing.T) {
	client, cursors := alertSearchStub(t, 3)

	alerts, err := client.GetRecentAlerts(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlerts: %v", err)
	}
	if len(alerts) != 3 {
		t.Fatalf("%d alertes, attendu 3", len(alerts))
	}
	if len(*cursors) != 1 {
		t.Fatalf("%d requêtes émises, attendu 1", len(*cursors))
	}
}

// TestGetRecentAlerts_StopsAtHardCap : la pagination est bornée (mémoire + charge
// Indexer) mais s'arrête net au plafond au lieu de boucler — ET la troncature est
// annoncée, avec l'horodatage de la plus ancienne alerte RÉELLEMENT lue, pour que
// l'appelant ne pousse pas son curseur au-delà de ce qu'il a vu.
func TestGetRecentAlerts_StopsAtHardCap(t *testing.T) {
	client, cursors := alertSearchStub(t, maxAlertsPerPoll*2)

	win, err := client.GetRecentAlertsWindow(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlertsWindow: %v", err)
	}
	if len(win.Alerts) != maxAlertsPerPoll {
		t.Fatalf("%d alertes, attendu le plafond %d", len(win.Alerts), maxAlertsPerPoll)
	}
	if want := maxAlertsPerPoll / alertPageSize; len(*cursors) != want {
		t.Fatalf("%d requêtes émises, attendu %d", len(*cursors), want)
	}
	if !win.Truncated {
		t.Fatal("une fenêtre tronquée au plafond doit être signalée comme telle")
	}
	if win.OldestReturned != win.Alerts[len(win.Alerts)-1].Timestamp {
		t.Fatalf("curseur de reprise = %q, attendu l'horodatage de la plus ancienne alerte lue %q",
			win.OldestReturned, win.Alerts[len(win.Alerts)-1].Timestamp)
	}
}

// TestAlertWindow_OldestReturnedTime : le curseur de reprise doit être exploitable
// tel quel, quels que soient les formats d'horodatage servis par Wazuh.
func TestAlertWindow_OldestReturnedTime(t *testing.T) {
	cases := map[string]bool{
		"2026-08-04T10:00:00Z":             true,
		"2026-08-04T10:00:00.123+0000":     true,
		"2026-08-04T10:00:00.123456+02:00": true,
		"pas une date":                     false,
		"":                                 false,
	}
	for raw, want := range cases {
		win := AlertWindow{OldestReturned: raw}
		if _, ok := win.OldestReturnedTime(); ok != want {
			t.Fatalf("OldestReturnedTime(%q) ok=%v, attendu %v", raw, ok, want)
		}
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

// TestGetRecentAlerts_StopsWhenSortValuesMissing : sans valeurs de tri, impossible de
// reprendre sans risquer de sauter des alertes — on s'arrête en signalant la
// troncature au lieu de retomber sur un from/size instable.
func TestGetRecentAlerts_StopsWhenSortValuesMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits := make([]map[string]any, 0, alertPageSize)
		for i := 0; i < alertPageSize; i++ {
			// Ni "sort" ni identifiant d'alerte : aucun curseur reconstituable.
			hits = append(hits, map[string]any{
				"_source": map[string]any{"timestamp": "2026-08-04T10:00:00Z"},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"total": map[string]any{"value": 99999}, "hits": hits},
		})
	}))
	defer srv.Close()

	client := NewWazuhIndexerClient(srv.URL, "user", "pass", true)
	win, err := client.GetRecentAlertsWindow(time.Hour)
	if err != nil {
		t.Fatalf("GetRecentAlertsWindow: %v", err)
	}
	if len(win.Alerts) != alertPageSize {
		t.Fatalf("%d alertes, attendu une seule page %d", len(win.Alerts), alertPageSize)
	}
	if !win.Truncated {
		t.Fatal("une pagination interrompue faute de curseur doit être signalée tronquée")
	}
}

// TestBuildAlertQuery vérifie la pagination et le filtre de règles injectés dans la
// requête, y compris le départage de tri sur un champ UNIQUE (sans lui, deux alertes
// de même horodatage — le cas normal en pic d'attaque — se dupliquent ou
// disparaissent entre deux pages).
func TestBuildAlertQuery(t *testing.T) {
	q := buildAlertQuery("2026-08-04T10:00:00Z", []string{"5710", "5402"}, 250, nil)

	if q["size"] != 250 {
		t.Fatalf("size = %v, attendu 250", q["size"])
	}
	if _, present := q["from"]; present {
		t.Fatal("la requête ne doit plus porter de `from` : la pagination se fait par search_after")
	}
	if _, present := q["search_after"]; present {
		t.Fatal("la première page ne doit pas porter de search_after")
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)
	for _, needle := range []string{`"5710"`, `"5402"`, `"2026-08-04T10:00:00Z"`, `"timestamp"`, `"unmapped_type"`} {
		if !strings.Contains(body, needle) {
			t.Fatalf("requête sans %s: %s", needle, body)
		}
	}
	sorts, ok := q["sort"].([]map[string]interface{})
	if !ok || len(sorts) != 2 {
		t.Fatalf("tri = %v, attendu un tri principal + un départage", q["sort"])
	}
	if _, ok := sorts[1][alertSortTiebreaker]; !ok {
		t.Fatalf("le départage doit porter sur %s (champ unique), obtenu %v", alertSortTiebreaker, sorts[1])
	}

	// Page suivante : le curseur est transmis tel quel.
	next := buildAlertQuery("2026-08-04T10:00:00Z", []string{"5710"}, 250, []interface{}{"2026-08-04T10:00:00Z", "id-42"})
	after, ok := next["search_after"].([]interface{})
	if !ok || len(after) != 2 || after[1] != "id-42" {
		t.Fatalf("search_after = %v, attendu le curseur de la page précédente", next["search_after"])
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
