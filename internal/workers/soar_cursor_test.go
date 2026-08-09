package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"goacore/internal/models"
	"goacore/internal/services"
)

// Ces tests couvrent le câblage du curseur d'alertes du worker SOAR sur l'API
// fenêtrée de l'Indexer (GetRecentAlertsWindow). L'enjeu : une fenêtre TRONQUÉE
// (plafond atteint pendant un pic d'attaque) ne doit jamais faire avancer le curseur
// au-delà de ce qui a réellement été lu, sinon la queue de fenêtre est perdue pour
// de bon.

// stubIndexer monte un faux Indexer paginé par search_after servant `total` alertes,
// la plus récente en premier, espacées d'une seconde. Il renvoie le client pointé
// dessus ainsi que l'horodatage de la plus ancienne alerte du corpus.
func stubIndexer(t *testing.T, total int) (*services.WazuhIndexerClient, time.Time) {
	t.Helper()

	base := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	ts := func(i int) string { return base.Add(-time.Duration(i) * time.Second).Format(time.RFC3339) }
	id := func(i int) string { return fmt.Sprintf("%d.%d", base.Unix(), i) }

	// Position de reprise : l'index de l'alerte dont search_after porte l'_id.
	pos := map[string]int{}
	for i := 0; i < total; i++ {
		pos[id(i)] = i
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Size        int           `json:"size"`
			SearchAfter []interface{} `json:"search_after"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("requête illisible: %v", err)
		}
		start := 0
		if len(body.SearchAfter) == 2 {
			last, _ := body.SearchAfter[1].(string)
			p, ok := pos[last]
			if !ok {
				t.Errorf("search_after inconnu: %v", body.SearchAfter)
			}
			start = p + 1
		}
		end := start + body.Size
		if end > total {
			end = total
		}

		var b strings.Builder
		fmt.Fprintf(&b, `{"hits":{"total":{"value":%d},"hits":[`, total)
		for i := start; i < end; i++ {
			if i > start {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"_source":{"id":%q,"timestamp":%q,`+
				`"rule":{"id":"5710","level":5,"description":"sshd auth failed"},`+
				`"agent":{"id":"001","name":"srv","ip":"10.0.0.1"},`+
				`"data":{"srcip":"203.0.113.7"},"full_log":"log"},"sort":[%q,%q]}`,
				id(i), ts(i), ts(i), id(i))
		}
		b.WriteString(`]}}`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(srv.Close)

	client := services.NewWazuhIndexerClient(srv.URL, "u", "p", true)
	oldest := base.Add(-time.Duration(total-1) * time.Second)
	return client, oldest
}

// runTick exécute un tick SOAR complet contre l'Indexer stub, toutes les catégories
// d'alerte désactivées (on ne teste ici que la position du curseur, pas le fan-out
// Discord). Renvoie le curseur après le tick.
func runTick(t *testing.T, indexer *services.WazuhIndexerClient, cursor time.Time) time.Time {
	t.Helper()
	cfg := &models.SoarConfigState{Loaded: true} // toutes catégories à false
	checkSoarEvents(
		context.Background(),
		nil,                     // db : la persistance du curseur est no-op (loadSoarState/saveSoarState nil-safe)
		&services.WazuhClient{}, // non nil : sinon checkSoarEvents sort tout de suite
		indexer,
		nil, nil,
		cfg,
		&sync.Map{}, &sync.Map{},
		&cursor,
	)
	return cursor
}

// TestCheckSoarEventsCursorTruncatedWindow : sur une fenêtre tronquée au plafond
// (pic d'attaque), le curseur doit rester sur la plus ancienne alerte RÉELLEMENT
// lue. S'il avançait à pollStart, tout ce que le plafond a laissé derrière ne serait
// jamais relu — des alertes de sécurité perdues définitivement.
func TestCheckSoarEventsCursorTruncatedWindow(t *testing.T) {
	// Un corpus plus grand que le plafond de l'Indexer garantit la troncature.
	const total = 5100
	indexer, _ := stubIndexer(t, total)

	before := time.Now()
	got := runTick(t, indexer, before.Add(-2*time.Minute))

	if !got.Before(before) {
		t.Fatalf("curseur = %s : il a dépassé le début du poll (%s) alors que la fenêtre est tronquée — la queue de fenêtre est perdue",
			got.Format(time.RFC3339), before.Format(time.RFC3339))
	}
	// La 5000e alerte lue (plafond maxAlertsPerPoll) est datée de base-4999s.
	want := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC).Add(-4999 * time.Second)
	if !got.Equal(want) {
		t.Fatalf("curseur = %s, attendu %s (horodatage de la plus ancienne alerte lue)",
			got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

// TestCheckSoarEventsCursorCompleteWindow : sans troncature, le comportement d'origine
// est conservé — le curseur avance au début du poll, sinon chaque tick relirait (et
// republierait) la même fenêtre.
func TestCheckSoarEventsCursorCompleteWindow(t *testing.T) {
	indexer, oldest := stubIndexer(t, 3)

	before := time.Now()
	got := runTick(t, indexer, before.Add(-2*time.Minute))
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Fatalf("curseur = %s : attendu le début du poll (entre %s et %s) sur une fenêtre complète",
			got.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
	}
	if got.Equal(oldest) {
		t.Fatal("curseur figé sur la plus ancienne alerte alors que la fenêtre est complète : la même fenêtre serait relue à chaque tick")
	}
}

// TestNextAlertCursor épingle la règle de décision isolément, y compris le repli
// quand l'horodatage de reprise est inexploitable.
func TestNextAlertCursor(t *testing.T) {
	pollStart := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	oldest := time.Date(2026, 8, 4, 11, 30, 0, 0, time.UTC)

	cases := []struct {
		name string
		win  services.AlertWindow
		want time.Time
	}{
		{
			name: "fenêtre complète : curseur au début du poll",
			win:  services.AlertWindow{OldestReturned: oldest.Format(time.RFC3339)},
			want: pollStart,
		},
		{
			name: "fenêtre tronquée : curseur sur la plus ancienne alerte lue",
			win:  services.AlertWindow{Truncated: true, OldestReturned: oldest.Format(time.RFC3339)},
			want: oldest,
		},
		{
			name: "tronquée sans horodatage exploitable : repli sur le début du poll",
			win:  services.AlertWindow{Truncated: true, OldestReturned: "pas-une-date"},
			want: pollStart,
		},
		{
			name: "tronquée et vide : repli sur le début du poll",
			win:  services.AlertWindow{Truncated: true},
			want: pollStart,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := nextAlertCursor(tc.win, pollStart); !got.Equal(tc.want) {
				t.Fatalf("nextAlertCursor = %s, want %s", got.Format(time.RFC3339), tc.want.Format(time.RFC3339))
			}
		})
	}
}

// TestAlertDedupKeyBurst est la non-régression du bug de dédup : cent échecs SSH du
// même agent, de la même règle et de la MÊME seconde sont cent alertes distinctes.
// L'ancienne clé (agent:rule:timestamp) les confondait et en écartait 99.
func TestAlertDedupKeyBurst(t *testing.T) {
	newAlert := func(id string) services.WazuhAlert {
		var a services.WazuhAlert
		a.ID = id
		a.Timestamp = "2026-08-04T10:00:00Z"
		a.Rule.ID = "5710"
		a.Agent.ID = "001"
		return a
	}

	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		key := alertDedupKey(newAlert(fmt.Sprintf("1770000000.%d", i)))
		if seen[key] {
			t.Fatalf("clé %q déjà vue : deux alertes distinctes du même pic sont confondues", key)
		}
		seen[key] = true
	}
	if len(seen) != 100 {
		t.Fatalf("%d clés distinctes pour 100 alertes", len(seen))
	}
}

// TestAlertDedupKeyFallback : sans identifiant Wazuh (indexeur ancien, ou entrée déjà
// persistée avant le correctif), la clé historique reste utilisée telle quelle.
func TestAlertDedupKeyFallback(t *testing.T) {
	var a services.WazuhAlert
	a.Timestamp = "2026-08-04T10:00:00Z"
	a.Rule.ID = "5402"
	a.Agent.ID = "001"

	if got, want := alertDedupKey(a), "001:5402:2026-08-04T10:00:00Z"; got != want {
		t.Fatalf("clé de repli = %q, want %q", got, want)
	}

	a.ID = "  " // uniquement des blancs : traité comme absent
	if got, want := alertDedupKey(a), "001:5402:2026-08-04T10:00:00Z"; got != want {
		t.Fatalf("clé de repli (ID blanc) = %q, want %q", got, want)
	}
}
