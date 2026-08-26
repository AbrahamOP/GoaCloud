package workers

import (
	"context"
	"sync"
	"testing"

	"goacore/internal/services"
)

// TestSendEnrichedAlertOnSentFailure vérifie le contrat at-least-once : quand le
// post Discord ne peut pas aboutir (bot non prêt), onSent doit être rappelé avec
// false pour que l'appelant rende la clé de dedup au pool (retry au tick suivant)
// — et non la marquer comme envoyée. C'est la correction du finding majeur de revue.
func TestSendEnrichedAlertOnSentFailure(t *testing.T) {
	var got *bool
	onSent := func(sent bool) { got = &sent }

	// discord == nil → échec de livraison garanti, sans I/O réseau.
	sendEnrichedAlert(context.Background(), services.AIAlertContext{Title: "x", Description: "y"}, "critical", "", nil, nil, onSent)

	if got == nil {
		t.Fatal("onSent n'a pas été appelé")
	}
	if *got != false {
		t.Fatal("onSent(true) sur échec de post — la clé serait marquée envoyée à tort")
	}
}

// TestDedupReleaseOnFailure simule le câblage réel worker : la clé est stockée en
// mémoire à la détection, puis le callback la retire sur échec de post → un tick
// ultérieur la retraitera (at-least-once), au lieu de la perdre définitivement.
func TestDedupReleaseOnFailure(t *testing.T) {
	dedup := &sync.Map{}
	const key = "001:5402:2026-07-07T00:00:00"

	dedup.Store(key, struct{}{}) // détection : anti double-fanout intra-tick
	onSent := func(sent bool) {
		if !sent {
			dedup.Delete(key)
		}
	}
	sendEnrichedAlert(context.Background(), services.AIAlertContext{Title: "x", Description: "y"}, "critical", "", nil, nil, onSent)

	if _, still := dedup.Load(key); still {
		t.Fatal("la clé est restée dedupée après échec de post — alerte perdue à jamais")
	}
}
