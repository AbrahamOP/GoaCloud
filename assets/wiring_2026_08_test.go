package assets

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Garde-fous sur le CÂBLAGE des correctifs d'août 2026 : du code de service
// correct existait déjà, mais aucune vue ne l'appelait. Une interface qui
// enregistre un réglage inerte est un défaut à part entière — c'est exactement
// ce que l'audit d'origine reprochait au produit.

// --------------------------------------------------------------------------
// 1. Rétention des archives : l'interrupteur doit exister et être explicite
// --------------------------------------------------------------------------

// TestRetentionSwitchIsWired : le champ « conserver N archives » ne pilote plus
// rien depuis que la rotation est passée en opt-in (retention_enabled). Sans
// l'interrupteur dans la requête, l'exploitant règle une valeur, l'interface
// confirme l'enregistrement, et aucune archive n'est jamais purgée.
func TestRetentionSwitchIsWired(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "backups.html"))

	if !strings.Contains(body, "retention_enabled:") {
		t.Error("backups.html: la requête /api/backups/target-settings n'envoie pas retention_enabled — le réglage de rétention reste inerte")
	}
	if !strings.Contains(body, "hc-rotation") {
		t.Error("backups.html: aucune case à cocher d'activation de la rotation")
	}
	// L'état affiché doit venir de la base, sinon la case se réaffiche décochée
	// sur une cible dont la purge est armée.
	if !strings.Contains(body, "{{if .Target.RetentionEnabled}}checked{{end}}") {
		t.Error("backups.html: la case d'activation ne reflète pas .Target.RetentionEnabled")
	}
}

// TestRetentionActivationIsConfirmed : armer la rotation autorise la suppression
// définitive d'archives, y compris celles que GoaCore n'a pas produites. Ça ne
// peut pas se jouer sur un clic de « Enregistrer » sans confirmation.
func TestRetentionActivationIsConfirmed(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "backups.html"))

	if !strings.Contains(body, `id="retention-confirm-modal"`) {
		t.Fatal("backups.html: aucune modale de confirmation pour l'activation de la suppression automatique")
	}
	// La confirmation doit NOMMER la machine concernée : « êtes-vous sûr ? » sans
	// sujet est ce qui fait cliquer sans lire.
	if !strings.Contains(body, `id="rtc-target-name"`) || !strings.Contains(body, "rtc-target-name').textContent") {
		t.Error("backups.html: la confirmation ne nomme pas la machine visée")
	}
	// Et dire ce qui va être détruit, y compris hors de son propre périmètre.
	if !strings.Contains(body, "vzdump") {
		t.Error("backups.html: la confirmation n'avertit pas que les archives d'un job vzdump du client seront purgées elles aussi")
	}
	// La modale doit passer par la pile partagée (Échap, piège de focus).
	if !strings.Contains(body, "GoaUI.openModal('retention-confirm-modal')") {
		t.Error("backups.html: la modale de rétention n'est pas ouverte via GoaUI.openModal")
	}
}

// --------------------------------------------------------------------------
// 2. Épinglage des clés d'hôte : le parcours d'amorçage TOFU
// --------------------------------------------------------------------------

// TestHostKeyPinningJourneyExists : sans écran d'amorçage, le durcissement
// d'Ansible (refus de tout hôte non épinglé) n'a aucune sortie et les
// planifications restent cassées à jamais.
func TestHostKeyPinningJourneyExists(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "ssh_keys.html"))

	for _, route := range []string{
		"/api/ssh/host-keys/scan",
		"/api/ssh/host-keys/pin",
		"/api/ssh/host-keys",
	} {
		if !strings.Contains(body, route) {
			t.Errorf("ssh_keys.html: la route %s n'est appelée nulle part", route)
		}
	}
	// La révocation est un DELETE, pas un POST déguisé.
	if !regexp.MustCompile(`(?s)/api/ssh/host-keys'.{0,120}method:\s*'DELETE'`).MatchString(body) {
		t.Error("ssh_keys.html: la révocation n'utilise pas DELETE /api/ssh/host-keys")
	}
	// Le cœur du parcours : l'exploitant compare l'empreinte SUR la machine.
	// Épingler ce que le réseau vient d'annoncer sans le vérifier, c'est du TOFU
	// aveugle — l'amorçage est le seul moment où l'interception est détectable.
	if !strings.Contains(body, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub") {
		t.Error("ssh_keys.html: la consigne de comparaison hors bande (ssh-keygen -lf) est absente")
	}
	if !strings.Contains(body, `id="hostkey-fingerprint"`) {
		t.Error("ssh_keys.html: l'empreinte récupérée n'est pas affichée")
	}
}

// TestHostKeyDataIsEscaped : l'IP saisie et l'empreinte renvoyée par le serveur
// atterrissent dans le DOM. Elles y vont par textContent, jamais en HTML.
func TestHostKeyDataIsEscaped(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "ssh_keys.html"))
	for _, id := range []string{"hostkey-fingerprint", "hostkey-result-ip", "revoke-hostkey-ip"} {
		if !strings.Contains(body, "'"+id+"').textContent") {
			t.Errorf("ssh_keys.html: #%s n'est pas rempli via textContent", id)
		}
		if strings.Contains(body, "'"+id+"').innerHTML") {
			t.Errorf("ssh_keys.html: #%s est rempli via innerHTML — donnée non échappée", id)
		}
	}
}
