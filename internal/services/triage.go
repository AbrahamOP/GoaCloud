package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SOAR triage — classement apprenant des alertes (Wiz-like).
//
// Chaque alerte est réduite à une EMPREINTE stable (sha256 de ses champs
// discriminants) ; l'opérateur classe l'empreinte depuis les boutons Discord, et le
// worker SOAR supprime les occurrences futures des empreintes classées "by design"
// ou "faux positif" — sans jamais les rendre invisibles : chaque suppression est
// comptée et resurfacée par le digest hebdomadaire.

// Triage statuses. TriageOpen is the implicit state of any alert never classified.
const (
	TriageOpen          = "open"
	TriageByDesign      = "by_design"
	TriageFalsePositive = "false_positive"
	TriageInvestigating = "investigating"
	TriageResolved      = "resolved"
)

// TriageStatusSuppresses reports whether alerts fingerprinted under this status
// must be suppressed before posting. Only the two "cette alerte est du bruit"
// verdicts suppress: "investigating" and "resolved" keep posting — une alerte qui
// récidive pendant ou après traitement est une information, pas du bruit.
func TriageStatusSuppresses(status string) bool {
	return status == TriageByDesign || status == TriageFalsePositive
}

// triageDecisions are the statuses an operator can assign from the Discord
// buttons. "open" is deliberately absent: it is the default state, never a verdict.
var triageDecisions = map[string]bool{
	TriageByDesign:      true,
	TriageFalsePositive: true,
	TriageInvestigating: true,
	TriageResolved:      true,
}

// validTriageDecision reports whether status is an operator-assignable verdict.
func validTriageDecision(status string) bool {
	return triageDecisions[status]
}

// TriageFingerprint computes the stable triage fingerprint of an indexer alert:
// sha256(rule.id | agent.name | champ-clé) en hex.
//
// Le champ-clé dépend de la famille de règle, pour que le classement colle au
// geste de l'opérateur : un « by design » sur une alerte FIM vise CE fichier
// (path), un « by design » sur une alerte d'authentification vise CE compte
// (dstuser) — jamais l'IP source, qui varie légitimement. Les familles reprennent
// defaultAlertRuleIDs (wazuh_indexer.go) ; toute règle hors familles (ou un
// champ-clé absent sur un vieux mapping) retombe sur la description de la règle,
// stable pour une règle donnée.
func TriageFingerprint(a WazuhAlert) string {
	var key string
	switch a.Rule.ID {
	case "550", "553", "554": // FIM : le chemin surveillé identifie le constat
		key = a.Syscheck.Path
	case "5716", "5710", "5712", "5503": // auth : le compte visé
		key = a.Data.DstUser
	case "5402": // sudo : le compte QUI élève (dstuser vaudrait "root" partout —
		// une seule empreinte muterait toutes les élévations de l'agent)
		key = a.Data.SrcUser
	}
	if strings.TrimSpace(key) == "" {
		key = a.Rule.Description
	}
	return triageHash(a.Rule.ID, a.Agent.Name, key)
}

// TriageAgentStatusFingerprint fingerprints an agent status-change alert
// (Agent Perdu / Agent Retrouvé). Chaque direction a sa propre empreinte : une
// machine volontairement éteinte se classe « by design » sur "disconnected" ET
// sur "active", explicitement — jamais de suppression implicite de l'une par
// l'autre.
func TriageAgentStatusFingerprint(agentName, newStatus string) string {
	return triageHash("agent-status", agentName, newStatus)
}

// triageHash joins the normalized parts and hashes them. Normalization is
// whitespace-only (trim + collapse) : PAS de casse-folding, deux chemins FIM qui
// ne diffèrent que par la casse sont deux fichiers distincts sous Linux et ne
// doivent jamais partager une empreinte (une suppression ne doit jamais avaler
// une alerte réellement distincte).
func triageHash(parts ...string) string {
	norm := make([]string, len(parts))
	for i, p := range parts {
		norm[i] = strings.Join(strings.Fields(p), " ")
	}
	sum := sha256.Sum256([]byte(strings.Join(norm, "|")))
	return hex.EncodeToString(sum[:])
}

// isTriageFingerprint reports whether s looks like a fingerprint we produced
// (64 lowercase hex chars). Used to validate the fingerprint carried inside a
// Discord custom_id, which is attacker-visible client input.
func isTriageFingerprint(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// TriageDigestRow is one fingerprint's line in the weekly suppression digest.
type TriageDigestRow struct {
	Fingerprint     string
	RuleID          string
	AgentName       string
	Title           string
	Status          string
	SinceDigest     int
	TotalSuppressed int
}

// TriageStore persists triage verdicts and suppression counters (table
// soar_triage). Same conventions as the other stores: *sql.DB direct, nil-safe
// (a nil store or nil db degrades to "aucun classement" so the SOAR worker and
// the tests keep working without MySQL), errors wrapped for the caller to log.
type TriageStore struct {
	db *sql.DB
}

// NewTriageStore builds a TriageStore. db may be nil (tests, DB-less boot paths):
// every method then no-ops.
func NewTriageStore(db *sql.DB) *TriageStore {
	return &TriageStore{db: db}
}

// ready reports whether the store can reach a database.
func (s *TriageStore) ready() bool {
	return s != nil && s.db != nil
}

// Decision returns the status AND who decided it (both "" when never classified,
// same contract as an absent row) — le statut pilote la suppression, le décideur
// rend l'étiquette « classée par X » au (re)rendu d'un message.
func (s *TriageStore) Decision(fingerprint string) (status, decidedBy string, err error) {
	if !s.ready() {
		return "", "", nil
	}
	err = s.db.QueryRow("SELECT status, decided_by FROM soar_triage WHERE fingerprint = ?", fingerprint).
		Scan(&status, &decidedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("triage decision %q: %w", fingerprint, err)
	}
	return status, decidedBy, nil
}

// RecordSeen upserts the fingerprint row when its alert is POSTED (never called
// on a suppressed occurrence). A recurrence of a "resolved" fingerprint reopens
// it (une récidive après résolution est une régression) ; "investigating" est
// conservé. sample est la dernière alerte postée, en JSON (nil accepté), gardée
// pour la future similarité (phase 2 Qdrant) et la page dashboard (phase 3).
func (s *TriageStore) RecordSeen(fingerprint, ruleID, agentName, title string, sample []byte) error {
	if !s.ready() {
		return nil
	}
	var sampleVal interface{}
	if len(sample) > 0 {
		sampleVal = string(sample)
	}
	_, err := s.db.Exec(`
		INSERT INTO soar_triage (fingerprint, status, rule_id, agent_name, title, sample_alert, first_seen, last_seen)
		VALUES (?, 'open', ?, ?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE
			last_seen = NOW(),
			rule_id = VALUES(rule_id),
			agent_name = VALUES(agent_name),
			title = VALUES(title),
			sample_alert = COALESCE(VALUES(sample_alert), sample_alert),
			status = IF(status = 'resolved', 'open', status)`,
		fingerprint, ruleID, truncateRunes(agentName, 180), truncateRunes(title, 180), sampleVal)
	if err != nil {
		return fmt.Errorf("triage record seen %q: %w", fingerprint, err)
	}
	return nil
}

// RecordSuppressed counts one suppressed occurrence (post évité). Les deux
// compteurs avancent : le total vie-entière et celui du digest en cours.
// Row absente = no-op silencieux (un classement ne peut venir que d'une row).
func (s *TriageStore) RecordSuppressed(fingerprint string) error {
	if !s.ready() {
		return nil
	}
	_, err := s.db.Exec(`
		UPDATE soar_triage
		SET count_suppressed = count_suppressed + 1,
		    suppressed_since_digest = suppressed_since_digest + 1,
		    last_seen = NOW()
		WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return fmt.Errorf("triage record suppressed %q: %w", fingerprint, err)
	}
	return nil
}

// SetDecision records an operator verdict from a Discord button. Upsert : la row
// peut manquer (DB dev reset alors que d'anciens messages Discord portent encore
// des boutons) — le verdict crée alors la row plutôt que d'échouer.
// decidedByID est l'ID Discord immuable (traçabilité : le username, mutable à
// volonté, ne sert qu'à l'affichage).
func (s *TriageStore) SetDecision(fingerprint, status, decidedBy, decidedByID string) error {
	if !validTriageDecision(status) {
		return fmt.Errorf("triage: statut invalide %q", status)
	}
	if !s.ready() {
		return fmt.Errorf("triage: store sans base de données")
	}
	_, err := s.db.Exec(`
		INSERT INTO soar_triage (fingerprint, status, decided_at, decided_by, decided_by_id, first_seen, last_seen)
		VALUES (?, ?, NOW(), ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE
			status = VALUES(status),
			decided_at = NOW(),
			decided_by = VALUES(decided_by),
			decided_by_id = VALUES(decided_by_id)`,
		fingerprint, status, truncateRunes(decidedBy, 100), truncateRunes(decidedByID, 32))
	if err != nil {
		return fmt.Errorf("triage set decision %q: %w", fingerprint, err)
	}
	return nil
}

// DigestRows returns every fingerprint with suppressions since the last digest,
// most-suppressed first. Toutes les rows sont retournées (pas seulement le top
// affiché) : le reset post-digest doit créditer chaque empreinte exactement de ce
// qui a été rapporté.
func (s *TriageStore) DigestRows() ([]TriageDigestRow, error) {
	if !s.ready() {
		return nil, nil
	}
	rows, err := s.db.Query(`
		SELECT fingerprint, rule_id, agent_name, title, status, suppressed_since_digest, count_suppressed
		FROM soar_triage
		WHERE suppressed_since_digest > 0
		ORDER BY suppressed_since_digest DESC, fingerprint`)
	if err != nil {
		return nil, fmt.Errorf("triage digest rows: %w", err)
	}
	defer rows.Close()
	var out []TriageDigestRow
	for rows.Next() {
		var r TriageDigestRow
		if err := rows.Scan(&r.Fingerprint, &r.RuleID, &r.AgentName, &r.Title, &r.Status, &r.SinceDigest, &r.TotalSuppressed); err != nil {
			return nil, fmt.Errorf("triage digest scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResetDigestCounts subtracts the REPORTED counts after a successful digest post,
// row by row — jamais un reset à zéro global : une suppression survenue entre la
// lecture du digest et ce reset doit survivre et compter au digest suivant.
func (s *TriageStore) ResetDigestCounts(rows []TriageDigestRow) error {
	if !s.ready() || len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("triage reset digest: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op après un Commit réussi
	for _, r := range rows {
		if _, err := tx.Exec(`
			UPDATE soar_triage
			SET suppressed_since_digest = GREATEST(suppressed_since_digest - ?, 0)
			WHERE fingerprint = ?`, r.SinceDigest, r.Fingerprint); err != nil {
			return fmt.Errorf("triage reset digest %q: %w", r.Fingerprint, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("triage reset digest commit: %w", err)
	}
	return nil
}
