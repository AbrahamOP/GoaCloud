package assets

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Garde-fous contre le DOM-XSS corrigé en août 2026 : plusieurs vues
// interpolaient des champs d'API (nom d'agent Wazuh, nom de snapshot Proxmox,
// nom de VM) directement dans des chaînes HTML. Ces valeurs viennent de machines
// supervisées — une frontière de confiance distincte — donc potentiellement
// d'une machine compromise.

// bareProperty décrit un `${objet.champ}` (éventuellement suivi d'un
// `|| valeur-par-défaut`) : un accès de propriété brut, sans échappement.
// Les ternaires, les appels de fonction et l'indexation par crochets sortent
// volontairement du filet — il s'agit d'un garde-fou, pas d'une preuve.
var bareProperty = regexp.MustCompile(
	`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?:\s*\|\|\s*(?:'[^']*'|"[^"]*"|\d+))?$`)

// Expressions tolérées : valeurs calculées par la vue elle-même (compteurs,
// tables de classes CSS), jamais des données distantes. Toute nouvelle entrée
// doit être justifiée — dans le doute, échapper plutôt qu'ajouter une exception.
var safeInterpolation = map[string]bool{
	"c.text":       true, // table de classes Tailwind indexée par sévérité
	"c.bg":         true,
	"c.border":     true,
	"c.label":      true,
	"items.length": true, // entier calculé localement
	"p.count":      true, // entier agrégé localement
	"names.length": true, // entier, et posé via innerText
}

// templateLiterals extrait le contenu des littéraux gabarits (backticks) d'un
// fichier. C'est là que vit la construction de HTML côté client.
func templateLiterals(src string) []string {
	var out []string
	for i := 0; i < len(src); i++ {
		if src[i] != '`' {
			continue
		}
		var b strings.Builder
		j := i + 1
		for j < len(src) && src[j] != '`' {
			if src[j] == '\\' {
				j += 2
				continue
			}
			b.WriteByte(src[j])
			j++
		}
		out = append(out, b.String())
		i = j
	}
	return out
}

var interpolation = regexp.MustCompile(`\$\{([^{}]*)\}`)

func templateFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("aucun template trouvé: %v", err)
	}
	return files
}

// TestNoRawPropertyInterpolation échoue si une vue réinjecte une propriété
// d'objet brute dans un littéral gabarit. La forme attendue est
// escapeHtml(x.y) / esc(x.y).
func TestNoRawPropertyInterpolation(t *testing.T) {
	for _, f := range templateFiles(t) {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("lecture %s: %v", f, err)
		}
		for _, lit := range templateLiterals(string(body)) {
			for _, m := range interpolation.FindAllStringSubmatch(lit, -1) {
				expr := strings.TrimSpace(m[1])
				if !bareProperty.MatchString(expr) {
					continue
				}
				key := strings.TrimSpace(strings.SplitN(expr, "||", 2)[0])
				if safeInterpolation[key] {
					continue
				}
				t.Errorf("%s: interpolation non échappée ${%s} — utiliser escapeHtml()/esc()", f, expr)
			}
		}
	}
}

// TestNoJSONInHTMLAttribute échoue si une valeur est sérialisée dans un attribut
// délimité par des apostrophes : JSON.stringify n'échappe pas `'`, un nom
// d'agent contenant `x' onmouseover='…` sort donc de l'attribut. La bonne forme
// est element.dataset.foo = JSON.stringify(v) après création du nœud.
func TestNoJSONInHTMLAttribute(t *testing.T) {
	pat := regexp.MustCompile(`=\s*'\$\{[^}]*\}'`)
	for _, f := range templateFiles(t) {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("lecture %s: %v", f, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if hit := pat.FindString(line); hit != "" {
				t.Errorf("%s:%d: valeur interpolée dans un attribut entre apostrophes (%s) — passer par element.dataset",
					f, i+1, hit)
			}
		}
	}
}
