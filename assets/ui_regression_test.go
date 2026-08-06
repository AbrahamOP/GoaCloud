package assets

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Garde-fous sur la couche présentation, corrigée en août 2026 :
//   - plus aucun alert() natif comme canal d'erreur ou de succès ;
//   - toute modale porte role="dialog" et passe par le module partagé ui.js
//     (Échap, piège de focus, restauration du focus) ;
//   - les tableaux défilent dans leur conteneur, pas en entraînant la page ;
//   - les surcharges !important responsives ne reviennent pas dans theme.css.

func readTemplate(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture %s: %v", path, err)
	}
	return string(body)
}

func readAsset(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("static", rel))
	if err != nil {
		t.Fatalf("lecture static/%s: %v", rel, err)
	}
	return string(body)
}

// --------------------------------------------------------------------------
// 1. Notifications
// --------------------------------------------------------------------------

// alertCall repère un appel `alert(` qui n'est ni `role="alert"` ni un mot
// composé (`sendAlert(`, `.alert(`).
var alertCall = regexp.MustCompile(`(^|[^.\w])alert\s*\(`)

// TestNoNativeAlert échoue si une vue revient à la boîte de dialogue du
// navigateur : elle bloque la page, affiche l'URL du site et n'apprend rien à un
// administrateur non développeur. Le canal est notify()/notifyError() (ui.js).
func TestNoNativeAlert(t *testing.T) {
	for _, f := range templateFiles(t) {
		for i, line := range strings.Split(readTemplate(t, f), "\n") {
			// Les commentaires de template mentionnent légitimement alert().
			if strings.Contains(line, "{{/*") || strings.Contains(line, "*/}}") {
				continue
			}
			if alertCall.MatchString(line) {
				t.Errorf("%s:%d: alert() natif — utiliser notify(type, message) / notifyError(err, contexte)",
					f, i+1)
			}
		}
	}
}

// TestNotifyHelpersExposed vérifie que les helpers appelés depuis les attributs
// onclick="" des vues existent bien dans le scope global.
func TestNotifyHelpersExposed(t *testing.T) {
	ui := readAsset(t, "ui.js")
	for _, sym := range []string{
		"window.notify", "window.notifyError",
		"window.openModal", "window.closeModal", "window.GoaUI",
	} {
		if !strings.Contains(ui, sym) {
			t.Errorf("ui.js n'expose plus %s — les handlers onclick des vues n'y ont plus accès", sym)
		}
	}
}

// TestPagesLoadUIModule : toute page qui charge theme.js doit aussi charger
// ui.js et poser l'hôte des toasts, sinon notify() n'a nulle part où s'afficher.
func TestPagesLoadUIModule(t *testing.T) {
	// login.html affiche ses erreurs en bandeau rendu côté serveur et n'appelle
	// aucun helper JS de notification : elle n'a pas besoin du module.
	exempt := map[string]bool{"login.html": true}
	for _, f := range templateFiles(t) {
		if exempt[filepath.Base(f)] {
			continue
		}
		body := readTemplate(t, f)
		if !strings.Contains(body, `src="/static/theme.js"`) {
			continue
		}
		if !strings.Contains(body, `src="/static/ui.js"`) {
			t.Errorf("%s: charge theme.js mais pas ui.js", f)
		}
		if !strings.Contains(body, `{{template "toast-host"}}`) {
			t.Errorf(`%s: n'inclut pas {{template "toast-host"}}`, f)
		}
	}
}

// --------------------------------------------------------------------------
// 2. Modales accessibles
// --------------------------------------------------------------------------

// modalRoot : une racine de modale est un <div> plein écran porteur d'un id.
// Les fonds (`modal-backdrop`, `mobile-overlay`) n'en sont pas.
var modalRoot = regexp.MustCompile(`(?s)<div\b[^>]*class="fixed inset-0[^>]*>`)

var idAttr = regexp.MustCompile(`id="([^"]+)"`)

var notADialog = map[string]bool{
	"mobile-overlay": true,
	"modal-backdrop": true,
}

func modalRoots(t *testing.T, path string) map[string]string {
	t.Helper()
	body := readTemplate(t, path)
	roots := map[string]string{}
	for _, tag := range modalRoot.FindAllString(body, -1) {
		m := idAttr.FindStringSubmatch(tag)
		if m == nil || notADialog[m[1]] {
			continue
		}
		roots[m[1]] = tag
	}
	return roots
}

// TestModalsAreDialogs : chaque modale s'annonce comme un dialogue et porte un
// intitulé pointant vers un élément réellement présent dans la page. Sans
// aria-labelledby valide, un lecteur d'écran annonce « dialogue » et rien d'autre.
func TestModalsAreDialogs(t *testing.T) {
	seen := 0
	for _, f := range templateFiles(t) {
		body := readTemplate(t, f)
		for id, tag := range modalRoots(t, f) {
			seen++
			for _, attr := range []string{`role="dialog"`, `aria-modal="true"`, `tabindex="-1"`} {
				if !strings.Contains(tag, attr) {
					t.Errorf("%s: modale #%s sans %s", f, id, attr)
				}
			}
			m := regexp.MustCompile(`aria-labelledby="([^"]+)"`).FindStringSubmatch(tag)
			if m == nil {
				t.Errorf("%s: modale #%s sans aria-labelledby", f, id)
				continue
			}
			if !strings.Contains(body, `id="`+m[1]+`"`) {
				t.Errorf("%s: modale #%s pointe aria-labelledby=%q vers un id inexistant", f, id, m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("aucune racine de modale détectée : le motif de détection ne correspond plus au balisage")
	}
}

// TestModalsUseSharedModule : ouvrir ou fermer une modale en manipulant
// directement la classe `hidden` contourne Échap, le piège de focus et la
// restauration du focus déclencheur. Tout doit passer par GoaUI.
func TestModalsUseSharedModule(t *testing.T) {
	for _, f := range templateFiles(t) {
		body := readTemplate(t, f)
		for id := range modalRoots(t, f) {
			for _, verb := range []string{"remove", "add"} {
				bad := `getElementById('` + id + `').classList.` + verb + `('hidden')`
				if strings.Contains(body, bad) {
					t.Errorf("%s: modale #%s manipulée via classList.%s('hidden') — utiliser GoaUI.openModal/closeModal",
						f, id, verb)
				}
			}
		}
	}
}

// TestModalModuleHandlesEscapeAndFocus : le module partagé reste la seule
// implémentation d'Échap, du piège de focus et du focus rendu au déclencheur.
func TestModalModuleHandlesEscapeAndFocus(t *testing.T) {
	ui := readAsset(t, "ui.js")
	for _, needle := range []string{
		`"Escape"`,        // fermeture clavier
		`"Tab"`,           // piège de focus
		"_goaOpener",      // mémorisation du déclencheur
		"trapFocus",       //
		"goa:modal-close", // point d'extension pour le ménage des pages
	} {
		if !strings.Contains(ui, needle) {
			t.Errorf("ui.js: %s a disparu — le comportement de dialogue n'est plus garanti", needle)
		}
	}
}

// --------------------------------------------------------------------------
// 3. Mobile
// --------------------------------------------------------------------------

// TestSidebarClosedIsNotTabbable : hors desktop, un tiroir fermé masqué par la
// seule translation reste dans l'ordre de tabulation — on tabule dans neuf liens
// invisibles avant d'atteindre le contenu.
func TestSidebarClosedIsNotTabbable(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "partials.html"))
	if !strings.Contains(body, "invisible md:translate-x-0 md:visible") {
		t.Error("partials.html: la sidebar fermée doit porter `invisible md:visible` en plus de -translate-x-full")
	}
	if !strings.Contains(body, "sidebar.inert =") {
		t.Error("partials.html: sidebar-js ne pilote plus l'attribut `inert` du tiroir fermé")
	}
	for _, attr := range []string{`aria-expanded="false"`, `aria-controls="sidebar"`, `aria-label="Ouvrir le menu de navigation"`} {
		if !strings.Contains(body, attr) {
			t.Errorf("partials.html: le bouton hamburger n'a plus %s", attr)
		}
	}
	if !strings.Contains(body, "'Escape'") {
		t.Error("partials.html: le tiroir mobile ne se ferme plus avec Échap")
	}
}

// TestSkipLinkTargetsMain : le lien d'évitement doit pointer vers une cible qui
// existe dans chaque page qui l'inclut.
func TestSkipLinkTargetsMain(t *testing.T) {
	for _, f := range templateFiles(t) {
		body := readTemplate(t, f)
		if !strings.Contains(body, `{{template "skip-link"}}`) {
			continue
		}
		if !strings.Contains(body, `id="main-content"`) {
			t.Errorf(`%s: inclut le lien d'évitement mais n'a pas d'élément id="main-content"`, f)
		}
	}
}

// tableTag repère l'ouverture d'un <table>.
var tableTag = regexp.MustCompile(`<table\b`)

// TestTablesScrollInsideContainer : sur la page Sécurité et sur le rapport, un
// tableau plus large que l'écran doit défiler dans son propre conteneur. Sans ça
// c'est toute la page qui part en défilement horizontal sur téléphone.
func TestTablesScrollInsideContainer(t *testing.T) {
	cases := map[string]string{
		filepath.Join("templates", "wazuh.html"):  "overflow-x-auto",
		filepath.Join("templates", "report.html"): "table-scroll",
	}
	for path, wrapper := range cases {
		body := readTemplate(t, path)
		tables := len(tableTag.FindAllString(body, -1))
		if tables == 0 {
			t.Fatalf("%s: aucun tableau trouvé, le test ne vérifie plus rien", path)
		}
		if got := strings.Count(body, wrapper); got < tables {
			t.Errorf("%s: %d tableau(x) pour seulement %d conteneur(s) %q",
				path, tables, got, wrapper)
		}
	}
}

// TestNoImportantResponsiveOverrides : les paddings et tailles de titres mobiles
// se déclarent en variantes responsives dans le balisage. Une pile d'!important
// sur des utilitaires Tailwind interdit toute exception par page.
func TestNoImportantResponsiveOverrides(t *testing.T) {
	css := readAsset(t, "theme.css")
	for _, bad := range []string{
		".px-8 {", ".px-6 {", "h2.text-3xl", "h3.text-2xl", ".text-4xl {",
	} {
		if strings.Contains(css, bad) {
			t.Errorf("theme.css: surcharge %q réintroduite — utiliser les variantes responsives Tailwind", bad)
		}
	}
}

// --------------------------------------------------------------------------
// 4. Rafraîchissement live
// --------------------------------------------------------------------------

// TestSSEReconnectBackoff : une reconnexion à délai fixe martèle un serveur en
// panne, et rien à l'écran ne distingue « flux vivant » de « flux mort ».
func TestSSEReconnectBackoff(t *testing.T) {
	js := readAsset(t, "theme.js")
	for _, needle := range []string{
		"SSE_BACKOFF_MAX_MS", // plafond
		"_sseRetryDelay * 2", // croissance exponentielle
		"onSSEState",         // état exposé aux pages
	} {
		if !strings.Contains(js, needle) {
			t.Errorf("theme.js: %s manquant — le backoff SSE ou son signalement a disparu", needle)
		}
	}
	if strings.Contains(js, "setTimeout(connectSSE, 5000)") {
		t.Error("theme.js: retour à un délai de reconnexion fixe de 5 s")
	}
}

// TestOverviewSignalsStaleData : sur un tableau de bord d'astreinte, « tout est
// vert » et « le backend ne répond plus » ne doivent jamais se ressembler.
func TestOverviewSignalsStaleData(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "overview.html"))
	for _, needle := range []string{
		`id="ov-freshness"`,   // horodatage visible
		"consecutiveFailures", // compteur d'échecs
		"renderFreshness",     //
		"visibilitychange",    // pause en arrière-plan
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("overview.html: %s manquant", needle)
		}
	}
	if strings.Contains(body, "/* transient error: keep last values */") {
		t.Error("overview.html: l'échec de rafraîchissement est redevenu silencieux")
	}
	// Le premier appel doit être immédiat : sans lui la page vit une minute
	// entière sur le seul rendu serveur.
	if !regexp.MustCompile(`(?m)^\s*refreshOverview\(\);`).MatchString(body) {
		t.Error("overview.html: pas d'appel immédiat à refreshOverview() avant la mise en place de l'intervalle")
	}
}

// --------------------------------------------------------------------------
// 5. Finitions
// --------------------------------------------------------------------------

// TestFontDeclaredOnce : la police du produit se déclare dans @layer base, pas
// dans dix-sept balises <style> inline.
func TestFontDeclaredOnce(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "tailwind.input.css"))
	if err != nil {
		t.Fatalf("lecture tailwind.input.css: %v", err)
	}
	if !strings.Contains(string(input), "@layer base") ||
		!strings.Contains(string(input), "font-family: 'Outfit'") {
		t.Fatal("tailwind.input.css: la police n'est plus déclarée dans @layer base")
	}

	// login.html et report.html ont leur propre feuille autonome (page publique,
	// document imprimable) : elles restent hors du périmètre partagé.
	standalone := map[string]bool{"login.html": true, "report.html": true}
	for _, f := range templateFiles(t) {
		if standalone[filepath.Base(f)] {
			continue
		}
		if strings.Contains(readTemplate(t, f), "font-family: 'Outfit'") {
			t.Errorf("%s: redéclare la police en inline — elle vient de @layer base", f)
		}
	}
}

// TestReducedMotionHonoured : la pastille de santé pulse en boucle infinie et
// plusieurs indicateurs tournent en continu ; il faut respecter le réglage
// système « Réduire les animations ».
func TestReducedMotionHonoured(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "tailwind.input.css"))
	if err != nil {
		t.Fatalf("lecture tailwind.input.css: %v", err)
	}
	if !strings.Contains(string(input), "prefers-reduced-motion: reduce") {
		t.Error("tailwind.input.css: bloc prefers-reduced-motion absent")
	}
	if !strings.Contains(readAsset(t, "tailwind.min.css"), "prefers-reduced-motion") {
		t.Error("assets/static/tailwind.min.css: CSS non régénéré après ajout de prefers-reduced-motion")
	}
}

// TestNavigationLabelsAccented : ces libellés sont sur chaque écran du produit —
// donc sur chaque image d'une démo filmée.
func TestNavigationLabelsAccented(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "partials.html"))
	wanted := []string{"Sécurité (Wazuh)", "Clés SSH", `title="Changer le thème"`, `title="Déconnexion"`}
	for _, w := range wanted {
		if !strings.Contains(body, w) {
			t.Errorf("partials.html: %q manquant (accent perdu ?)", w)
		}
	}
	for _, bad := range []string{"Securite (Wazuh)", "Cles SSH", "Changer le theme", "Deconnexion"} {
		if strings.Contains(body, bad) {
			t.Errorf("partials.html: %q — accent manquant dans la navigation permanente", bad)
		}
	}
}

// TestBubblesNotDuplicated : le bloc décoratif est un partial ; setup.html en
// gardait une copie mot pour mot.
func TestBubblesNotDuplicated(t *testing.T) {
	// Le bloc a été migré vers les tokens sémantiques : le marqueur suit.
	marker := `<div class="absolute top-0 left-0 w-96 h-96 bg-primary/20`
	for _, f := range templateFiles(t) {
		if filepath.Base(f) == "partials.html" || filepath.Base(f) == "login.html" {
			continue
		}
		if strings.Contains(readTemplate(t, f), marker) {
			t.Errorf(`%s: recopie le bloc décoratif — utiliser {{template "bubbles"}}`, f)
		}
	}
}

// labelNoFor repère un <label> sans attribut `for` et sans contrôle imbriqué.
var labelNoFor = regexp.MustCompile(`<label(?:\s+(?:class|id|style)="[^"]*")*\s*>`)

// TestLabelsAreAssociated : un intitulé purement visuel n'agrandit pas la zone
// cliquable et n'est pas annoncé avec son champ. Les <label> qui enveloppent
// leur contrôle sont associés implicitement et restent valides.
func TestLabelsAreAssociated(t *testing.T) {
	// Vues où l'audit avait relevé les intitulés détachés.
	for _, name := range []string{"proxmox.html", "ansible.html"} {
		body := readTemplate(t, filepath.Join("templates", name))
		for i, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "<label") || strings.Contains(line, "for=") {
				continue
			}
			// Un label qui ouvre un bloc contenant son <input>/<select> est valide.
			if strings.Contains(line, "cursor-pointer") || strings.Contains(line, "inline-flex") {
				continue
			}
			if labelNoFor.MatchString(line) {
				t.Errorf("%s:%d: <label> sans `for` ni contrôle imbriqué — %s",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
