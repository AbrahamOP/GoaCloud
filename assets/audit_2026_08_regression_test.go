package assets

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Garde-fous sur les défauts relevés par la revue adversariale du lot de
// remédiation d'août 2026. Chacun de ces tests correspond à une régression qui
// était passée à travers la revue précédente : ils vivent ici, dans le paquet
// `assets`, parce que c'est déjà le seul endroit du dépôt où la couche
// présentation et les fichiers d'exploitation sont vérifiés par du Go.
//
// Les chemins sont relatifs à assets/ ; la racine du dépôt est donc "..".

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{".."}, parts...)...)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture %s: %v", path, err)
	}
	return string(body)
}

// --------------------------------------------------------------------------
// 1. Secrets par fichier et sondes de santé
// --------------------------------------------------------------------------

// TestDBHealthcheckHandlesSecretFiles : .env.example recommande les secrets par
// fichier (_FILE). Un health-check qui ne lit que MYSQL_ROOT_PASSWORD laisse alors
// la base éternellement « unhealthy », et `depends_on: service_healthy` empêche
// l'application de démarrer — sur l'exact chemin d'installation recommandé.
func TestDBHealthcheckHandlesSecretFiles(t *testing.T) {
	for _, compose := range [][]string{
		{"docker-compose.yml"},
		{"install", "docker-compose.yml"},
	} {
		body := repoFile(t, compose...)
		name := filepath.Join(compose...)
		if !strings.Contains(body, "mysqladmin ping") {
			t.Fatalf("%s: le health-check de `db` n'utilise plus mysqladmin, ce test ne vérifie plus rien", name)
		}
		if !strings.Contains(body, "MYSQL_ROOT_PASSWORD_FILE") {
			t.Errorf("%s: le health-check de `db` ignore MYSQL_ROOT_PASSWORD_FILE — la base reste « unhealthy » avec un secret par fichier", name)
		}
	}
}

// TestContainerHealthcheckProbesReadiness : sonder une page de l'interface
// (/login) garde le conteneur vert pendant une panne totale de la base, c'est-à-dire
// pendant que toutes les pages utiles renvoient 500. /readyz répond 503 dans ce cas.
func TestContainerHealthcheckProbesReadiness(t *testing.T) {
	body := repoFile(t, "Dockerfile")
	idx := strings.Index(body, "HEALTHCHECK")
	if idx < 0 {
		t.Fatal("Dockerfile: plus aucun HEALTHCHECK")
	}
	hc := body[idx:]
	if end := strings.Index(hc, "\nENTRYPOINT"); end > 0 {
		hc = hc[:end]
	}
	if !strings.Contains(hc, "/readyz") {
		t.Error("Dockerfile: le HEALTHCHECK ne sonde pas /readyz — il reste vert base éteinte")
	}
	if strings.Contains(hc, "/login") {
		t.Error("Dockerfile: le HEALTHCHECK sonde encore /login")
	}
	// TLS auto-signé sur 8443 : sans cette option la sonde échoue toujours, et le
	// conteneur passerait « unhealthy » en permanence — l'inverse du bug d'origine.
	if !strings.Contains(hc, "--no-check-certificate") {
		t.Error("Dockerfile: le HEALTHCHECK a perdu --no-check-certificate (certificat auto-signé)")
	}
}

// --------------------------------------------------------------------------
// 2. install/backup.sh — comportement réel
// --------------------------------------------------------------------------

func backupScript(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "install", "backup.sh"))
	if err != nil {
		t.Fatalf("chemin backup.sh: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("install/backup.sh: %v", err)
	}
	return path
}

// runBackup exécute le script avec /bin/sh et rend sortie + succès.
func runBackup(t *testing.T, env []string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{backupScript(t)}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// writeDump crée un faux dump gzip valide, âgé de `ageDays` jours.
func writeDump(t *testing.T, dir, name string, ageDays int, complete bool) string {
	t.Helper()
	path := filepath.Join(dir, name)
	payload := "CREATE TABLE t (id INT);\n"
	if complete {
		payload += "-- Dump completed on 2026-08-01 03:00:00\n"
	} else {
		payload += "-- interrompu au milieu\n"
	}
	plain := path + ".plain"
	if err := os.WriteFile(plain, []byte(payload), 0o600); err != nil {
		t.Fatalf("écriture %s: %v", plain, err)
	}
	cmd := exec.Command("/bin/sh", "-c", "gzip -c "+plain+" > "+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gzip: %v (%s)", err, out)
	}
	_ = os.Remove(plain)
	when := time.Now().AddDate(0, 0, -ageDays)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
	return path
}

// TestPruneAlwaysKeepsOneDump : sans plancher, quelques semaines de sauvegardes en
// échec (disque plein, identifiants changés) suffisent à ce que la rétention vide
// entièrement le répertoire — elle efface la dernière copie existante juste au
// moment où elle devient la seule.
func TestPruneAlwaysKeepsOneDump(t *testing.T) {
	dir := t.TempDir()
	old := writeDump(t, dir, "goacore-20260101-030000.sql.gz", 90, true)
	older := writeDump(t, dir, "goacore-20251201-030000.sql.gz", 120, true)

	out, ok := runBackup(t, []string{"GOACORE_BACKUP_RETENTION_DAYS=14"}, "prune", dir)
	if !ok {
		t.Fatalf("prune a échoué : %s", out)
	}
	if _, err := os.Stat(old); err != nil {
		t.Errorf("prune a supprimé la sauvegarde la plus récente alors qu'elle était la seule restante : %v\n%s", err, out)
	}
	if _, err := os.Stat(older); err == nil {
		t.Errorf("prune n'a pas supprimé le dump le plus ancien, hors rétention :\n%s", out)
	}
}

// TestPruneStillRespectsRetention : le plancher ne doit pas neutraliser la
// rétention quand des dumps récents existent.
func TestPruneStillRespectsRetention(t *testing.T) {
	dir := t.TempDir()
	fresh := writeDump(t, dir, "goacore-20260805-030000.sql.gz", 0, true)
	stale := writeDump(t, dir, "goacore-20260101-030000.sql.gz", 90, true)

	out, ok := runBackup(t, []string{"GOACORE_BACKUP_RETENTION_DAYS=14"}, "prune", dir)
	if !ok {
		t.Fatalf("prune a échoué : %s", out)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("prune a supprimé un dump dans la fenêtre de rétention : %v", err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Errorf("prune conserve un dump hors rétention alors qu'un plus récent existe :\n%s", out)
	}
}

// TestVerifyRejectsTruncatedDump : c'est le contrôle sur lequel s'appuie
// désormais `restore`. S'il accepte un dump tronqué, la vérification préalable à la
// restauration ne vaut rien.
func TestVerifyRejectsTruncatedDump(t *testing.T) {
	dir := t.TempDir()
	good := writeDump(t, dir, "goacore-20260805-030000.sql.gz", 0, true)
	bad := writeDump(t, dir, "goacore-20260804-030000.sql.gz", 0, false)

	if out, ok := runBackup(t, nil, "verify", good); !ok {
		t.Errorf("verify refuse un dump complet : %s", out)
	}
	if out, ok := runBackup(t, nil, "verify", bad); ok {
		t.Errorf("verify accepte un dump tronqué : %s", out)
	}
}

// TestRestoreVerifiesBeforeOverwriting : `restore` a besoin d'un service compose
// démarré, donc son comportement complet n'est pas exerçable ici. Ce qui l'est —
// et qui est le cœur du défaut — c'est l'ORDRE : le contrôle d'intégrité doit
// précéder l'écriture dans la base, et la décompression ne doit plus se faire dans
// un pipeline dont /bin/sh jette silencieusement le code de retour.
func TestRestoreVerifiesBeforeOverwriting(t *testing.T) {
	body := repoFile(t, "install", "backup.sh")
	start := strings.Index(body, "cmd_restore() {")
	if start < 0 {
		t.Fatal("install/backup.sh: cmd_restore introuvable")
	}
	end := strings.Index(body[start:], "\ncmd_verify() {")
	if end < 0 {
		t.Fatal("install/backup.sh: fin de cmd_restore introuvable")
	}
	fn := body[start : start+end]

	check := strings.Index(fn, "assert_dump_ok")
	if check < 0 {
		t.Fatal("cmd_restore ne vérifie pas l'intégrité du dump avant de restaurer")
	}
	write := strings.Index(fn, "exec mysql ")
	if write < 0 {
		t.Fatal("cmd_restore n'écrit plus dans la base ? le test ne vérifie plus rien")
	}
	if check > write {
		t.Error("cmd_restore restaure AVANT de vérifier l'intégrité du dump")
	}
	if regexp.MustCompile(`gunzip -c "\$file"\s*\n\s*else`).MatchString(fn) {
		t.Error("cmd_restore décompresse encore dans un pipeline : /bin/sh ne rapporte que le code de retour de mysql, jamais celui de gunzip")
	}
}

// TestDumpIsCreatedRestricted : le dump contient tout l'état du produit, secrets
// chiffrés compris. Un `chmod` a posteriori le laisse lisible par tous pendant
// toute la durée du dump — la fenêtre la plus longue et la plus prévisible qui soit.
func TestDumpIsCreatedRestricted(t *testing.T) {
	body := repoFile(t, "install", "backup.sh")
	start := strings.Index(body, "cmd_dump() {")
	end := strings.Index(body, "cmd_restore() {")
	if start < 0 || end < start {
		t.Fatal("install/backup.sh: cmd_dump introuvable")
	}
	fn := body[start:end]
	umask := strings.Index(fn, "umask 077")
	if umask < 0 {
		t.Fatal("cmd_dump ne pose pas de umask restrictif : le dump naît en 0644")
	}
	if redirect := strings.Index(fn, `gzip > "$tmp"`); redirect >= 0 && umask > redirect {
		t.Error("le umask est posé APRÈS la création du fichier : trop tard")
	}
}

// --------------------------------------------------------------------------
// 3. Couleurs
// --------------------------------------------------------------------------

// rawPalette repère une classe utilitaire construite sur une échelle de couleur
// Tailwind brute (text-cyan-400, bg-teal-500/10…). Ces couleurs sont figées : elles
// ne suivent pas le thème et tombent à 1,6:1 sur les surfaces claires.
var rawPalette = regexp.MustCompile(`\b(?:text|bg|border|from|to|via|ring|fill|stroke|decoration|divide|outline|accent|caret|placeholder)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}(?:/\d{1,3})?\b`)

// TestNoRawPaletteClasses : la migration vers les tokens sémantiques doit être
// complète, sans quoi il reste exactement ce qu'elle voulait éliminer.
func TestNoRawPaletteClasses(t *testing.T) {
	// Hors périmètre de ce correctif (traités par un autre changement du même lot).
	// partials.html a été migré : la barre latérale, présente sur chaque écran,
	// ne doit plus diverger de la barre d'onglets Paramètres.
	exempt := map[string]bool{
		"settings-account.html": true,
	}
	for _, f := range templateFiles(t) {
		if exempt[filepath.Base(f)] {
			continue
		}
		for i, line := range strings.Split(readTemplate(t, f), "\n") {
			if m := rawPalette.FindString(line); m != "" {
				t.Errorf("%s:%d: classe de palette brute %q — utiliser un token sémantique (text-info, text-warning, bg-primary/20…)",
					f, i+1, m)
			}
		}
	}
	for _, js := range []string{"ui.js", "search.js", "theme.js"} {
		if m := rawPalette.FindString(readAsset(t, js)); m != "" {
			t.Errorf("static/%s: classe de palette brute %q", js, m)
		}
	}
}

// severityToken extrait le token `text-…` associé à un niveau de sévérité.
func severityToken(t *testing.T, body, level string) string {
	t.Helper()
	re := regexp.MustCompile(level + `:\s*\{[^}]*text:\s*'(text-[a-z-]+)'`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("wazuh.html: couleur de la sévérité %s introuvable", level)
	}
	return m[1]
}

// TestWazuhSeveritiesAreDistinguishable : quatre niveaux de sévérité pour trois
// teintes, c'est une sévérité qu'il faut lire pour la distinguer — exactement ce
// que la couleur est censée éviter sur un écran de sécurité.
func TestWazuhSeveritiesAreDistinguishable(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "wazuh.html"))
	seen := map[string]string{}
	for _, level := range []string{"Critical", "High", "Medium", "Low"} {
		token := severityToken(t, body, level)
		if other, dup := seen[token]; dup {
			t.Errorf("wazuh.html: %s et %s partagent la couleur %s", other, level, token)
		}
		seen[token] = level
	}
}

// TestSparklinesFollowTheme : les trois courbes de la page Proxmox étaient les
// seuls éléments non thémés de l'écran (couleurs hexadécimales en dur).
func TestSparklinesFollowTheme(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "proxmox.html"))
	calls := regexp.MustCompile(`drawSparkline\('spark-[a-z]+',[^\n]*,\s*'([^'\n]+)'\)`).FindAllStringSubmatch(body, -1)
	if len(calls) == 0 {
		t.Fatal("proxmox.html: aucun appel à drawSparkline, le test ne vérifie plus rien")
	}
	for _, c := range calls {
		if !strings.HasPrefix(c[1], "var(--md-color-") {
			t.Errorf("proxmox.html: sparkline en couleur figée %q — utiliser un token MD3", c[1])
		}
	}
	// var() n'est pas résolu dans un attribut de présentation SVG, seulement dans
	// une déclaration CSS : le passage aux tokens n'a de sens qu'avec style="".
	if !strings.Contains(body, `style="fill:${color}"`) {
		t.Error("proxmox.html: la couleur de sparkline doit être posée en style inline, sinon var(--…) n'est pas résolu")
	}
}

// --------------------------------------------------------------------------
// 4. Modales : saisie non enregistrée et pile unique
// --------------------------------------------------------------------------

// TestEscapeDoesNotDiscardUnsavedInput : Échap fermait n'importe quelle modale
// sur-le-champ, éditeur de playbook compris — une frappe malheureuse et le YAML
// tapé disparaissait sans un mot.
func TestEscapeDoesNotDiscardUnsavedInput(t *testing.T) {
	ui := readAsset(t, "ui.js")
	for _, needle := range []string{
		"_goaDirty",                // état « modifié »
		"requestClose",             // fermeture par geste, distincte de closeModal
		"isTrusted",                // seule une saisie humaine salit la modale
		"data-modal-discardable",   // opt-out pour les saisies jetables
		`addEventListener("input"`, // marquage
	} {
		if !strings.Contains(ui, needle) {
			t.Errorf("ui.js: %s manquant — Échap peut de nouveau jeter une saisie non enregistrée", needle)
		}
	}
	// Le handler clavier doit passer par la garde, pas fermer directement.
	esc := regexp.MustCompile(`(?s)event\.key === "Escape".{0,240}`).FindString(ui)
	if esc == "" {
		t.Fatal("ui.js: gestionnaire d'Échap introuvable")
	}
	if !strings.Contains(esc, "requestClose(") {
		t.Error("ui.js: Échap appelle closeModal directement, sans la garde « saisie non enregistrée »")
	}
}

// TestCommandPaletteSharesTheModalStack : tant que la palette Ctrl+K vivait à côté
// de la pile de ui.js, Échap était avalé par la modale du dessous et le focus lui
// était volé sans que son piège de focus ne le sache.
func TestCommandPaletteSharesTheModalStack(t *testing.T) {
	search := readAsset(t, "search.js")
	for _, needle := range []string{
		"GoaUI.openModal",        // ouverture par la pile partagée
		"GoaUI.closeModal",       // fermeture par la pile partagée
		"data-modal-discardable", // Échap doit fermer la palette immédiatement
		"data-modal-autofocus",   // le focus va dans le champ de recherche
		`role="dialog"`,          // c'est un dialogue, il doit le dire
		"goa:modal-close",        // ménage même quand la pile ferme elle-même
	} {
		if !strings.Contains(search, needle) {
			t.Errorf("search.js: %s manquant — la palette n'est plus une couche de la pile partagée", needle)
		}
	}
	if strings.Contains(search, "e.key === 'Escape'") {
		t.Error("search.js: gestionnaire d'Échap concurrent réintroduit — la pile de ui.js est la seule autorité")
	}
}

// --------------------------------------------------------------------------
// 5. Finitions
// --------------------------------------------------------------------------

// TestBackupsSettingsTableScrolls : quatre colonnes dans une modale contrainte à
// max-w-3xl, sur un écran étroit la dernière devenait inatteignable (conteneur en
// overflow-hidden, donc coupée net et non défilable).
func TestBackupsSettingsTableScrolls(t *testing.T) {
	body := readTemplate(t, filepath.Join("templates", "backups.html"))
	tables := strings.Count(body, "<table")
	if tables == 0 {
		t.Fatal("backups.html: aucun tableau, le test ne vérifie plus rien")
	}
	if got := strings.Count(body, "overflow-x-auto"); got < tables {
		t.Errorf("backups.html: %d tableau(x) pour seulement %d conteneur(s) overflow-x-auto", tables, got)
	}
}

// TestNotificationPermissionHasExplicitTrigger : supprimer la demande de permission
// spontanée était juste (le navigateur l'ignore hors geste utilisateur), mais la
// supprimer SANS remplacement laisse la permission à « default » à vie et les
// notifications définitivement mortes.
func TestNotificationPermissionHasExplicitTrigger(t *testing.T) {
	theme := readAsset(t, "theme.js")
	if !strings.Contains(theme, "sendLocalNotif") {
		t.Fatal("theme.js: sendLocalNotif a disparu, ce test ne vérifie plus rien")
	}
	if !strings.Contains(theme, "requestPermission") {
		t.Fatal("theme.js: aucune demande de permission — les notifications ne peuvent jamais être accordées ; retirer sendLocalNotif ou rebrancher un déclencheur")
	}

	// Une fonction jamais appelée serait la même impasse : une vue doit la câbler.
	wired := false
	for _, f := range templateFiles(t) {
		if strings.Contains(readTemplate(t, f), "requestNotificationPermission()") {
			wired = true
			break
		}
	}
	if !wired {
		t.Error("aucune vue n'appelle requestNotificationPermission() — la permission reste à « default » à vie")
	}
}

// --------------------------------------------------------------------------
// 6. CI
// --------------------------------------------------------------------------

// TestCIRunsMigrationsAgainstRealMySQL : les tests qui rejouent la montée de
// version d'une base cliente existante sont le chemin le plus risqué du produit.
// Ils étaient `t.Skip` faute de DSN, donc jamais exercés.
func TestCIRunsMigrationsAgainstRealMySQL(t *testing.T) {
	ci := repoFile(t, ".github", "workflows", "ci-deploy.yml")
	for _, needle := range []string{
		"mysql:8.0",                // service de base de données
		"GOACORE_TEST_DSN",         // variable qui active les tests d'intégration
		"GOACORE_REQUIRE_DB_TESTS", // verrou : un DSN absent devient un échec
	} {
		if !strings.Contains(ci, needle) {
			t.Errorf("ci-deploy.yml: %s manquant — le chemin de mise à niveau d'une base cliente n'est plus testé", needle)
		}
	}
	// Le job doit bloquer un déploiement, sinon il ne protège personne.
	if !strings.Contains(ci, "db-tests]") {
		t.Error("ci-deploy.yml: les jobs de déploiement ne dépendent pas de db-tests")
	}
}
