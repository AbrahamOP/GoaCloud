# Contribuer à GoaCore

Merci de l'intérêt que vous portez à GoaCore. Ce document explique comment
construire le projet en local, lancer les tests, et proposer vos modifications.

GoaCore est un produit **auto-hébergé, mono-tenant et souverain** : pas de
télémétrie, pas de plan de contrôle SaaS, pas de phone-home. Toute contribution
doit respecter ce principe — aucune intégration ne doit collecter de données ni
joindre une ressource autre que celle de l'instance qui l'exécute.

> Vous avez trouvé une faille de sécurité ? **Ne pas ouvrir d'issue publique.**
> Suivez la procédure de divulgation responsable décrite dans
> [SECURITY.md](SECURITY.md).

---

## Licence des contributions

GoaCore est distribué sous licence **GNU Affero General Public License v3.0**
(AGPL-3.0) — voir [LICENSE](LICENSE).

En proposant une contribution (Pull Request, patch, correctif), **vous acceptez
que votre contribution soit publiée sous cette même licence AGPL-3.0**. N'envoyez
que du code dont vous détenez les droits ou que vous êtes autorisé à publier sous
AGPL-3.0. N'incluez pas de code tiers incompatible avec l'AGPL.

---

## Prérequis

- **Go 1.22+** (le module cible `go 1.22`)
- **Docker** + **Docker Compose** (pour la stack complète avec MySQL)
- **Node.js / npm** (uniquement si vous touchez au CSS Tailwind)
- `git`, et idéalement `gofmt` + `go vet` (fournis avec Go)

---

## Build & run en local

### Option recommandée — Docker Compose (stack complète)

C'est la voie la plus simple : elle démarre l'application **et** une base MySQL
préconfigurée.

```bash
# 1. Copier le modèle de configuration et l'éditer
cp .env.example .env
$EDITOR .env

# 2. Construire et lancer
docker compose up --build
```

L'interface est alors disponible sur :

- `https://localhost:8443` (HTTPS, point d'entrée principal, certificat auto-signé en dev)
- `http://localhost:8080` (HTTP interne, mappé sur le port 8080 du conteneur)

Variables **minimales** à renseigner dans `.env` pour démarrer (les autres
intégrations — Proxmox, Wazuh, Discord, IA — sont configurables ensuite depuis
l'interface d'onboarding et peuvent rester vides au premier lancement) :

```dotenv
# Base de données (la stack Compose crée cette base automatiquement)
DB_USER=goacloud
DB_PASSWORD=change-me
DB_ROOT_PASSWORD=change-me-root
DB_NAME=goacloud

# Clé de session — OBLIGATOIRE, doit être une longue valeur aléatoire
# Générer : openssl rand -hex 32
SESSION_SECRET=change-me-to-a-long-random-secret

# En dev, si vos backends (Proxmox/Wazuh) ont des certs auto-signés
SKIP_TLS_VERIFY=true
```

> **`SESSION_SECRET` n'est jamais committé.** Chaque instance génère le sien.
> Le fichier `.env` est ignoré par git (`.gitignore`) — ne le forcez jamais
> dans un commit.

La liste complète des variables (Proxmox, Wazuh, Wazuh Indexer, Discord,
enrichissement IA, TLS) est documentée et commentée dans
[`.env.example`](.env.example).

### Option — binaire Go seul

Si vous fournissez votre propre MySQL, vous pouvez compiler et lancer le binaire
directement :

```bash
go mod download
go build -o bin/goacloud ./cmd/server
./bin/goacloud
```

Le point d'entrée est `cmd/server/main.go`. Les variables d'environnement
attendues sont les mêmes que dans `docker-compose.yml` (notamment `DB_HOST`,
`DB_USER`, `DB_PASS`, `PORT`, `SESSION_SECRET`).

### CSS (Tailwind) — seulement si vous modifiez le style

Le CSS compilé est versionné ; ne le régénérez que si vous modifiez des classes.

```bash
npm install
npx tailwindcss -i ./tailwind.input.css -o ./assets/<sortie> --watch
```

---

## Lancer les tests

Le projet est testé via le toolchain Go standard. Avant toute Pull Request,
assurez-vous que les commandes suivantes passent — ce sont celles qu'exécute la
CI, et elles y sont bloquantes :

```bash
gofmt -l .          # ne doit rien afficher (sinon : gofmt -w <fichier>)
go vet ./...        # analyse statique
go test ./...       # suite de tests
go test ./... -race # détecteur de data races (workers, scheduler, caches)
go build ./...      # compilation
```

La CI lance en plus [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck),
qui signale les vulnérabilités connues **réellement appelées** par le code :

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

> Cette étape est temporairement non bloquante, le temps de résorber la dette de
> dépendances existante. Ne l'aggravez pas : une PR ne doit pas introduire de
> nouvelle vulnérabilité appelée.

Les tests couvrent notamment la configuration, les middlewares (rate-limit,
onboarding gate), les workers et le moteur de sauvegarde/restauration. Ajoutez
des tests pour tout nouveau comportement, et veillez à ne pas casser le
**test anti-drift** du helper `goabackup` (la frontière de sécurité côté hôte
Proxmox est validée en CI).

---

## Conventions

### Style de code

- **`gofmt`** obligatoire (la CI rejette le code non formaté).
- **`go vet`** sans avertissement.
- Suivez les idiomes Go usuels (noms, gestion d'erreurs, pas de panique sur les
  chemins normaux). Restez cohérent avec le code existant.

### Branches

- **`main`** : branche stable / publiée. Pas de push direct.
- **`dev`** : branche d'intégration. Les fonctionnalités partent d'ici.
- Branche de travail : `feat/...`, `fix/...`, `docs/...`, `ci/...`, etc.

Ouvrez votre branche depuis `dev`, et ciblez **`dev`** (ou `main` pour un
correctif urgent, selon la nature du changement).

### Messages de commit — Conventional Commits

Le projet suit la convention [Conventional Commits](https://www.conventionalcommits.org/) :

```
<type>(<scope optionnel>): <description courte à l'impératif>
```

Types courants : `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.

Exemples (tirés de l'historique du dépôt) :

```
feat(jalon3): canal & cloud self-service
fix(soar): redémarrer le worker après une erreur Indexer
docs(license): AGPL-3.0 + README finalisé
```

> **Pas de ligne `Co-Authored-By` ni de footer « Generated with … »** dans les
> messages de commit ou de PR.

---

## Proposer une Pull Request

1. **Forkez** le dépôt (ou créez une branche si vous avez les droits).
2. Branchez-vous depuis `dev` : `git switch dev && git switch -c feat/ma-feature`.
3. Codez, en ajoutant/maintenant les tests.
4. Vérifiez localement : `gofmt -l . && go vet ./... && go test ./... -race`.
5. Committez en Conventional Commits.
6. Poussez et **ouvrez la PR vers `dev`** (ou `main` si justifié).
7. Dans la description, expliquez **le pourquoi** du changement, ce que vous avez
   testé, et tout impact sur la configuration (nouvelle variable d'env, migration
   de schéma `schema.sql`, etc.).

La CI (`gofmt`, `go vet`, `go test` avec et sans `-race`, build, `govulncheck`,
validation du helper `goabackup`) doit être verte avant relecture. Gardez les PR
ciblées et de taille raisonnable : une PR = un sujet.

> Les jobs déclenchés par une Pull Request s'exécutent sur un runner GitHub
> hébergé et jetable, sans accès aux secrets du dépôt : c'est normal qu'une PR
> issue d'un fork n'obtienne ni notification Discord ni déploiement. Seuls les
> `push` sur `dev`/`main`, après relecture et merge, déclenchent le déploiement.

Merci pour votre contribution.
