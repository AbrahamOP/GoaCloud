# GoaCore

> **Single pane of glass** open-source et auto-hébergé pour les PME qui exploitent leur propre Proxmox : infrastructure, sécurité (SIEM/SOAR) et **backup vérifié** — réuni dans un seul tableau de bord, sans télémétrie.

![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
[![Image GHCR](https://img.shields.io/badge/ghcr.io-goacore-2496ED?logo=docker&logoColor=white)](https://github.com/GoaCloud/GoaCore/pkgs/container/goacore)
![Statut](https://img.shields.io/badge/Statut-pré--1.0-orange)
![License](https://img.shields.io/badge/License-AGPL--3.0-blue)
[![Discord](https://img.shields.io/badge/Discord-Rejoindre%20la%20communauté-5865F2?logo=discord&logoColor=white)](https://discord.gg/pSW7kxJSjf)

GoaCore unifie trois domaines habituellement éclatés entre plusieurs outils — **gestion d'infrastructure**, **opérations de sécurité** et **sauvegardes dont la restaurabilité est réellement prouvée par un test de restauration** — en une suite intégrée que la PME installe chez elle et configure entièrement depuis l'interface web.

> **À savoir avant de commencer** — GoaCore est fonctionnel mais reste **pré-1.0, en développement actif**. Le code est **open-source (AGPL-3.0) et public** ; l'assistant d'installation clé en main et le polish produit sont en cours (voir [Roadmap](#roadmap)). Ce n'est pas (encore) un produit commercial fini et éprouvé en production à large échelle.

---

## Pourquoi GoaCore

GoaCore est conçu **souverain et privacy-by-design**, et ce n'est pas un argument marketing :

- **Zéro télémétrie, zéro phone-home.** L'audit du Jalon 0 a explicitement constaté « 0 secret, 0 phone-home backend ». Le créateur n'a **aucun accès** aux données ni à l'usage des clients. Principe non négociable.
- **Données 100 % chez la PME.** Les secrets sont chiffrés dans **votre** MySQL, les sauvegardes vont sur **votre** stockage Proxmox et **votre** cloud (remote rclone), l'IA peut pointer vers un Ollama auto-hébergé ou tout endpoint compatible OpenAI que **vous** contrôlez.
- **Mono-tenant.** Une instance = une PME = un Proxmox. Pas de multi-tenant, pas de plan de contrôle SaaS.
- **Code auditable.** Le code est destiné à être public et vérifiable — pas de backdoor. Les intégrations ciblent toujours les ressources **du client**, jamais celles du créateur.

---

## Fonctionnalités

### Infrastructure (Proxmox)

- Tableau de bord des VMs / conteneurs : liste, démarrage / arrêt / redémarrage, snapshots, métriques CPU / RAM / stockage en direct, le tout via l'API Proxmox.
- Console **VNC** dans le navigateur et **terminal SSH web** vers les invités. Les identifiants de console suivent la connexion Proxmox active (hot-reload).

### Sécurité (SIEM / SOAR)

- **Intégration Wazuh** : alertes de sécurité, état des agents, résumé des vulnérabilités / CVE, via les clients API Wazuh + Wazuh Indexer (port 9200).
- **SOAR avec enrichissement IA** : un worker en arrière-plan classe et enrichit les alertes Wazuh (SSH, Sudo, FIM, Packages) via Ollama **ou** tout endpoint compatible OpenAI, puis pousse des notifications Discord graduées par sévérité.

### Backup vérifié — le différenciateur

- **GoaBackup** : sauvegardes `vzdump` à la demande et planifiées, copie off-site optionnelle vers le remote rclone de l'entreprise, et surtout **restaurabilité prouvée par un vrai test de restauration** :
  - **N1** — intégrité de l'archive off-site (cryptcheck).
  - **N2 / N3** — restauration réelle dans un invité **sandbox jetable et isolé**, boot réel, healthcheck optionnel (N3), mesure du **RTO**, puis destruction garantie de la sandbox.

### Automatisation

- **Ansible** : écriture / upload de playbooks, exécution sur les VMs cibles avec leurs clés SSH associées, exécutions planifiées et historique des sorties.
- **Gestionnaire de clés SSH** : génération de paires ED25519 dans l'app, déploiement sur les VMs via Cloud-Init ou mot de passe, clés **chiffrées au repos**.

### Transverse

- **Gestion des utilisateurs** : rôles Admin / Viewer, MFA TOTP, protection CSRF, sessions à cookies chiffrés, journal d'audit.
- **Catalogue d'applications** avec health checks et favoris.
- **Notifications Discord** pour les événements d'authentification, les runs Ansible et les verdicts de test de restauration, avec un canal séparé par catégorie.

---

## Aperçu

```
┌──────────────────────────────────────────────────────────────┐
│  GoaCore                                     [Admin ▾]        │
├──────────┬───────────────────────────────────────────────────┤
│ Infra    │  VMs: 12 running · 3 stopped     CPU ▓▓▓░ 38%      │
│ Sécurité │  Alertes Wazuh: 4 high · 21 med   RAM ▓▓▓▓▓ 71%    │
│ Backup   │  Dernier test restore: ✓ N3 PROUVÉ · RTO 4m12s     │
│ Ansible  │  Canal backup: connecté · Off-site: OK             │
│ SSH      │                                                    │
└──────────┴───────────────────────────────────────────────────┘
```

*(Placeholder textuel — captures d'écran à venir.)*

---

## Stack technique

| Composant   | Technologie                                                            |
|-------------|-----------------------------------------------------------------------|
| Backend     | Go 1.22, routeur `go-chi/chi` v5, `html/template` (rendu serveur)     |
| Base        | MySQL 8.0                                                              |
| Frontend    | Tailwind CSS + JavaScript vanilla (assets CDN vendorisés localement)  |
| Auth        | bcrypt + MFA TOTP + CSRF + `gorilla/sessions` (cookies chiffrés)      |
| Temps réel  | `gorilla/websocket` + broker SSE                                      |
| Packaging   | Docker multi-stage (`golang:alpine` → `alpine:3.21`, user non-root, templates/assets/helper embarqués via `go:embed`) |
| Déploiement | Docker Compose (app + MySQL) ; Ansible + `openssh-client` embarqués dans l'image runtime pour le module d'automatisation |

---

## Installation

GoaCore se déploie avec Docker. La méthode rapide ne nécessite **aucune compilation** :
l'image publique multi-arch (amd64 / arm64) est tirée depuis GitHub Container Registry.

### Installation rapide (image pré-construite) — recommandée

```bash
mkdir goacore && cd goacore
curl -O https://raw.githubusercontent.com/GoaCloud/GoaCore/main/install/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/GoaCloud/GoaCore/main/install/.env.example
# Éditez .env : générez SESSION_SECRET (openssl rand -hex 32) + des mots de passe MySQL forts
docker compose up -d
```

Ouvrez ensuite `https://<hôte>:8443/setup` pour créer le compte administrateur. Proxmox,
Wazuh, IA et Discord sont optionnels et se configurent depuis l'interface. L'image est
publiée sur [`ghcr.io/goacloud/goacore`](https://github.com/GoaCloud/GoaCore/pkgs/container/goacore)
à chaque version (`vX.Y.Z`) ; épinglez une version via `GOACORE_TAG` dans `.env`.

---

### Installation depuis les sources

Pour contribuer ou construire l'image vous-même.

#### Prérequis

- **Docker** et **Docker Compose**.
- Un serveur **Proxmox VE** (pour les modules infra, console, GoaBackup et test de restauration).
- *(Optionnel)* Wazuh, un fournisseur IA (Ollama / compatible OpenAI) et un bot Discord — tous configurables plus tard depuis l'UI.

### 1. Cloner le dépôt

```bash
git clone https://github.com/<owner>/goacore.git
cd goacore
```

### 2. Variables minimales

Seules quelques variables sont requises au démarrage. Tout le reste (Proxmox, Wazuh, IA, Discord, canal de backup) est **optionnel au boot** et destiné à être configuré depuis l'interface.

```bash
cp .env.example .env
```

| Variable           | Description                                                                                                            |
|--------------------|----------------------------------------------------------------------------------------------------------------------|
| `SESSION_SECRET`   | **Secret aléatoire fort** (≥ 32 caractères). L'app **refuse de démarrer** si la valeur est vide, trop courte ou un placeholder connu. Générez-la avec `openssl rand -hex 32`. |
| `DB_USER`          | Utilisateur MySQL                                                                                                     |
| `DB_PASSWORD`      | Mot de passe MySQL **fort** (ex. `openssl rand -base64 24`)                                                           |
| `DB_ROOT_PASSWORD` | Mot de passe root MySQL **fort**                                                                                      |
| `DB_NAME`          | Nom de la base (par défaut : `goacloud`)                                                                              |

> Toutes les autres variables (Proxmox, Wazuh, IA, Discord, canal GoaBackup) sont **optionnelles au boot** et commentées dans `.env.example` — elles se configurent depuis l'interface (précédence base > env). `PROXMOX_STORAGE` / `PROXMOX_BRIDGE` laissés vides = auto-détection via l'API Proxmox ; le nœud Proxmox par défaut est le générique `pve`.

### 3. Démarrer la stack

```bash
docker-compose up -d --build
```

L'application sert en **HTTPS sur le port 8443** (certificat auto-signé généré automatiquement, destiné à être placé derrière un reverse proxy ou remplacé).

### 4. Premier lancement

Au premier démarrage, vous êtes redirigé vers `/setup` pour créer le **compte administrateur**.

---

## Configuration in-app

Après `/setup`, **toute** la configuration se fait depuis l'application — pas de variables d'env, pas de SSH, pas d'édition de fichiers sur l'hôte.

Chaque panneau de connexion (Proxmox, Wazuh API, Wazuh Indexer, IA, Discord) permet de saisir URL + identifiants, de cliquer sur **« Tester la connexion »** (sonde en direct, distingue erreurs réseau et erreurs d'authentification), puis d'**enregistrer** :

- le secret est **chiffré dans MySQL** (AES-256-GCM, clé dérivée de `SESSION_SECRET`) ;
- le client actif est **hot-reloadé atomiquement** (prochain tick worker / rafraîchissement immédiat du cache VM) ;
- une entrée d'audit est écrite.

La précédence est **ligne DB > env > non configuré**, donc une config existante en variables d'env peut être importée en base en un clic, puis annulée si besoin.

### Canal de backup en self-service

L'onboarding du canal GoaBackup est un assistant guidé :

1. GoaCore **génère une clé ed25519** dans l'app et stocke la clé privée (PEM) chiffrée.
2. Il présente une **commande d'installation root copier-coller** (URL dérivée de l'hôte, jamais un domaine en dur) accompagnée du **SHA-256** du helper pour vérifier l'intégrité.
3. L'admin exécute le script sur **son** Proxmox — **l'app ne se connecte jamais en SSH pour installer**, elle ne fait que servir un script auditable.
4. **« Vérifier l'installation »** prouve le canal de bout en bout (disk-free via le helper SSH en forced-command).

Les destinations cloud sont les **remotes rclone de l'entreprise**, listés en direct depuis l'hôte.

---

## Le différenciateur : GoaBackup

La plupart des solutions sauvegardent. GoaBackup **prouve que la restauration fonctionne** :

| Niveau | Ce qui est prouvé                                                                                  |
|--------|---------------------------------------------------------------------------------------------------|
| **N1** | Intégrité de l'archive off-site (cryptcheck).                                                      |
| **N2** | Restauration réelle dans un invité **sandbox jetable et isolé**, boot réel, puis destruction.     |
| **N3** | Idem N2 + **healthcheck** applicatif, mesure du **RTO**, teardown garanti.                         |

Le test de restauration est **destructif par nature** : il restaure dans une plage de VMID sandbox dédiée (9500-9599) sur l'hôte du client et dépend d'une **isolation réseau correcte** de la sandbox. Des valeurs par défaut existent (VLAN 99, `vmbr1`), mais **l'opérateur reste responsable de l'isolation réelle** — l'UI avertit lorsque le bridge de la sandbox est identique au bridge de création prod.

---

## Sécurité & souveraineté

- **Secrets chiffrés** au repos dans la base du client (AES-256-GCM, clé dérivée de `SESSION_SECRET`).
- **Connexions testées en direct** avant enregistrement ; toute modification est **auditée**.
- **Contrôle d'accès** : actions sensibles réservées au rôle **Admin** (les Viewers sont en lecture seule), **MFA TOTP**, **CSRF**, sessions à cookies chiffrés.
- **Zéro phone-home** : aucun appel sortant qui ne soit choisi par le client. Les intégrations IA / cloud / Discord pointent vers les ressources **du client**.
- `SKIP_TLS_VERIFY` existe pour les certificats auto-signés de Proxmox / Wazuh — à utiliser en connaissance de cause.

---

## Limites connues

- **Pré-1.0, développement actif** : le code est public (AGPL-3.0) et l'installation clé en main est en place (image publique GHCR + Docker Compose), mais le polish produit continue (**Jalon 5**). Ce n'est pas une release stable largement déployée.
- **Centré Proxmox** : la gestion des VMs, la console, le canal GoaBackup et la sandbox de test de restauration sont câblés spécifiquement pour Proxmox VE. Ce n'est pas un gestionnaire d'hyperviseur générique.
- **Off-site cloud via rclone** : suppose que rclone est configuré sur l'hôte Proxmox par l'admin. Les remotes type S3 / Backblaze sont self-service, mais la mise en place **Google Drive est guidée** (l'admin lance encore `rclone config` sur l'hôte pour l'étape OAuth headless) — **pas** un flux OAuth complet in-app.
- **Wazuh, IA et Discord sont optionnels** : sans aucun configuré, GoaCore est essentiellement un dashboard Proxmox + backup.
- **HTTPS auto-signé** par défaut (destiné à être placé derrière un reverse proxy ou remplacé).
- **Couverture de tests partielle**, concentrée sur les chemins backup / restore / connection-store / canal ; beaucoup de handlers ne sont pas encore couverts.
- Le pipeline CI/CD fourni est taillé pour l'environnement self-hosted de l'auteur et **n'est pas** un exemple générique pour utilisateurs finaux.

---

## Roadmap

GoaCore passe d'un dashboard homelab à un produit open-source installable par une PME. Détails dans [ROADMAP.md](ROADMAP.md).

- **Jalon 0** — Audit global & nettoyage *(prérequis open-source)* ✅
- **Jalon 1** — Onboarding infrastructure in-app ✅
- **Jalon 2** — Dé-câbler les valeurs en dur + auto-détection ✅
- **Jalon 3** — Canal & destinations de backup en self-service ✅
- **Jalon 4** — Installation clé en main + **publication open-source** ✅ *(repo public AGPL-3.0, image Docker publique multi-arch sur GHCR, install Docker Compose clé en main, repo nettoyé des valeurs perso)*
- **Jalon 5** — Industrialisation continue 🔄 *(CI/tests, polish des modules, doc — en cours)*

---

## Contributing

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour le workflow de contribution et [SECURITY.md](SECURITY.md) pour la divulgation responsable des vulnérabilités.

---

## License

GoaCore est distribué sous licence **GNU Affero General Public License v3.0** (AGPL-3.0) — voir [LICENSE](LICENSE).

La **clause réseau** de l'AGPL impose que toute version modifiée mise à disposition via un réseau (y compris en SaaS) en publie les sources : elle préserve la souveraineté du modèle et empêche la fermeture du code en produit propriétaire. C'est un choix délibéré, cohérent avec le positionnement souverain du projet.

Copyright © 2026 GoaCore.
