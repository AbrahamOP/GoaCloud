# GoaCore — Feuille de route de produification

> De **dashboard homelab** vers **produit open-source installable par une PME**.

## Vision

**GoaCore** est l'app **self-hosted & open-source** que les PME installent **chez elles** pour **suivre et gérer leur infrastructure** en totale autonomie : infra (VMs Proxmox), cybersécurité (SIEM / SOAR / IA) et backup vérifié — depuis un seul tableau de bord simple.

- **Cible** : PME qui auto-hébergent leur propre Proxmox (IT interne léger).
- **Déploiement** : auto-hébergé chez le client, **une instance par PME (mono-tenant)**.
- **Cœur de valeur** : suite **intégrée** infra + sécurité + backup (la force = l'intégration).
- **Business** : open-source + support / services.

## Principes directeurs (non négociables)

1. **Souveraineté totale / privacy by design** — le créateur n'a **aucun accès** aux données ni à l'usage des clients. **Zéro télémétrie, zéro phone-home.** Les données restent 100 % chez la PME.
2. **Mono-tenant auto-hébergé** — une instance = une PME = un Proxmox. Pas de multi-tenant.
3. **Open-source auditable** — le code est public et vérifiable (pas de backdoor), gage de confiance.
4. **Self-service** — tout se configure **dans l'app** (DB/UI), jamais par SSH/CLI/édition de fichiers sur l'hôte.
5. **Intégrations vers les ressources DU client** — clouds (rclone), Discord, IA… pointent vers les comptes de la PME, jamais ceux du créateur.

## État actuel (point de départ)

GoaCore est aujourd'hui un dashboard Go (chi / MySQL) très fonctionnel mais **câblé sur le homelab du créateur** : modules infra (Proxmox, console), sécurité (Wazuh, SOAR/IA, Suricata), automatisation (Ansible, SSH), **backup vérifié (GoaBackup)**, notifications Discord. Configuration majoritairement par **variables d'env**, plusieurs **valeurs en dur** (IPs, node, VLAN, VMID, chemins), et des **pré-requis manuels** sur l'hôte (helper de backup, clés). Le module GoaBackup a déjà été audité ; le reste reste à passer en revue.

---

## Les jalons

### Jalon 0 — Audit global & nettoyage *(prérequis open-source)*

- **Objectif** : connaître l'ampleur exacte de la « dette homelab » sur **tout** GoaCore et garantir qu'aucun secret ne sera publié.
- **Pourquoi maintenant** : sûr (lecture/nettoyage, pas de refactor risqué), donne la vraie image, et **publier un secret = incident** → indispensable avant l'open-source.
- **Périmètre** :
  - Scan **secrets** dans le code **et l'historique git** (IPs, tokens, mots de passe, clés privées).
  - Audit **souveraineté** : recenser tous les appels réseau sortants, garantir **zéro phone-home / télémétrie**.
  - Audit **hardcoding** par module (IPs 192.168.x, node « Proxmox », domaines `goacloud.fr`, VLAN, VMID, storages, chemins).
  - Audit **secrets en clair / defaults dangereux** (`SESSION_SECRET` par défaut, mots de passe `root`, skip TLS).
- **Effort** : moyen · **Risque** : faible · **Dépendances** : aucune.
- **Definition of Done** : rapport consolidé (bloqueurs / dettes / OK), liste exhaustive des secrets à purger (code + historique), confirmation « zéro appel sortant non choisi par le client ».

### Jalon 1 — Onboarding infrastructure in-app *(le déblocage self-service)*

- **Objectif** : une PME branche **son** Proxmox depuis l'app, sans variable d'env ni intervention.
- **Périmètre** :
  - Page **« Connexion »** : URL + token Proxmox saisis et **testés en live**, stockés **chiffrés en DB**.
  - Migration progressive **config env → config DB** (l'instance se configure dans l'app, première installation guidée).
  - Détection automatique du node / des storages via l'API Proxmox.
- **Effort** : élevé · **Dépendances** : Jalon 0.
- **Definition of Done** : une instance vierge peut être connectée à n'importe quel Proxmox via l'UI uniquement ; plus aucune variable d'env Proxmox requise.

### Jalon 2 — Dé-câbler les valeurs + auto-détection

- **Objectif** : supprimer toutes les constantes spécifiques à une infra donnée.
- **Périmètre** :
  - Constantes → config ou **auto-détection** : storage backup/restore, bridge réseau, VLAN d'isolation, plage VMID sandbox, node, chemins.
  - **Helper de backup générique** : retrait de la whitelist de remotes, chemins & sonde disque agnostiques du type de stockage (LVM-thin / ZFS / PBS).
  - Une **seule source de vérité** pour les valeurs partagées entre l'app et le helper.
- **Effort** : moyen · **Dépendances** : Jalon 1.
- **Definition of Done** : aucune valeur d'infra en dur dans le code ; tout est détecté ou configurable ; le module backup fonctionne sur un Proxmox au layout différent (ZFS, autre bridge…).

### Jalon 3 — Canal & destinations en self-service

- **Objectif** : brancher le canal d'exécution et les destinations cloud **sans CLI**.
- **Périmètre** :
  - **Installeur du canal** : bouton qui génère la commande à exécuter sur le Proxmox du client (clé **générée in-app**, chiffrée en DB, plus aucun dépôt manuel ni montage de fichier).
  - **Connexion cloud du client** (rclone) depuis l'UI — vers **son** Drive / S3 / Backblaze, jamais celui du créateur.
- **Effort** : élevé · **Dépendances** : Jalons 1-2.
- **Definition of Done** : une PME active l'off-site et le restore-test depuis l'UI ; le helper s'installe via une commande générée ; le cloud connecté est celui du client.

### Jalon 4 — Installation clé en main + publication open-source — ✅ Réalisé (2026-06-27)

- **Objectif** : rendre l'installation triviale et publier le projet proprement.
- **Livré** : image Docker publique multi-arch (`ghcr.io/goacloud/goacore`, workflow `publish-image.yml` sur tag), `install/docker-compose.yml` + `.env.example` autonomes, « Quick start » README, repo public AGPL-3.0 nettoyé (aucun secret ni IP/chemin perso, y compris dans les tests).
- **Périmètre** :
  - **Docker Compose** documenté, **assistant de configuration** (setup wizard), **defaults sains**.
  - `LICENSE`, `README`, documentation d'installation et d'usage, `CONTRIBUTING`.
  - **Nettoyage final** du repo et de l'historique (issu du Jalon 0) → **passage du repo en public**.
- **Effort** : moyen · **Dépendances** : Jalon 0 (nettoyage), Jalons 1-3 (self-service).
- **Definition of Done** : un tiers installe GoaCore à partir du seul README en quelques minutes ; repo public sans aucun secret ni valeur perso.

### Jalon 5 — Industrialisation continue

- **Objectif** : qualité et pérennité produit.
- **Périmètre** : CI / tests, documentation utilisateur, revue & polish des modules un par un (Proxmox, Wazuh, Ansible, SOAR, SSH), accessibilité, i18n éventuelle.
- **Effort** : continu · **Dépendances** : transverse.
- **Definition of Done** : continu (pas de fin) — couverture de tests et doc maintenues à chaque évolution.

---

## Suivi des jalons

| Jalon | Statut | Note |
|-------|--------|------|
| 0 — Audit global & nettoyage | ✅ Fait | Audit (0 secret, 0 phone-home backend) + nettoyage : CDN vendorisés, CSP durcie, storage/bridge configurables, user SSH générique |
| 1 — Onboarding infra in-app | ✅ Fait | **Proxmox + Wazuh + AI + Discord** : config in-app chiffrée, test live, hot-reload (registry). Discord websocket reconnecté à chaud. OnboardingGate + migration env→DB |
| 2 — Dé-câbler + auto-détection | ✅ Fait | storage/VLAN/bridge sandbox résolus depuis la connexion ; helper agnostique LVM/ZFS/dir ; cryptcheck off-site portable ; garde VMID en dur + test anti-drift en CI ; doc déployée |
| 3 — Canal & destinations self-service | ✅ Fait | clé ed25519 générée in-app (chiffrée DB) ; installeur root auditable servi par l'app (jamais d'exécution distante) ; helper embarqué ; canal hot-reload ; cloud « guider + détecter » (S3/Backblaze self-service, GDrive guidé) |
| 4 — Install clé en main + open-source | 🔄 En cours | Repo **déjà PUBLIC** + AGPL-3.0 ; audit historique CLEAN (0 secret). Install clé en main faite sur `dev` (compose durci + healthcheck, .env.example, garde-fou SESSION_SECRET, CONTRIBUTING/SECURITY). **Reste : synchroniser `main` (vitrine) + polish** |
| 5 — Industrialisation continue | ⏳ À venir | Transverse |

> Note produit : le module **GoaBackup** (sauvegardes vérifiées : restauration réelle prouvée) est le **différenciateur** déjà construit. Le détail de sa généralisation est suivi à part.
