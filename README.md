# GoaCloud

GoaCloud est une interface unifiée "Single Pane of Glass" pour gérer vos infrastructures. Elle centralise la gestion de VMs Proxmox, la sécurité avec Wazuh, l'automatisation Ansible et le monitoring SIEM/SOAR.

## Fonctionnalités

*   **Dashboard** : Vue d'ensemble de l'état du parc (VMs, Alertes, Agents).
*   **Proxmox** : Liste des VMs, état, démarrage/arrêt/reboot, console VNC.
*   **Wazuh (SIEM)** : Visualisation des alertes de sécurité, état des agents, vulnérabilités.
*   **Ansible (Automation)** :
    *   Gestion et upload de Playbooks.
    *   Exécution de playbooks sur des VMs cibles.
    *   Sélection automatique de la clé SSH appropriée.
*   **SSH Manager** : Gestion des clés SSH, déploiement sur Proxmox.
*   **SOAR & IA** : Enrichissement automatique des alertes via IA (Ollama/OpenAI) et notifications Discord.
*   **Gestion Utilisateurs** : Rôles (Admin/Viewer), Audit Logs.

## Prérequis

*   **Docker** & **Docker Compose**
*   Un serveur **Proxmox** (avec API Token)
*   Un serveur **Wazuh** (pour les fonctionnalités de sécurité)
*   (Optionnel) **Ollama** ou clé OpenAI pour l'enrichissement IA.

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/AbrahamOP/goacloud.git
cd goacloud
```

### 2. Configuration (.env)

Copiez le fichier d'exemple et remplissez vos identifiants :

```bash
cp .env.example .env
nano .env
```

**Variables essentielles :**
*   `PROXMOX_*` : URL et Token pour se connecter à votre hyperviseur.
*   `WAZUH_*` : Accès à l'API Wazuh pour remonter les alertes.
*   `DISCORD_*` : Pour recevoir les notifications d'alertes critiques.

### 3. Démarrage

Utilisez Docker Compose pour lancer l'application et la base de données MySQL :

```bash
docker-compose up -d --build
```

L'application sera accessible sur `http://localhost:8080` (ou le port configuré).

### 4. Premier Démarrage (Setup)

Au premier lancement, la base de données est vide.
1.  Accédez à l'application.
2.  Vous serez redirigé vers la page de **Configuration Initiale (`/setup`)**.
3.  Créez votre compte **Administrateur**.
4.  Connectez-vous.

## Utilisation

### Gestion Ansible
*   Déposez vos playbooks `.yml` dans l'interface ou le dossier `playbooks/`.
*   Associez vos clés SSH aux VMs dans la section "SSH Keys" (Bouton "Edit").
*   Lancez un playbook : choisissez le fichier, la VM, et la clé (auto-sélectionnée).

### Sécurité (Wazuh & IA)
*   Les alertes remontent automatiquement.
*   L'IA enrichit les alertes critiques avec une analyse et des recommandations.
*   Utilisez le bouton "Test AI" dans la page SOAR pour vérifier la connexion.

## Développement

*   **Backend** : Go 1.21+
*   **Frontend** : HTML Templates + Tailwind CSS (CDN)
*   **Base de données** : MySQL

Pour redémarrer uniquement l'application après une modification Go :
```bash
docker-compose up -d --build app
```

## Licence
MIT
