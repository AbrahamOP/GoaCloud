# GoaCloud

GoaCloud is a self-hosted **Single Pane of Glass** dashboard for managing your homelab infrastructure. It brings together Proxmox VM management, Wazuh SIEM security, Ansible automation, SSH key management, and AI-powered SOAR — all in one place.

![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)

## Features

- **Dashboard** — Overview of your apps, services health status, and quick access to all modules.
- **Proxmox Management** — List VMs/CTs, start/stop/reboot, snapshots, console access, resource monitoring (CPU, RAM, Storage).
- **Wazuh SIEM** — Security alerts, agent status, vulnerability scanning, CVE summary, geo-location data.
- **SOAR & AI** — Automatic alert enrichment via AI (Ollama/OpenAI), Discord notifications with severity levels.
- **Ansible Automation** — Upload/write playbooks, execute on target VMs, scheduled executions, output history.
- **SSH Key Manager** — Generate, import, deploy SSH keys to VMs via Cloud-Init or password auth.
- **Web Console** — Browser-based SSH terminal to your VMs.
- **User Management** — Admin/Viewer roles, MFA (TOTP), audit logs.
- **App Catalog** — Register external apps with health checks and favorites.

## Prerequisites

- **Docker** & **Docker Compose**
- A **Proxmox VE** server with an API token
- (Optional) A **Wazuh** server for security features
- (Optional) **Ollama** or an OpenAI API key for AI enrichment
- (Optional) A **Discord** bot for notifications

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/AbrahamOP/goacloud.git
cd goacloud
```

### 2. Configure environment variables

```bash
cp .env.example .env
nano .env
```

Fill in the required values (see [Configuration](#configuration) below).

### 3. Start the stack

```bash
docker-compose up -d --build
```

The application will be available at `https://localhost:8443`.

### 4. Initial setup

On first launch, you will be redirected to `/setup` to create your admin account.

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `SESSION_SECRET` | **Strong random secret** for session encryption. Must be changed from default. |
| `DB_USER` | MySQL username |
| `DB_PASSWORD` | MySQL password |
| `DB_ROOT_PASSWORD` | MySQL root password |
| `DB_NAME` | Database name (default: `goacloud`) |

### Proxmox

| Variable | Description |
|----------|-------------|
| `PROXMOX_URL` | Proxmox API URL (e.g. `https://192.168.1.100:8006`) |
| `PROXMOX_NODE` | Proxmox node name (default: `pve`) |
| `PROXMOX_TOKEN_ID` | API Token ID (e.g. `user@pam!token-name`) |
| `PROXMOX_TOKEN_SECRET` | API Token secret |

### Wazuh

| Variable | Description |
|----------|-------------|
| `WAZUH_API_URL` | Wazuh Manager API URL (e.g. `https://192.168.1.101:55000`) |
| `WAZUH_USER` | Wazuh API username (default: `wazuh-wui`) |
| `WAZUH_PASSWORD` | Wazuh API password |
| `WAZUH_INDEXER_URL` | Wazuh Indexer URL (e.g. `https://192.168.1.101:9200`) |
| `WAZUH_INDEXER_USER` | Indexer username (default: `admin`) |
| `WAZUH_INDEXER_PASSWORD` | Indexer password |

#### Retrieving Wazuh passwords

**Wazuh API password** (user `wazuh-wui`):

```bash
cat ~/wazuh.creds
```

**Wazuh Indexer password** (user `admin`):

```bash
cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

### Discord (Optional)

| Variable | Description |
|----------|-------------|
| `DISCORD_BOTTOKEN` | Discord bot token |
| `DISCORD_CHANNEL_ID` | Default notification channel ID |
| `DISCORD_AUTH_CHANNEL_ID` | Channel for auth alerts (falls back to default) |
| `DISCORD_ANSIBLE_CHANNEL_ID` | Channel for Ansible notifications (falls back to default) |

### AI Enrichment (Optional)

| Variable | Description |
|----------|-------------|
| `AI_PROVIDER` | `ollama` or `openai` |
| `AI_URL` | Provider URL (default: `http://host.docker.internal:11434` for Ollama) |
| `AI_API_KEY` | API key (required for OpenAI) |
| `AI_MODEL` | Model name (e.g. `mistral`, `phi3:medium`, `gpt-4`) |

### Other

| Variable | Description |
|----------|-------------|
| `SKIP_TLS_VERIFY` | Set to `true` if Proxmox/Wazuh use self-signed certificates |

## Usage

### Ansible

1. Upload playbooks via the UI or place `.yml` files in the `playbooks/` directory.
2. Associate SSH keys to VMs in the SSH Keys section.
3. Select a playbook, target VM, and SSH key (auto-selected if associated).
4. Click **Run** or create a scheduled execution.

### Security (Wazuh & SOAR)

- Agents and alerts are fetched automatically from the Wazuh API.
- Configure alert types in the SOAR page (SSH, Sudo, FIM, Packages).
- AI enrichment adds analysis and recommendations to Discord alerts.

### SSH Key Management

- Generate ED25519 key pairs directly from the UI.
- Deploy keys to VMs via Proxmox Cloud-Init or SSH password auth.
- Keys are encrypted at rest in the database.

## Development

- **Backend**: Go 1.22, chi router, html/template
- **Frontend**: Tailwind CSS, vanilla JavaScript
- **Database**: MySQL 8.0

```bash
# Rebuild only the app container after code changes
docker-compose up -d --build app
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Go 1.22 |
| Router | go-chi/chi v5 |
| Database | MySQL 8.0 |
| Frontend | Tailwind CSS + Vanilla JS |
| Auth | bcrypt + TOTP (MFA) + CSRF |
| Sessions | gorilla/sessions (encrypted cookies) |
| WebSocket | gorilla/websocket |
| Container | Docker + Alpine |

## License

MIT — see [LICENSE](LICENSE).
