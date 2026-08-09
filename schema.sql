-- =============================================================================
-- GoaCore — schéma de référence (INDICATIF)
--
-- Ce fichier est une PHOTOGRAPHIE du schéma tel qu'il existe après un démarrage
-- réussi de l'application. Il sert à lire/auditer la base sans dérouler le code
-- Go ; il n'est jamais exécuté par l'application.
--
-- LA SOURCE DE VÉRITÉ EST `database.Migrate()` (internal/database/database.go) :
-- c'est lui qui crée les tables, applique les migrations versionnées et les
-- enregistre dans `schema_migrations`. Créer une base à la main à partir de ce
-- fichier reste possible (les CREATE sont alignés sur ceux de Migrate), mais
-- Migrate sera de toute façon rejoué au démarrage et complètera ce qui manque.
--
-- RÈGLE : toute évolution de schéma se fait par une nouvelle migration versionnée
-- dans `schemaMigrations`, JAMAIS en modifiant une version déjà publiée. Ce
-- fichier est mis à jour dans la foulée pour rester le reflet de l'état final.
-- =============================================================================

-- Journal des migrations appliquées : une ligne par version, écrite par Migrate.
-- Une base antérieure au versionnement se remplit toute seule au premier
-- démarrage (les migrations historiques sont rejouées à vide puis enregistrées).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT NOT NULL PRIMARY KEY,
    name VARCHAR(191) NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL DEFAULT '',
    role VARCHAR(50) NOT NULL DEFAULT 'Viewer',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    github_url VARCHAR(500) NOT NULL DEFAULT '',
    -- Compteur de révocation de session : l'incrémenter invalide tous les
    -- cookies émis avant (changement de mot de passe, reset MFA, déconnexion
    -- globale). Voir AuthMiddleware.
    session_epoch INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS apps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    external_url VARCHAR(255) NOT NULL,
    icon_url MEDIUMTEXT,
    category VARCHAR(50) DEFAULT 'General',
    health_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    health_response_ms INT NOT NULL DEFAULT 0,
    health_last_check DATETIME NULL,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE,
    position INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table de cache pour les IPs des VMs Proxmox
CREATE TABLE IF NOT EXISTS vm_cache (
    vmid INT PRIMARY KEY,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    vm_type VARCHAR(10),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    key_type VARCHAR(20) DEFAULT 'RSA',
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    fingerprint VARCHAR(100),
    associated_vms TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ssh_host_keys (
    ip VARCHAR(255) PRIMARY KEY,
    host_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SOAR Configuration
CREATE TABLE IF NOT EXISTS soar_config (
    id INT PRIMARY KEY DEFAULT 1,
    alert_status BOOLEAN DEFAULT TRUE,
    alert_ssh BOOLEAN DEFAULT TRUE,
    alert_sudo BOOLEAN DEFAULT TRUE,
    alert_fim BOOLEAN DEFAULT TRUE,
    alert_packages BOOLEAN DEFAULT TRUE
);

INSERT IGNORE INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages)
VALUES (1, TRUE, TRUE, TRUE, TRUE, TRUE);

CREATE TABLE IF NOT EXISTS soar_state (
    k VARCHAR(64) PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS soar_alert_dedup (
    alert_key VARCHAR(191) PRIMARY KEY,
    seen_at BIGINT NOT NULL,
    INDEX idx_seen_at (seen_at)
);

-- Journal d'audit. idx_created_at porte la lecture antéchronologique et la
-- purge par date (la rétention est appliquée hors de ce fichier).
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    username VARCHAR(255),
    action VARCHAR(255),
    details TEXT,
    ip_address VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS metrics_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cpu INT NOT NULL,
    ram INT NOT NULL,
    storage INT NOT NULL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_recorded_at (recorded_at)
);

CREATE TABLE IF NOT EXISTS favorites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    item_type VARCHAR(20) NOT NULL,
    item_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_fav (user_id, item_type, item_id)
);

-- Planifications Ansible. remote_user est NOT NULL SANS DEFAULT : root SSH est
-- désactivé sur le parc (PermitRootLogin=no), une planification doit donc porter
-- un utilisateur nominatif explicite, avec become=TRUE si sudo est nécessaire.
CREATE TABLE IF NOT EXISTS ansible_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    playbook VARCHAR(255) NOT NULL,
    vmid INT NOT NULL,
    key_id INT NOT NULL,
    interval_minutes INT NOT NULL,
    remote_user VARCHAR(50) NOT NULL,
    become BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    next_run DATETIME NOT NULL,
    last_run DATETIME NULL,
    last_status VARCHAR(20) DEFAULT 'pending',
    last_output TEXT,
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cibles de sauvegarde : une ligne par VMID, quel que soit son type. La clé
-- unique porte sur source_ref seul (et non sur (target_type, source_ref)) pour
-- qu'un même VMID saisi en 'qemu' puis auto-découvert en 'lxc' entre en conflit
-- au lieu de compter double dans les KPI.
CREATE TABLE IF NOT EXISTS backup_targets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(10) NOT NULL DEFAULT 'qemu',
    source_ref VARCHAR(50) NOT NULL,
    storage VARCHAR(100) NOT NULL DEFAULT 'local',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rpo_hours INT NOT NULL DEFAULT 24,
    schedule_cron VARCHAR(100) NOT NULL DEFAULT '',
    retention_count INT NOT NULL DEFAULT 3,
    healthcheck_type VARCHAR(20) NOT NULL DEFAULT 'none',
    healthcheck_target VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_target_source (source_ref)
);

CREATE TABLE IF NOT EXISTS backup_runs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    backup_type VARCHAR(20) NOT NULL DEFAULT 'vzdump',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    archive_path VARCHAR(512) NOT NULL DEFAULT '',
    checksum VARCHAR(128) NOT NULL DEFAULT '',
    source VARCHAR(20) NOT NULL DEFAULT 'manual',
    message TEXT,
    created_by VARCHAR(50),
    upid VARCHAR(255) NOT NULL DEFAULT '',
    destination VARCHAR(20) NOT NULL DEFAULT 'local',
    remote VARCHAR(64) NOT NULL DEFAULT '',
    push_status VARCHAR(20) NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_bruns_target (target_id),
    INDEX idx_bruns_status (status),
    INDEX idx_bruns_created (created_at)
);

-- Ligne unique (id=1) garantie par Migrate : le worker lit la config de rotation
-- sans cas particulier "pas de ligne".
CREATE TABLE IF NOT EXISTS backup_settings (
    id INT PRIMARY KEY DEFAULT 1,
    rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    rotation_hour INT NOT NULL DEFAULT 4,
    auto_verify_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT IGNORE INTO backup_settings (id) VALUES (1);

CREATE TABLE IF NOT EXISTS restore_tests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    run_id INT NULL,
    level VARCHAR(4) NOT NULL DEFAULT 'N1',
    verdict VARCHAR(20) NOT NULL DEFAULT 'pending',
    sandbox_vmid INT NOT NULL DEFAULT 0,
    rto_seconds INT NOT NULL DEFAULT 0,
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    logs TEXT,
    triggered_by VARCHAR(20) NOT NULL DEFAULT 'manual',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rtests_target (target_id),
    INDEX idx_rtests_verdict (verdict),
    INDEX idx_rtests_created (created_at)
);

-- Identifiants d'infrastructure configurés dans l'app (onboarding), une ligne
-- par service. Seul secret_enc est chiffré (AES-256-GCM). L'ABSENCE de ligne est
-- le signal "non configuré" : pas d'INSERT IGNORE ici, volontairement.
CREATE TABLE IF NOT EXISTS connections (
    service        VARCHAR(32)  NOT NULL PRIMARY KEY,
    enabled        TINYINT(1)   NOT NULL DEFAULT 1,
    url            VARCHAR(512) NOT NULL DEFAULT '',
    node           VARCHAR(128) NOT NULL DEFAULT '',
    token_id       VARCHAR(256) NOT NULL DEFAULT '',
    secret_enc     TEXT         NOT NULL,
    extra_json     JSON         NULL,
    configured     TINYINT(1)   NOT NULL DEFAULT 0,
    status         VARCHAR(16)  NOT NULL DEFAULT 'unknown',
    last_tested_at DATETIME     NULL,
    last_error     VARCHAR(512) NOT NULL DEFAULT '',
    source         VARCHAR(8)   NOT NULL DEFAULT 'db',
    updated_by     VARCHAR(128) NOT NULL DEFAULT '',
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
