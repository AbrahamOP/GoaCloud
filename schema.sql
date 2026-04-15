CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS apps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    external_url VARCHAR(255) NOT NULL,
    icon_url MEDIUMTEXT,
    category VARCHAR(50) DEFAULT 'General',
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


-- Initial Data (Optional)
-- INSERT INTO apps ...

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
