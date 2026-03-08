package database

import (
	"database/sql"
	"log/slog"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"goacloud/internal/config"
)

// Connect opens the database connection with retry logic.
func Connect(cfg *config.Config) (*sql.DB, error) {
	mysqlCfg := mysql.Config{
		User:                 cfg.DBUser,
		Passwd:               cfg.DBPass,
		Net:                  "tcp",
		Addr:                 cfg.DBHost,
		DBName:               cfg.DBName,
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	var db *sql.DB
	var err error
	for i := 0; i < 30; i++ {
		db, err = sql.Open("mysql", mysqlCfg.FormatDSN())
		if err == nil {
			err = db.Ping()
			if err == nil {
				break
			}
		}
		slog.Info("Waiting for database...", "attempt", i+1)
		time.Sleep(1 * time.Second)
	}
	return db, err
}

// Migrate runs auto-migrations to ensure all required tables and columns exist.
func Migrate(db *sql.DB) {
	coreTables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS apps (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			description TEXT,
			external_url VARCHAR(255) NOT NULL,
			icon_url VARCHAR(255),
			category VARCHAR(50) DEFAULT 'General',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS vm_cache (
			vmid INT PRIMARY KEY,
			name VARCHAR(255),
			ip_address VARCHAR(45),
			vm_type VARCHAR(10),
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			key_type VARCHAR(20) DEFAULT 'RSA',
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			fingerprint VARCHAR(100),
			associated_vms TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS soar_config (
			id INT PRIMARY KEY DEFAULT 1,
			alert_status BOOLEAN DEFAULT TRUE,
			alert_ssh BOOLEAN DEFAULT TRUE,
			alert_sudo BOOLEAN DEFAULT TRUE,
			alert_fim BOOLEAN DEFAULT TRUE,
			alert_packages BOOLEAN DEFAULT TRUE
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT,
			username VARCHAR(255),
			action VARCHAR(255),
			details TEXT,
			ip_address VARCHAR(255),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_host_keys (
			ip VARCHAR(255) PRIMARY KEY,
			host_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, stmt := range coreTables {
		if _, err := db.Exec(stmt); err != nil {
			slog.Error("DB create table", "error", err)
		}
	}

	// Ensure soar_config default row
	db.Exec(`INSERT IGNORE INTO soar_config (id, alert_status, alert_ssh, alert_sudo, alert_fim, alert_packages) VALUES (1, TRUE, TRUE, TRUE, TRUE, TRUE)`)

	// Column migrations (idempotent — errors from "already exists" are ignored)
	migrations := []string{
		"ALTER TABLE users ADD COLUMN email VARCHAR(255) NOT NULL DEFAULT ''",
		"ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'Viewer'",
		"ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE users ADD COLUMN mfa_secret TEXT",
		"ALTER TABLE users ADD COLUMN github_url VARCHAR(500) NOT NULL DEFAULT ''",
		"ALTER TABLE ssh_keys ADD COLUMN associated_vms TEXT",
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			if !strings.Contains(err.Error(), "Duplicate column") && !strings.Contains(err.Error(), "exists") {
				slog.Info("DB migration (may already exist)", "sql", m, "error", err)
			}
		}
	}
}
