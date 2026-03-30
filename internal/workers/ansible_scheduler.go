package workers

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"goacloud/internal/services"
)

// StartAnsibleScheduler checks for due ansible schedules every 60 seconds and executes them.
func StartAnsibleScheduler(ctx context.Context, db *sql.DB, sshService *services.SSHService, discord *services.DiscordBot) {
	slog.Info("Starting Ansible Scheduler Worker...")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Ansible Scheduler stopped")
			return
		case <-ticker.C:
			runDueSchedules(db, sshService, discord)
		}
	}
}

func runDueSchedules(db *sql.DB, sshService *services.SSHService, discord *services.DiscordBot) {
	rows, err := db.Query(`SELECT id, playbook, vmid, key_id, interval_minutes
		FROM ansible_schedules WHERE enabled = TRUE AND next_run <= NOW()`)
	if err != nil {
		slog.Error("Ansible scheduler: DB error", "error", err)
		return
	}
	defer rows.Close()

	type job struct {
		ID              int
		Playbook        string
		VMID            int
		KeyID           int
		IntervalMinutes int
	}

	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.ID, &j.Playbook, &j.VMID, &j.KeyID, &j.IntervalMinutes); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}

	for _, j := range jobs {
		go executeScheduledPlaybook(db, sshService, discord, j.ID, j.Playbook, j.VMID, j.KeyID, j.IntervalMinutes)
	}
}

func executeScheduledPlaybook(db *sql.DB, sshService *services.SSHService, discord *services.DiscordBot, scheduleID int, playbook string, vmid int, keyID int, intervalMinutes int) {
	slog.Info("Ansible scheduler: executing", "schedule_id", scheduleID, "playbook", playbook, "vmid", vmid)

	// Get VM name for notifications
	var targetIP, vmName string
	err := db.QueryRow("SELECT ip_address, COALESCE(name,'?') FROM vm_cache WHERE vmid = ?", vmid).Scan(&targetIP, &vmName)
	if err != nil || targetIP == "" || targetIP == "-" {
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", "VM IP not found or not cached")
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", "VM IP not found or not cached")
		return
	}

	// Get SSH key
	sshKey, err := sshService.GetSSHKeyByID(keyID)
	if err != nil {
		msg := fmt.Sprintf("SSH key not found: %v", err)
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", msg)
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", msg)
		return
	}

	// Path traversal protection
	playbookPath := filepath.Join("playbooks", filepath.Clean(playbook))
	absPlaybooks, err1 := filepath.Abs("playbooks")
	absPath, err2 := filepath.Abs(playbookPath)
	if err1 != nil || err2 != nil || !strings.HasPrefix(absPath, absPlaybooks+string(filepath.Separator)) {
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", "Invalid playbook path")
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", "Invalid playbook path")
		return
	}

	// Run playbook
	cmdOut, cleanup, err := services.RunPlaybook(playbookPath, targetIP, sshKey.PrivateKey)
	if err != nil {
		msg := fmt.Sprintf("Execution error: %v", err)
		updateScheduleResult(db, scheduleID, intervalMinutes, "error", msg)
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", msg)
		return
	}
	defer cleanup()

	// Read all output
	var buf bytes.Buffer
	io.Copy(&buf, cmdOut)
	output := buf.String()

	// Determine status from output
	status := "success"
	if strings.Contains(output, "fatal:") || strings.Contains(output, "UNREACHABLE!") {
		status = "error"
	}

	// Truncate output if too long (keep last 4000 chars)
	if len(output) > 4000 {
		output = "...(truncated)\n" + output[len(output)-4000:]
	}

	updateScheduleResult(db, scheduleID, intervalMinutes, status, output)
	notifyAnsibleExecution(discord, playbook, vmName, vmid, status, output)
	slog.Info("Ansible scheduler: done", "schedule_id", scheduleID, "status", status)
}

func notifyAnsibleExecution(discord *services.DiscordBot, playbook, vmName string, vmid int, status, output string) {
	if discord == nil || !discord.IsReady() {
		return
	}
	if err := discord.SendAnsibleAlert(playbook, vmName, vmid, status, output); err != nil {
		slog.Error("Ansible scheduler: Discord notification failed", "error", err)
	}
}

func updateScheduleResult(db *sql.DB, scheduleID int, intervalMinutes int, status string, output string) {
	nextRun := time.Now().Add(time.Duration(intervalMinutes) * time.Minute)
	_, err := db.Exec(`UPDATE ansible_schedules
		SET last_run = NOW(), last_status = ?, last_output = ?, next_run = ?
		WHERE id = ?`, status, output, nextRun, scheduleID)
	if err != nil {
		slog.Error("Ansible scheduler: failed to update result", "error", err, "schedule_id", scheduleID)
	}
}
