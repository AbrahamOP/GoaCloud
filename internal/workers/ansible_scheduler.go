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

	"goacore/internal/services"
)

// statusRunning marque une tâche réclamée dont le playbook est en vol. Tant qu'une
// ligne porte ce statut (et que son bail n'a pas expiré), aucun tick ne peut la
// relancer.
const statusRunning = "running"

// scheduleLeaseMargin s'ajoute à la durée maximale d'un playbook pour former le bail
// d'une tâche réclamée. Passé ce bail, la ligne est considérée orpheline (processus
// tué net) et peut être reprise : c'est le filet qui évite qu'un crash bloque une
// planification pour toujours.
const scheduleLeaseMargin = 5 * time.Minute

func scheduleLease() time.Duration {
	return services.PlaybookTimeout() + scheduleLeaseMargin
}

// StartAnsibleScheduler checks for due ansible schedules every 60 seconds and executes them.
//
// discord is a DiscordProvider (the registry): the live bot is re-resolved at the head
// of each tick (in runDueSchedules) and the resulting snapshot is handed to the async
// per-job goroutines. Because the executions run async, the bot MUST be re-read per
// tick — never captured at start — so an in-app Discord hot-reload reaches them.
func StartAnsibleScheduler(ctx context.Context, db *sql.DB, sshService *services.SSHService, discord services.DiscordProvider) {
	slog.Info("Starting Ansible Scheduler Worker...")
	recoverOrphanSchedules(db)
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

// recoverOrphanSchedules remet à plat les tâches restées « running » au démarrage.
// GoaCore est le seul ordonnanceur de sa base : une telle ligne ne peut être que le
// vestige d'un arrêt brutal pendant un playbook. On la libère en la marquant en
// erreur, sans avancer next_run — elle repartira à son heure normale plutôt que de
// se déclencher en masse au boot.
func recoverOrphanSchedules(db *sql.DB) {
	const msg = "Exécution interrompue par un arrêt de GoaCore — relance à la prochaine échéance."
	res, err := db.Exec(`UPDATE ansible_schedules SET last_status = 'error', last_output = ?
		WHERE last_status = ?`, msg, statusRunning)
	if err != nil {
		slog.Error("Ansible scheduler: orphan recovery failed", "error", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		slog.Warn("Ansible scheduler: orphan runs reset at startup", "count", n)
	}
}

// claimSchedule réserve atomiquement une tâche due, sur le modèle de
// l'anti-concurrence des sauvegardes (services/backup.go) : c'est la base qui
// arbitre. Un seul UPDATE peut voir la ligne « due et non réclamée » ; les autres
// obtiennent RowsAffected = 0 et renoncent. Sans ce verrou, un playbook de 8 minutes
// était resélectionné à chaque tick de 60 s — jusqu'à 8 ansible-playbook simultanés
// sur la même machine, avec la même clé, chacun écrivant last_output et notifiant.
//
// La réservation avance next_run d'un intervalle dès le départ (cadence fixe, pas de
// dérive) et pose le statut 'running'. La clause de bail (last_run < staleBefore)
// permet de reprendre une ligne dont le process a disparu sans jamais conclure.
func claimSchedule(db *sql.DB, scheduleID, intervalMinutes int, lease time.Duration) (bool, error) {
	interval := time.Duration(intervalMinutes) * time.Minute
	if interval < time.Minute {
		interval = time.Minute
	}
	now := time.Now()
	res, err := db.Exec(`UPDATE ansible_schedules
		SET last_status = ?, last_run = ?, next_run = ?
		WHERE id = ? AND enabled = TRUE AND next_run <= ?
		  AND (last_status IS NULL OR last_status <> ? OR last_run IS NULL OR last_run < ?)`,
		statusRunning, now, now.Add(interval), scheduleID, now, statusRunning, now.Add(-lease))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func runDueSchedules(db *sql.DB, sshService *services.SSHService, provider services.DiscordProvider) {
	// Snapshot the live bot once per tick; the async jobs below use this snapshot.
	var discord *services.DiscordBot
	if provider != nil {
		discord = provider.Discord()
	}
	rows, err := db.Query(`SELECT id, playbook, vmid, key_id, interval_minutes, remote_user, become
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
		RemoteUser      string
		Become          bool
	}

	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.ID, &j.Playbook, &j.VMID, &j.KeyID, &j.IntervalMinutes, &j.RemoteUser, &j.Become); err != nil {
			continue
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Ansible scheduler: row iteration error", "error", err)
	}

	lease := scheduleLease()
	for _, j := range jobs {
		// La sélection ci-dessus n'est qu'un pré-filtre : seule la réservation fait
		// foi. Une tâche encore en vol (ou réclamée par un autre tick) est ignorée.
		claimed, err := claimSchedule(db, j.ID, j.IntervalMinutes, lease)
		if err != nil {
			slog.Error("Ansible scheduler: claim failed", "error", err, "schedule_id", j.ID)
			continue
		}
		if !claimed {
			slog.Debug("Ansible scheduler: schedule already running, skipped", "schedule_id", j.ID)
			continue
		}
		go executeScheduledPlaybook(db, sshService, discord, j.ID, j.Playbook, j.VMID, j.KeyID, j.RemoteUser, j.Become)
	}
}

// executeScheduledPlaybook exécute une tâche DÉJÀ réservée par claimSchedule. Tous
// ses chemins de sortie repassent par updateScheduleResult : la ligne ne peut donc
// pas rester bloquée en 'running'.
func executeScheduledPlaybook(db *sql.DB, sshService *services.SSHService, discord *services.DiscordBot, scheduleID int, playbook string, vmid int, keyID int, remoteUser string, become bool) {
	slog.Info("Ansible scheduler: executing", "schedule_id", scheduleID, "playbook", playbook, "vmid", vmid)

	// Une panique ici tuerait le serveur ET laisserait la tâche en 'running' jusqu'à
	// expiration du bail : on la convertit en échec propre.
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("panique pendant l'exécution du playbook : %v", r)
			slog.Error("Ansible scheduler: panic recovered", "schedule_id", scheduleID, "error", r)
			updateScheduleResult(db, scheduleID, "error", msg)
			notifyAnsibleExecution(discord, playbook, "?", vmid, "error", msg)
		}
	}()

	// Guard legacy/invalid rows: root SSH is disabled fleet-wide (PermitRootLogin=no),
	// so a schedule still pinned to 'root' (or any invalid user) would fail UNREACHABLE
	// silently. Surface it as a clear error instead, prompting the admin to recreate the
	// schedule with a non-root user (+ become for escalation).
	if remoteUser == "root" {
		const msg = "remote_user 'root' is rejected: root SSH login is disabled (PermitRootLogin=no). Recreate this schedule with a non-root user and enable 'become' (sudo) for privilege escalation."
		updateScheduleResult(db, scheduleID, "error", msg)
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", msg)
		return
	}
	if !services.ValidRemoteUser(remoteUser) {
		const msg = "invalid remote_user on schedule — recreate it with a valid non-root SSH user."
		updateScheduleResult(db, scheduleID, "error", msg)
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", msg)
		return
	}

	// Get VM name for notifications
	var targetIP, vmName string
	err := db.QueryRow("SELECT ip_address, COALESCE(name,'?') FROM vm_cache WHERE vmid = ?", vmid).Scan(&targetIP, &vmName)
	if err != nil || targetIP == "" || targetIP == "-" {
		updateScheduleResult(db, scheduleID, "error", "VM IP not found or not cached")
		notifyAnsibleExecution(discord, playbook, "?", vmid, "error", "VM IP not found or not cached")
		return
	}

	// Get SSH key
	sshKey, err := sshService.GetSSHKeyByID(keyID)
	if err != nil {
		msg := fmt.Sprintf("SSH key not found: %v", err)
		updateScheduleResult(db, scheduleID, "error", msg)
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", msg)
		return
	}

	// Path traversal protection
	playbookPath := filepath.Join("playbooks", filepath.Clean(playbook))
	absPlaybooks, err1 := filepath.Abs("playbooks")
	absPath, err2 := filepath.Abs(playbookPath)
	if err1 != nil || err2 != nil || !strings.HasPrefix(absPath, absPlaybooks+string(filepath.Separator)) {
		updateScheduleResult(db, scheduleID, "error", "Invalid playbook path")
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", "Invalid playbook path")
		return
	}

	// Run playbook. Le magasin de clés hôtes est passé explicitement : l'exécution
	// est refusée si l'identité de la cible n'est pas déjà épinglée (ssh_host_keys).
	cmdOut, cleanup, err := services.RunPlaybook(playbookPath, targetIP, sshKey.PrivateKey, remoteUser, become,
		services.WithHostKeyStore(sshService))
	if err != nil {
		msg := fmt.Sprintf("Execution error: %v", err)
		updateScheduleResult(db, scheduleID, "error", msg)
		notifyAnsibleExecution(discord, playbook, vmName, vmid, "error", msg)
		return
	}
	defer cleanup()

	// Read all output
	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, cmdOut)
	output := buf.String()

	// Statut basé d'abord sur le CODE DE SORTIE réel d'ansible-playbook (cleanup attend
	// la fin du process et le renvoie), puis sur les marqueurs de sortie en complément.
	// Un échec avec exit≠0 sans "fatal:"/"UNREACHABLE!" (erreur de syntaxe → "ERROR!",
	// process tué, etc.) n'est ainsi plus rapporté comme un succès. cleanup() est
	// idempotent : le defer ci-dessus reste le filet de sécurité (suppression de clé).
	exitErr := cleanup()
	status := "success"
	if copyErr != nil {
		status = "error"
		output += fmt.Sprintf("\n[scheduler] error reading playbook output: %v", copyErr)
	} else if exitErr != nil {
		status = "error"
		output += fmt.Sprintf("\n[scheduler] ansible-playbook a échoué (code de sortie) : %v", exitErr)
	} else if strings.Contains(output, "fatal:") || strings.Contains(output, "UNREACHABLE!") {
		status = "error"
	}

	// Truncate output if too long (keep last 4000 chars)
	if len(output) > 4000 {
		output = "...(truncated)\n" + output[len(output)-4000:]
	}

	updateScheduleResult(db, scheduleID, status, output)
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

// updateScheduleResult conclut une exécution et LIBÈRE la réservation (le statut
// quitte 'running'). next_run n'est délibérément pas touché : il a été positionné par
// claimSchedule au départ de l'exécution, ce qui donne une cadence fixe indépendante
// de la durée du playbook.
func updateScheduleResult(db *sql.DB, scheduleID int, status string, output string) {
	_, err := db.Exec(`UPDATE ansible_schedules
		SET last_run = NOW(), last_status = ?, last_output = ?
		WHERE id = ?`, status, output, scheduleID)
	if err != nil {
		slog.Error("Ansible scheduler: failed to update result", "error", err, "schedule_id", scheduleID)
	}
}
