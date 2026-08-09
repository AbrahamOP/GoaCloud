package services

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"goacore/internal/config"
	"goacore/internal/models"
)

// Restore-test tuning constants.
//
// The isolation VLAN and the restore storage are NO LONGER constants: they are
// resolved per-run from the live Proxmox snapshot (pm.SandboxVlanTag() and
// resolveRestoreStorage) so a PME can point the restore test at its own storage /
// isolation VLAN without a code change. The disk guards keep their compiled
// defaults below but are overridable via env (see BackupService.diskDataPctCeiling
// / minLocalAvailBytes, seeded in NewBackupService).
const (
	restoreTaskTimeout        = 20 * time.Minute // max wait for a restore task
	restorePollInterval       = 5 * time.Second
	bootSettleDelay           = 25 * time.Second       // grace period after "running" before probing
	bootWaitTimeout           = 3 * time.Minute        // max wait for the guest to reach "running"
	defaultDiskDataPctCeiling = 85.0                   // refuse N2/N3 above this thin-pool data usage
	defaultMinLocalAvailBytes = 5 * 1024 * 1024 * 1024 // 5 GiB headroom required on local storage

	// Bounds of the free-sandbox-VMID scan. The scan dials the read-only helper over
	// SSH once per candidate; with a stopped helper each dial burns its own timeout, so
	// an unbounded scan of the whole [9500,9599] range could block a test for tens of
	// minutes before admitting the obvious ("the channel is down"). Whichever bound is
	// hit first aborts the scan with an explicit error.
	sandboxScanBudget    = 90 * time.Second // max total wall time spent scanning
	sandboxScanMaxErrors = 5                // consecutive probe failures ⇒ transport is down
)

// ErrRestoreTestInProgress is returned when a restore test is already running for a target.
var ErrRestoreTestInProgress = fmt.Errorf("a restore test is already running for this target")

// ErrChannelUnavailable is returned when the read-only Proxmox helper channel is
// not configured but a level needs it.
var ErrChannelUnavailable = fmt.Errorf("the Proxmox restore-test channel is not configured")

// RunRestoreTest records a restore_tests row (verdict=running), then launches a
// recover-guarded goroutine that performs the level's verification and historises
// the verdict. It returns the new test ID immediately. Only one test may run per
// target at a time.
func (s *BackupService) RunRestoreTest(targetID int, level, triggeredBy string) (int, error) {
	level = normalizeLevel(level)
	if triggeredBy == "" {
		triggeredBy = "manual"
	}

	// Load the target.
	t, err := s.loadTarget(targetID)
	if err != nil {
		return 0, fmt.Errorf("target not found: %w", err)
	}
	vmid, convErr := strconv.Atoi(t.SourceRef)
	if convErr != nil || vmid <= 0 {
		return 0, fmt.Errorf("target %d has no valid VMID (%q)", targetID, t.SourceRef)
	}

	// Anti-concurrency: claim the slot before inserting the row.
	if !s.claimTestSlot(targetID) {
		return 0, ErrRestoreTestInProgress
	}

	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO restore_tests (target_id, level, verdict, started_at, triggered_by, logs)
		 VALUES (?, ?, 'running', ?, ?, '')`,
		targetID, level, now, triggeredBy)
	if err != nil {
		s.releaseTestSlot(targetID)
		return 0, fmt.Errorf("insert restore_test: %w", err)
	}
	testID64, _ := res.LastInsertId()
	testID := int(testID64)

	// The whole restore orchestration (restore → boot → healthcheck → DESTROY) belongs
	// to the application lifecycle: it is launched inside the service's task group so a
	// shutdown drains it instead of abandoning a booted clone of a production guest on
	// the hypervisor. A refusal here means the service is already draining.
	if !s.startTask(func() { s.runRestoreTestAsync(testID, t, vmid, level) }) {
		s.releaseTestSlot(targetID)
		s.finishTest(testID, "failed", 0, 0, "Test non lancé : arrêt du service en cours")
		return 0, ErrServiceShuttingDown
	}
	return testID, nil
}

// runRestoreTestAsync executes the level logic. It is recover-guarded so it can
// never crash the process, and it always releases the per-target slot.
func (s *BackupService) runRestoreTestAsync(testID int, t models.BackupTarget, vmid int, level string) {
	defer s.releaseTestSlot(t.ID)
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("restore-test: panic recovered", "test_id", testID, "panic", rec)
			s.finishTest(testID, "failed", 0, 0, fmt.Sprintf("panic interne: %v", rec))
			s.notifyRestoreTest(t.Name, 0, level, "failed", fmt.Sprintf("panic interne: %v", rec))
		}
	}()

	logs := &strings.Builder{}
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		logs.WriteString(time.Now().Format("15:04:05") + " " + line + "\n")
		slog.Info("restore-test", "test_id", testID, "msg", line)
	}

	pveType := "qemu"
	if t.TargetType == "lxc" {
		pveType = "lxc"
	}

	switch level {
	case "N1":
		s.runLevelN1(testID, t, vmid, logs, logf)
	case "N2":
		s.runLevelN2N3(testID, t, vmid, pveType, "N2", logs, logf)
	default: // N3
		s.runLevelN2N3(testID, t, vmid, pveType, "N3", logs, logf)
	}
}

// runLevelN1 verifies off-site archive integrity via the channel (no restore).
func (s *BackupService) runLevelN1(testID int, t models.BackupTarget, vmid int, logs *strings.Builder, logf func(string, ...any)) {
	logf("N1 — vérification d'intégrité off-site (cryptcheck) pour VMID %d", vmid)
	// Resolve the LIVE channel once for the whole N1 op (hot-reload aware, coherent
	// for the single logical operation).
	channel := s.liveChannel()
	if !channel.Configured() {
		logf("canal Proxmox non configuré — test impossible")
		s.finishTest(testID, "failed", 0, 0, logs.String())
		s.notifyRestoreTest(t.Name, 0, "N1", "failed", "canal non configuré")
		return
	}
	// Resolve the off-site remote for THIS target. In a multi-remote deployment each
	// target may have been pushed to a different remote, so the cryptcheck must run
	// against the remote the target was actually pushed to — deriving it from the
	// connection-global attribute would cryptcheck the wrong remote and report a silent
	// false negative. Precedence: the remote of the target's latest off-site run >
	// connection attribute (DB extra_json > env > hard default gcrypt). The helper
	// re-validates whatever we pass host-side against `rclone listremotes`.
	remote := s.latestPushedRemote(t.ID)
	if remote == "" {
		remote = s.cfgStore.ProxmoxSnapshot().CryptCheckRemote()
		logf("remote off-site: %s (attribut connexion — aucun push enregistré pour cette cible)", remote)
	} else {
		logf("remote off-site: %s (dernier push de la cible)", remote)
	}
	ok, detail, err := channel.Cryptcheck(vmid, remote)
	if err != nil {
		logf("échec cryptcheck: %v", err)
		s.finishTest(testID, "failed", 0, 0, logs.String())
		s.notifyRestoreTest(t.Name, 0, "N1", "failed", err.Error())
		return
	}
	logf("cryptcheck: %s", detail)
	verdict := "failed"
	if ok {
		verdict = "passed"
	}
	s.finishTest(testID, verdict, 0, 0, logs.String())
	s.notifyRestoreTest(t.Name, 0, "N1", verdict, detail)
}

// runLevelN2N3 restores the latest archive into an isolated sandbox guest, boots
// it, optionally runs a healthcheck (N3), measures RTO, and ALWAYS destroys the
// sandbox afterwards (deferred). level is "N2" or "N3".
func (s *BackupService) runLevelN2N3(testID int, t models.BackupTarget, vmid int, pveType, level string, logs *strings.Builder, logf func(string, ...any)) {
	// One coherent Proxmox snapshot for the whole restore: this is a single logical
	// operation (restore → boot → healthcheck → destroy), so all its API calls must
	// target the SAME Proxmox even if a hot-reload lands mid-run. The destroy defer
	// closes over this snapshot deliberately so cleanup hits the same host the
	// restore wrote to.
	pm := s.cfgStore.ProxmoxSnapshot()
	// Resolve the sandbox isolation parameters ONCE from this coherent snapshot
	// (single resolution order: DB extra_json > env > literal, all already merged into
	// pm by the config layer). vlanTag floors a 0/empty back to the hard 99; the
	// sandbox bridge is the DEDICATED pm.SandboxBridge (its own extra_json key / env),
	// flooring an empty value to the hard vmbr1 fallback — NEVER pm.Bridge (the
	// creation bridge, often vmbr0=prod, which may not trunk the isolation VLAN). The
	// (bridge,vlan) pair is COUPLED for isolation correctness and never freely
	// auto-detected. The restore storage is resolved later (needs the elected archive's
	// pveType).
	vlanTag := pm.SandboxVlanTag()
	sandboxBridge := pm.SandboxBridgeName()

	// HONNÊTETÉ DU VERDICT (le seul argument différenciant du produit). Un verdict N3
	// affirme « l'application répond ». Sans healthcheck configuré sur la cible — et
	// c'est le cas NOMINAL des cibles auto-découvertes (healthcheck_type='none') — rien
	// dans ce run ne peut le prouver : seul le redémarrage l'est. On rétrograde donc le
	// niveau ENREGISTRÉ (et affiché) en N2 avant même de restaurer, plutôt que d'échouer,
	// pour que le test reste utile ; le libellé dit exactement ce qui a été prouvé.
	demoted := false
	if provable := provenLevel(level, t.HealthcheckType, t.HealthcheckTarget); provable != level {
		logf("N3 demandé mais aucun healthcheck n'est configuré sur cette cible : impossible de prouver que l'application répond. Test enregistré en %s (redémarrage prouvé, application non vérifiée). Configurez un healthcheck (service ou port) pour un vrai N3.", provable)
		level = provable
		demoted = true
		s.setTestLevel(testID, level)
	}

	fail := func(detail string) {
		s.finishTest(testID, "failed", 0, 0, logs.String())
		s.notifyRestoreTest(t.Name, 0, level, "failed", detail)
	}

	// Resolve the LIVE channel ONCE for the whole restore op (restore → boot →
	// healthcheck → destroy is one logical operation; a hot-reload mid-run must not
	// swap the channel underneath it). Hot-reload aware, coherent for this run.
	channel := s.liveChannel()
	if !channel.Configured() {
		logf("canal Proxmox non configuré — test impossible")
		fail("canal non configuré")
		return
	}

	// 1. Disk pre-flight guard. Thresholds come from the BackupService (env-overridable,
	// compiled defaults). The thin-pool ceiling guard fires ONLY on a usable lvmthin
	// reading (DiskInfo.HasThinPoolCeiling): a backend without a thin_data_pct (ZFS/dir
	// → 0 from the helper, or an old helper with no backend field) must NOT be read as
	// "0% used ⇒ always pass" — the universal avail floor still applies below.
	disk, err := channel.DiskFree()
	if err != nil {
		logf("échec contrôle disque: %v", err)
		fail(err.Error())
		return
	}
	logf("disque: backend=%s thin_data=%.1f%% local_avail=%s avail_probe=%s", disk.Backend, disk.ThinDataPct, humanSize(disk.LocalAvailBytes), disk.AvailProbe)
	// Fail-SAFE on a totally blind sonde: if there is neither a usable thin-pool ceiling
	// nor a usable avail floor (df errored, or returned 0 on a non-lvmthin backend), NO
	// disk guard is effective. A destructive N2/N3 restore must NOT proceed unprotected —
	// refuse rather than fail-open (the Go counterpart of the helper's lvs/df fail-soft).
	if disk.IsBlindProbe() {
		logf("garde-fou disque: sonde aveugle (backend=%s avail_probe=%s local_avail=%s) — aucune garde disque effective, annulation",
			disk.Backend, disk.AvailProbe, humanSize(disk.LocalAvailBytes))
		slog.Warn("restore-test: disk probe blind, refusing destructive restore",
			"test_id", testID, "backend", disk.Backend, "avail_probe", disk.AvailProbe, "local_avail", disk.LocalAvailBytes)
		fail("sonde disque aveugle (aucune garde disponible) — restauration refusée par sûreté")
		return
	}
	if disk.HasThinPoolCeiling() && disk.ThinDataPct > s.diskDataPctCeiling {
		logf("garde-fou disque: thin_data %.1f%% > %.1f%% — annulation", disk.ThinDataPct, s.diskDataPctCeiling)
		fail(fmt.Sprintf("disque saturé (thin_data %.1f%%)", disk.ThinDataPct))
		return
	}
	if disk.LocalAvailBytes > 0 && disk.LocalAvailBytes < s.minLocalAvailBytes {
		logf("garde-fou disque: local_avail %s < %s — annulation", humanSize(disk.LocalAvailBytes), humanSize(s.minLocalAvailBytes))
		fail(fmt.Sprintf("espace insuffisant (%s disponibles)", humanSize(disk.LocalAvailBytes)))
		return
	}

	// 2. Pick a free sandbox VMID via Ping (status == "absent"), using the channel
	// resolved at the head of this op.
	sandboxVMID, err := s.pickFreeSandboxVMID(channel.Ping, logf)
	if err != nil {
		logf("aucun VMID sandbox libre: %v", err)
		fail(err.Error())
		return
	}
	logf("sandbox VMID retenu: %d", sandboxVMID)

	// 3. Find the latest archive volid for the target.
	archive, archiveType, archiveVMID, ok := s.latestArchiveVolID(vmid, t.Storage)
	if !ok {
		logf("aucune archive trouvée pour VMID %d", vmid)
		fail("aucune archive disponible")
		return
	}
	// M1 — defense in depth: the elected archive MUST belong to the target VMID.
	// latestArchiveVolID already filters by VMID, but a bug, a storage listing
	// quirk, or a future refactor must never let us restore an archive of another
	// guest into the sandbox. Abort the test rather than restore an incoherent
	// archive.
	if archiveVMID != vmid {
		logf("INCOHÉRENCE: archive élue VMID %d ≠ cible VMID %d — test avorté", archiveVMID, vmid)
		slog.Error("restore-test: archive/vmid mismatch", "test_id", testID, "archive_vmid", archiveVMID, "target_vmid", vmid)
		fail(fmt.Sprintf("archive incohérente (VMID %d ≠ %d)", archiveVMID, vmid))
		return
	}
	if archiveType != "" {
		pveType = archiveType
	}
	logf("archive: %s (type %s)", archive, pveType)
	// PREUVE AUDITABLE : on rattache le test à la sauvegarde effectivement restaurée
	// (restore_tests.run_id → backup_runs.archive_path), sinon « la restauration a
	// réussi » ne dit pas DE QUOI. Best-effort : une archive produite hors GoaCore n'a
	// pas de run associé, le volid reste alors tracé dans les logs du test.
	s.linkTestToArchive(testID, t.ID, archive)

	// Resolve the restore storage now that the elected archive's pveType is known
	// (qemu→images, lxc→rootdir), using the same snapshot pm captured above so the
	// whole op stays coherent under a hot-reload.
	restoreStorage := s.proxmox.resolveRestoreStorage(pm, pveType)
	logf("storage de restauration: %s", restoreStorage)

	// Persist the sandbox VMID early so a crash mid-test still records which slot
	// was used (and the defer below guarantees its destruction regardless).
	s.setTestSandbox(testID, sandboxVMID)

	// 4. GUARANTEED cleanup: destroy the sandbox no matter what happens next, and
	// ALWAYS release the in-process VMID reservation so the slot can be reused.
	defer func() {
		defer s.releaseSandboxVMID(sandboxVMID)
		logf("nettoyage: destruction du sandbox %d", sandboxVMID)
		upid, derr := s.proxmox.DestroyGuest(pm.URL, pm.Node, pm.TokenID,
			pm.TokenSecret, pveType, sandboxVMID)
		if derr != nil {
			logf("ATTENTION: échec destruction sandbox %d: %v", sandboxVMID, derr)
			slog.Error("restore-test: sandbox destroy failed", "test_id", testID, "vmid", sandboxVMID, "error", derr)
			s.notifyZombieSandbox(sandboxVMID, derr)
			return
		}
		if upid != "" {
			if _, werr := s.proxmox.waitForTask(pm.URL, pm.Node, pm.TokenID,
				pm.TokenSecret, upid, 5*time.Minute, restorePollInterval); werr != nil {
				logf("destruction sandbox %d: %v", sandboxVMID, werr)
				s.notifyZombieSandbox(sandboxVMID, werr)
			}
		}
	}()

	// 5. Restore into the sandbox (RTO clock starts here).
	rtoStart := time.Now()
	logf("restauration de l'archive vers le sandbox %d…", sandboxVMID)
	upid, err := s.proxmox.RestoreBackup(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, pveType, archive, sandboxVMID, restoreStorage)
	if err != nil {
		logf("échec lancement restauration: %v", err)
		fail(err.Error())
		return
	}
	exit, err := s.proxmox.waitForTask(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, upid, restoreTaskTimeout, restorePollInterval)
	if err != nil {
		logf("restauration en échec: %v", err)
		fail(err.Error())
		return
	}
	if exit != "OK" {
		logf("restauration terminée avec un statut non-OK: %s", exit)
		fail("restauration: " + exit)
		return
	}
	logf("restauration terminée (OK)")

	// 6. Force the sandbox onto the isolation VLAN + sandbox bridge BEFORE starting
	// it (the resolved pair, coupled for isolation correctness).
	if err := s.proxmox.SetGuestNetworkVlan(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, pveType, sandboxVMID, vlanTag, sandboxBridge); err != nil {
		logf("échec isolation réseau VLAN %d (bridge %s): %v", vlanTag, sandboxBridge, err)
		fail("isolation réseau: " + err.Error())
		return
	}
	logf("réseau forcé sur VLAN %d (bridge %s)", vlanTag, sandboxBridge)

	// 7. Start the sandbox and wait until it is running. Routed through
	// sandboxPowerAction so the isSandboxVMID guard is enforced INSIDE the restore
	// engine (defense in depth), like restore/network/destroy — PowerAction itself
	// stays generic for the dashboard handler.
	if err := s.sandboxPowerAction(pm, pveType, sandboxVMID, "start"); err != nil {
		logf("échec démarrage sandbox: %v", err)
		fail("démarrage: " + err.Error())
		return
	}
	if err := s.waitSandboxRunning(channel.Ping, sandboxVMID, logf); err != nil {
		logf("le sandbox n'a pas démarré: %v", err)
		fail(err.Error())
		return
	}
	rto := int(time.Since(rtoStart).Seconds())
	logf("sandbox démarré (running) — RTO=%ds", rto)

	// Boot grace period before any healthcheck.
	time.Sleep(bootSettleDelay)

	// 8. N3 only: in-guest healthcheck via the channel. A level still at N3 here
	// GUARANTEES a healthcheck is configured (otherwise it was demoted to N2 above),
	// so this branch can never end on an unproven "passed".
	if level == "N3" {
		kind := "service"
		if t.HealthcheckType == "port" {
			kind = "port"
		}
		ok, detail, herr := channel.Healthcheck(sandboxVMID, pveType, kind, t.HealthcheckTarget)
		if herr != nil {
			logf("échec healthcheck: %v", herr)
			s.finishTest(testID, "failed", rto, sandboxVMID, logs.String())
			s.notifyRestoreTest(t.Name, sandboxVMID, level, "failed", herr.Error())
			return
		}
		logf("healthcheck (%s %s): %s", kind, t.HealthcheckTarget, detail)
		if !ok {
			s.finishTest(testID, "failed", rto, sandboxVMID, logs.String())
			s.notifyRestoreTest(t.Name, sandboxVMID, level, "failed", "healthcheck: "+detail)
			return
		}
	}

	verdictDetail := fmt.Sprintf("RTO %ds", rto)
	if demoted {
		verdictDetail += " — redémarrage prouvé, application non vérifiée (aucun healthcheck configuré)"
	}
	logf("verdict: PASSED (%s)", level)
	s.finishTest(testID, "passed", rto, sandboxVMID, logs.String())
	s.notifyRestoreTest(t.Name, sandboxVMID, level, "passed", verdictDetail)
}

// provenLevel returns the level a run can actually PROVE for a target: N3 claims
// "the application answers", which is only provable when the target declares a usable
// in-guest healthcheck. Without one, an N3 request is downgraded to N2 ("restored and
// booted"). N1/N2 are returned unchanged. Pure and table-testable — it is the single
// place where the product decides what a verdict is allowed to claim.
func provenLevel(requested, healthcheckType, healthcheckTarget string) string {
	if requested != "N3" {
		return requested
	}
	if !hasHealthcheck(healthcheckType, healthcheckTarget) {
		return "N2"
	}
	return "N3"
}

// hasHealthcheck reports whether a target declares a usable in-guest healthcheck.
// Auto-discovered targets carry healthcheck_type='none' (or empty) with no target, so
// this returns false for them — the nominal case the N3 verdict must not lie about.
func hasHealthcheck(healthcheckType, healthcheckTarget string) bool {
	t := strings.ToLower(strings.TrimSpace(healthcheckType))
	if t == "" || t == "none" {
		return false
	}
	return strings.TrimSpace(healthcheckTarget) != ""
}

// pickFreeSandboxVMID scans the sandbox range for a VMID that is both ABSENT on
// Proxmox (Ping) AND not already reserved in-process (sandboxInUse), and reserves
// it ATOMICALLY before returning it. This closes the C2 race: two restore tests
// running concurrently on different targets can NEVER be handed the same VMID, so
// they can never restore-overwrite each other's sandbox (even with force=1).
//
// Ping performs a network round-trip; to keep that off the lock we do a two-phase
// pass: probe each candidate's Proxmox status WITHOUT the lock, then, holding the
// lock, re-check it isn't reserved and claim it atomically. The reservation must be
// released later via releaseSandboxVMID (the destroy defer does this).
//
// The scan is BOUNDED in time and in consecutive failures (sandboxScanBudget /
// sandboxScanMaxErrors): a stopped helper used to cost one SSH dial timeout per
// candidate, i.e. up to ~25 minutes of a test sitting on "running" before failing.
func (s *BackupService) pickFreeSandboxVMID(pingFn func(int) (string, error), logf func(string, ...any)) (int, error) {
	return s.pickFreeSandboxVMIDWith(pingFn, logf)
}

// pickFreeSandboxVMIDWith is the testable core of pickFreeSandboxVMID: it takes the
// Proxmox status probe as a function so the scan/atomic-reservation logic can be
// exercised without a live channel. ping reports "absent"/"running"/"stopped" or an
// error for a single VMID. It applies the production bounds; pickFreeSandboxVMIDBounded
// takes them explicitly so a test can exercise them without waiting for real timeouts.
func (s *BackupService) pickFreeSandboxVMIDWith(ping func(int) (string, error), logf func(string, ...any)) (int, error) {
	return s.pickFreeSandboxVMIDBounded(ping, logf, time.Now().Add(sandboxScanBudget), sandboxScanMaxErrors)
}

// pickFreeSandboxVMIDBounded is pickFreeSandboxVMIDWith with explicit bounds.
// deadline caps the TOTAL wall time of the scan; maxConsecErrors aborts as soon as
// that many probes fail in a row (the probe transport is down — continuing would only
// burn one timeout per remaining candidate). A probe failure is still tolerated in
// isolation: the counter resets on the next successful probe, so a single flaky slot
// never aborts the scan. Both aborts return an explicit error rather than the generic
// "no free VMID", so the operator sees the real cause.
func (s *BackupService) pickFreeSandboxVMIDBounded(ping func(int) (string, error), logf func(string, ...any), deadline time.Time, maxConsecErrors int) (int, error) {
	consecErrors := 0
	for vmid := sandboxVMIDMin; vmid <= sandboxVMIDMax; vmid++ {
		// Fast skip: if already reserved in-process, don't even Ping it.
		s.testMu.Lock()
		reserved := s.sandboxInUse[vmid]
		s.testMu.Unlock()
		if reserved {
			continue
		}

		if !time.Now().Before(deadline) {
			return 0, fmt.Errorf("recherche d'un VMID sandbox libre abandonnée: délai imparti dépassé (arrêt au candidat %d)", vmid)
		}

		// Probe Proxmox status off the lock (network call).
		status, err := ping(vmid)
		if err != nil {
			// A transient error on one slot shouldn't abort the whole scan, but
			// log it; keep trying the next slots — until the transport is clearly
			// down (maxConsecErrors in a row).
			logf("ping %d: %v", vmid, err)
			consecErrors++
			if maxConsecErrors > 0 && consecErrors >= maxConsecErrors {
				return 0, fmt.Errorf("canal Proxmox injoignable: %d sondes de VMID sandbox en échec d'affilée (dernière erreur: %v)",
					consecErrors, err)
			}
			continue
		}
		consecErrors = 0
		if status != "absent" {
			continue
		}

		// Atomically re-check and claim under the lock: a concurrent test may have
		// reserved this same slot between our Ping and now.
		s.testMu.Lock()
		if s.sandboxInUse[vmid] {
			s.testMu.Unlock()
			continue
		}
		if s.sandboxInUse == nil {
			s.sandboxInUse = make(map[int]bool)
		}
		s.sandboxInUse[vmid] = true
		s.testMu.Unlock()
		return vmid, nil
	}
	return 0, fmt.Errorf("aucun VMID sandbox libre dans [%d,%d]", sandboxVMIDMin, sandboxVMIDMax)
}

// sandboxPowerAction is the restore engine's guarded wrapper around the generic
// ProxmoxService.PowerAction: it REFUSES (no API call) any VMID outside the sandbox
// range, then forwards to PowerAction. PowerAction is dual-use (the dashboard power
// handler also calls it) so it stays generic; this wrapper carries the sandbox
// invariant for the restore path, exactly like RestoreBackup/SetGuestNetworkVlan/
// DestroyGuest do internally — so a future refactor that powers a different VMID from
// the restore engine is caught here rather than silently acting on a prod guest.
func (s *BackupService) sandboxPowerAction(pm config.ProxmoxConn, pveType string, vmid int, action string) error {
	if !isSandboxVMID(vmid) {
		return errNotSandbox("power", vmid)
	}
	return s.proxmox.PowerAction(pm.URL, pm.Node, pm.TokenID, pm.TokenSecret,
		pveType, strconv.Itoa(vmid), action)
}

// releaseSandboxVMID frees an atomically-reserved sandbox VMID. It is idempotent
// and safe to call from the destroy defer regardless of how the test ended.
func (s *BackupService) releaseSandboxVMID(vmid int) {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	delete(s.sandboxInUse, vmid)
}

// waitSandboxRunning polls the channel until the sandbox reports "running". pingFn is
// the LIVE channel's Ping resolved at the head of the restore op, passed in so the
// whole run uses one coherent channel even across a mid-run hot-reload.
func (s *BackupService) waitSandboxRunning(pingFn func(int) (string, error), vmid int, logf func(string, ...any)) error {
	deadline := time.Now().Add(bootWaitTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(restorePollInterval)
		status, err := pingFn(vmid)
		if err != nil {
			logf("ping %d (attente boot): %v", vmid, err)
			continue
		}
		if status == "running" {
			return nil
		}
	}
	return fmt.Errorf("timeout: le sandbox %d n'a pas atteint l'état running", vmid)
}

// latestArchiveVolID returns the most recent vzdump volid for vmid, its type, and
// the VMID actually carried by the elected archive entry (returned so the caller
// can assert it matches the requested vmid — see M1).
func (s *BackupService) latestArchiveVolID(vmid int, storage string) (string, string, int, bool) {
	pm := s.cfgStore.ProxmoxSnapshot()
	if storage == "" {
		storage = s.defaultBackupStorage
	}
	entries, err := s.proxmox.ListBackups(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, storage)
	if err != nil {
		slog.Error("restore-test: list backups", "vmid", vmid, "error", err)
		return "", "", 0, false
	}
	var best models.BackupEntry
	found := false
	for _, e := range entries {
		if e.VMID != vmid {
			continue
		}
		if !found || e.CTime.After(best.CTime) {
			best = e
			found = true
		}
	}
	if !found {
		return "", "", 0, false
	}
	return best.VolID, best.Type, best.VMID, true
}

// latestPushedRemote returns the rclone remote of the target's most recent off-site
// backup run, or "" when none exists. It is the per-target source for the N1
// cryptcheck remote so a multi-remote deployment checks each target against the
// remote it was actually pushed to (not a single connection-global remote). It
// prefers a run whose push succeeded (push_status='ok'), falling back to the latest
// run that merely carries a non-empty remote, so a freshly-pushed-but-unverified
// target still cryptchecks the right place. Best-effort: any DB error yields "" and
// the caller falls back to the connection attribute.
func (s *BackupService) latestPushedRemote(targetID int) string {
	if s.db == nil {
		return ""
	}
	var remote sql.NullString
	err := s.db.QueryRow(
		`SELECT remote FROM backup_runs
		 WHERE target_id = ? AND remote IS NOT NULL AND remote <> ''
		 ORDER BY (push_status = 'ok') DESC, id DESC
		 LIMIT 1`, targetID).Scan(&remote)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("restore-test: latest pushed remote lookup", "target_id", targetID, "error", err)
		}
		return ""
	}
	return remote.String
}

// --- persistence helpers ---

// loadTarget fetches a single backup target by ID.
func (s *BackupService) loadTarget(id int) (models.BackupTarget, error) {
	var t models.BackupTarget
	err := s.db.QueryRow(
		`SELECT id, name, target_type, source_ref, storage, enabled, rpo_hours,
		        retention_count, healthcheck_type, healthcheck_target, created_at
		 FROM backup_targets WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.TargetType, &t.SourceRef, &t.Storage, &t.Enabled,
			&t.RPOHours, &t.RetentionCount, &t.HealthcheckType, &t.HealthcheckTarget, &t.CreatedAt)
	if err != nil {
		return t, err
	}
	t.Name = sanitizeName(t.Name, mustAtoi(t.SourceRef))
	return t, nil
}

// setTestSandbox records the sandbox VMID chosen for a test.
func (s *BackupService) setTestSandbox(testID, vmid int) {
	if _, err := s.db.Exec(`UPDATE restore_tests SET sandbox_vmid = ? WHERE id = ?`, vmid, testID); err != nil {
		slog.Error("restore-test: set sandbox vmid", "test_id", testID, "error", err)
	}
}

// setTestLevel rewrites the level recorded for a test. It is used when the requested
// level cannot be proven (N3 without healthcheck → N2, see provenLevel): the level
// stored in DB — the one the UI and the history show — must always describe what was
// actually verified, never what was asked for.
func (s *BackupService) setTestLevel(testID int, level string) {
	if _, err := s.db.Exec(`UPDATE restore_tests SET level = ? WHERE id = ?`, level, testID); err != nil {
		slog.Error("restore-test: set level", "test_id", testID, "level", level, "error", err)
	}
}

// archiveFileName reduces a Proxmox volid to the bare archive file name
// ("local:backup/vzdump-lxc-110-….tar.zst" → "vzdump-lxc-110-….tar.zst"). The two
// forms coexist in backup_runs.archive_path: a local run records the volid, while an
// off-site push records the file name reported by the helper. Pure.
func archiveFileName(volID string) string {
	if i := strings.LastIndex(volID, "/"); i >= 0 {
		return volID[i+1:]
	}
	if i := strings.LastIndex(volID, ":"); i >= 0 {
		return volID[i+1:]
	}
	return volID
}

// linkTestToArchive records WHICH archive the test actually restored, by resolving the
// backup_runs row that produced it and writing its id into restore_tests.run_id (the
// column existed but was never filled, so the "proof of restorability" did not say what
// had been restored). Matching accepts both forms of archive_path (volid or bare file
// name — see archiveFileName).
//
// Best-effort: an archive created outside GoaCore (a vzdump scheduled on Proxmox
// itself) has no run to point at; the volid then stays traced in the test logs, which
// are persisted with the row.
func (s *BackupService) linkTestToArchive(testID, targetID int, volID string) {
	if s.db == nil || volID == "" {
		return
	}
	var runID int
	err := s.db.QueryRow(
		`SELECT id FROM backup_runs
		 WHERE target_id = ? AND archive_path IN (?, ?)
		 ORDER BY id DESC
		 LIMIT 1`, targetID, volID, archiveFileName(volID)).Scan(&runID)
	if errors.Is(err, sql.ErrNoRows) {
		slog.Info("restore-test: restored archive has no GoaCore run", "test_id", testID, "volid", volID)
		return
	}
	if err != nil {
		slog.Error("restore-test: resolve archive run", "test_id", testID, "volid", volID, "error", err)
		return
	}
	if _, err := s.db.Exec(`UPDATE restore_tests SET run_id = ? WHERE id = ?`, runID, testID); err != nil {
		slog.Error("restore-test: link test to run", "test_id", testID, "run_id", runID, "error", err)
		return
	}
	slog.Info("restore-test: archive under test", "test_id", testID, "run_id", runID, "volid", volID)
}

// finishTest writes the terminal verdict, RTO, sandbox and logs to a test row.
func (s *BackupService) finishTest(testID int, verdict string, rtoSec, sandboxVMID int, logs string) {
	_, err := s.db.Exec(
		`UPDATE restore_tests
		 SET verdict = ?, rto_seconds = ?, sandbox_vmid = ?, completed_at = ?, logs = ?
		 WHERE id = ?`,
		verdict, rtoSec, sandboxVMID, time.Now(), logs, testID)
	if err != nil {
		slog.Error("restore-test: finish test", "test_id", testID, "error", err)
	}
}

// notifyRestoreTest sends a Discord restore-test alert if a bot is configured.
// The network call runs in its own recover-guarded goroutine (nil-safe).
func (s *BackupService) notifyRestoreTest(target string, vmid int, level, verdict, detail string) {
	// Resolve the LIVE bot at emit time so a hot-reload swap reaches this alert.
	discord := s.discordBot()
	if discord == nil || !discord.IsReady() {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("restore-test: panic in Discord notification recovered", "panic", rec)
			}
		}()
		if err := discord.SendRestoreTestAlert(target, vmid, level, verdict, 0, detail); err != nil {
			slog.Error("restore-test: Discord notification failed", "error", err)
		}
	}()
}

// notifyZombieSandbox emits a dedicated Discord alert when a sandbox guest could
// not be destroyed (leaked). The network call runs in its own recover-guarded
// goroutine (nil-safe).
func (s *BackupService) notifyZombieSandbox(vmid int, cause error) {
	// Resolve the LIVE bot at emit time so a hot-reload swap reaches this alert.
	discord := s.discordBot()
	if discord == nil || !discord.IsReady() {
		return
	}
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("restore-test: panic in zombie Discord notification recovered", "panic", rec)
			}
		}()
		if err := discord.SendZombieSandboxAlert(vmid, detail); err != nil {
			slog.Error("restore-test: zombie Discord notification failed", "error", err)
		}
	}()
}

// RecentTests returns recent restore tests, optionally filtered by target, newest first.
func (s *BackupService) RecentTests(targetID, limit int) ([]models.RestoreTest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	base := `SELECT id, target_id, run_id, level, verdict, sandbox_vmid, rto_seconds,
		started_at, completed_at, logs, triggered_by, created_at
		FROM restore_tests`
	if targetID > 0 {
		rows, err = s.db.Query(base+` WHERE target_id = ? ORDER BY id DESC LIMIT ?`, targetID, limit)
	} else {
		rows, err = s.db.Query(base+` ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tests []models.RestoreTest
	for rows.Next() {
		var rt models.RestoreTest
		var runID sql.NullInt64
		var started, completed sql.NullTime
		var logs sql.NullString
		if err := rows.Scan(&rt.ID, &rt.TargetID, &runID, &rt.Level, &rt.Verdict,
			&rt.SandboxVMID, &rt.RTOSeconds, &started, &completed, &logs,
			&rt.TriggeredBy, &rt.CreatedAt); err != nil {
			slog.Error("restore-test: scan test", "error", err)
			continue
		}
		if runID.Valid {
			v := int(runID.Int64)
			rt.RunID = &v
		}
		if started.Valid {
			rt.StartedAt = &started.Time
		}
		if completed.Valid {
			rt.CompletedAt = &completed.Time
		}
		rt.Logs = logs.String
		tests = append(tests, rt)
	}
	return tests, rows.Err()
}

// ReconcileRunningTests marks orphaned "running" restore tests as failed (their
// driving goroutine died with a server restart).
func (s *BackupService) ReconcileRunningTests() (int64, error) {
	res, err := s.db.Exec(
		`UPDATE restore_tests
		 SET verdict = 'failed', completed_at = NOW(),
		     logs = CONCAT(COALESCE(logs,''), '\nInterrompu (redémarrage serveur)')
		 WHERE verdict = 'running'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ReconcileSandboxGuests destroys any guest actually present on the host inside
// the disposable sandbox range [9500,9599] at boot. No legitimate guest ever
// lives in that range (it is reserved exclusively for ephemeral restore tests), so
// anything found there is a leak left by a crash and must be purged before it fills
// the disk. It must run AFTER the DB reconciliation of orphaned tests.
//
// It lists guests via the Proxmox API (includeGuests), filters with isSandboxVMID
// (the same non-negotiable safety guard used everywhere), and destroys each via
// DestroyGuest (which refuses anything out of range, defense in depth). Returns the
// number of sandbox guests purged.
func (s *BackupService) ReconcileSandboxGuests() (int, error) {
	pm := s.cfgStore.ProxmoxSnapshot()
	stats, err := s.proxmox.GetStats(pm.URL, pm.Node, pm.TokenID,
		pm.TokenSecret, true, false)
	if err != nil {
		return 0, err
	}

	// destroy wraps the real DestroyGuest + task wait for the production path.
	destroy := func(vmid int, pveType string) error {
		upid, derr := s.proxmox.DestroyGuest(pm.URL, pm.Node, pm.TokenID,
			pm.TokenSecret, pveType, vmid)
		if derr != nil {
			return derr
		}
		if upid != "" {
			if _, werr := s.proxmox.waitForTask(pm.URL, pm.Node, pm.TokenID,
				pm.TokenSecret, upid, 5*time.Minute, restorePollInterval); werr != nil {
				return werr
			}
		}
		return nil
	}

	return s.reconcileSandboxGuests(stats.VMs, destroy), nil
}

// reconcileSandboxGuests is the testable core of ReconcileSandboxGuests: it filters
// the guest list to the sandbox range (the only safety-relevant decision) and calls
// destroy on each, alerting on failure. destroy MUST itself refuse anything out of
// range (DestroyGuest does), so even a filtering bug cannot touch a real guest.
// Returns the number of guests successfully purged.
func (s *BackupService) reconcileSandboxGuests(vms []models.VM, destroy func(vmid int, pveType string) error) int {
	cleaned := 0
	for _, vm := range vms {
		if !isSandboxVMID(vm.ID) {
			continue
		}
		pveType := "qemu"
		if vm.Type == "CT" {
			pveType = "lxc"
		}
		slog.Warn("restore-test: leaked sandbox guest found at boot, destroying", "vmid", vm.ID, "type", pveType)
		if err := destroy(vm.ID, pveType); err != nil {
			slog.Error("restore-test: failed to destroy leaked sandbox guest", "vmid", vm.ID, "error", err)
			s.notifyZombieSandbox(vm.ID, err)
			continue
		}
		cleaned++
	}
	return cleaned
}

// --- concurrency slot helpers ---

func (s *BackupService) claimTestSlot(targetID int) bool {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	if s.testInFlight == nil {
		s.testInFlight = make(map[int]bool)
	}
	if s.testInFlight[targetID] {
		return false
	}
	s.testInFlight[targetID] = true
	return true
}

func (s *BackupService) releaseTestSlot(targetID int) {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	delete(s.testInFlight, targetID)
}

// normalizeLevel canonicalises a requested level, defaulting to N3.
func normalizeLevel(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "N1":
		return "N1"
	case "N2":
		return "N2"
	default:
		return "N3"
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
