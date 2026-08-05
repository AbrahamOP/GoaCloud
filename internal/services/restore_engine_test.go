package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"goacore/internal/models"
)

// noopLogf is a logf stub for tests.
func noopLogf(string, ...any) {}

// newTestBackupService builds a BackupService with just the in-process maps wired,
// enough to exercise the concurrency / reconciliation helpers without any DB,
// Proxmox or Discord dependency.
func newTestBackupService() *BackupService {
	return &BackupService{
		testInFlight: make(map[int]bool),
		sandboxInUse: make(map[int]bool),
	}
}

// TestPickFreeSandboxVMID_SkipsReservedAndPresent verifies the picker honours both
// the in-process reservation map and the Proxmox "present" status.
func TestPickFreeSandboxVMID_SkipsReservedAndPresent(t *testing.T) {
	s := newTestBackupService()
	// Pre-reserve the first two slots in-process.
	s.sandboxInUse[sandboxVMIDMin] = true
	s.sandboxInUse[sandboxVMIDMin+1] = true

	// Ping reports the next two as present (running/stopped), then absent.
	ping := func(vmid int) (string, error) {
		switch vmid {
		case sandboxVMIDMin + 2:
			return "running", nil
		case sandboxVMIDMin + 3:
			return "stopped", nil
		default:
			return "absent", nil
		}
	}

	got, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := sandboxVMIDMin + 4
	if got != want {
		t.Fatalf("picked %d, want %d", got, want)
	}
	if !s.sandboxInUse[got] {
		t.Fatalf("picked VMID %d was not marked reserved", got)
	}
}

// TestPickFreeSandboxVMID_NeverReturnsSameTwice is the C2 invariant: repeated picks
// (sequential, simulating non-overlapping reservation) never hand out the same
// VMID while a previous one is still reserved.
func TestPickFreeSandboxVMID_NeverReturnsSameTwice(t *testing.T) {
	s := newTestBackupService()
	// Everything absent on Proxmox: only the in-process reservation gates uniqueness.
	ping := func(int) (string, error) { return "absent", nil }

	seen := make(map[int]bool)
	total := sandboxVMIDMax - sandboxVMIDMin + 1
	for i := 0; i < total; i++ {
		vmid, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
		if err != nil {
			t.Fatalf("pick %d errored unexpectedly: %v", i, err)
		}
		if seen[vmid] {
			t.Fatalf("VMID %d handed out twice while still reserved", vmid)
		}
		seen[vmid] = true
		if vmid < sandboxVMIDMin || vmid > sandboxVMIDMax {
			t.Fatalf("VMID %d out of sandbox range", vmid)
		}
	}
	// Range is now fully reserved → the next pick must fail.
	if _, err := s.pickFreeSandboxVMIDWith(ping, noopLogf); err == nil {
		t.Fatalf("expected exhaustion error once all %d slots reserved", total)
	}
}

// TestPickFreeSandboxVMID_Concurrent stresses the atomic reservation under real
// goroutines: N concurrent pickers must each get a DISTINCT VMID (run with -race).
func TestPickFreeSandboxVMID_Concurrent(t *testing.T) {
	s := newTestBackupService()
	ping := func(int) (string, error) { return "absent", nil }

	const workers = 50
	var wg sync.WaitGroup
	results := make([]int, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vmid, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
			results[idx] = vmid
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool)
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d errored: %v", i, errs[i])
		}
		if seen[results[i]] {
			t.Fatalf("VMID %d handed out to two concurrent workers", results[i])
		}
		seen[results[i]] = true
	}
}

// TestReleaseSandboxVMID verifies a released slot becomes pickable again.
func TestReleaseSandboxVMID(t *testing.T) {
	s := newTestBackupService()
	ping := func(int) (string, error) { return "absent", nil }

	first, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
	if err != nil {
		t.Fatalf("first pick errored: %v", err)
	}
	s.releaseSandboxVMID(first)
	if s.sandboxInUse[first] {
		t.Fatalf("VMID %d still reserved after release", first)
	}
	// A fresh picker over a now-empty map must be able to take the same first slot.
	again, err := s.pickFreeSandboxVMIDWith(ping, noopLogf)
	if err != nil {
		t.Fatalf("second pick errored: %v", err)
	}
	if again != first {
		t.Fatalf("after release, expected to re-pick %d, got %d", first, again)
	}
}

// TestReconcileSandboxGuests_OnlyTouchesSandboxRange asserts the boot reconciliation
// only ever asks to destroy guests inside [9500,9599]. Production VMIDs in the list
// must be left strictly untouched.
func TestReconcileSandboxGuests_OnlyTouchesSandboxRange(t *testing.T) {
	s := newTestBackupService()

	vms := []models.VM{
		{ID: 100, Type: "VM"},  // production — must be ignored
		{ID: 110, Type: "CT"},  // production — must be ignored
		{ID: 9500, Type: "CT"}, // sandbox lower bound
		{ID: 9550, Type: "VM"}, // sandbox mid
		{ID: 9599, Type: "VM"}, // sandbox upper bound
		{ID: 9600, Type: "VM"}, // just above range — must be ignored
		{ID: 9499, Type: "VM"}, // just below range — must be ignored
	}

	var destroyed []int
	destroy := func(vmid int, pveType string) error {
		if !isSandboxVMID(vmid) {
			t.Fatalf("destroy called on NON-sandbox VMID %d (type %s) — safety breach", vmid, pveType)
		}
		destroyed = append(destroyed, vmid)
		return nil
	}

	cleaned := s.reconcileSandboxGuests(vms, destroy)

	wantDestroyed := map[int]bool{9500: true, 9550: true, 9599: true}
	if cleaned != len(wantDestroyed) {
		t.Fatalf("cleaned = %d, want %d", cleaned, len(wantDestroyed))
	}
	for _, v := range destroyed {
		if !wantDestroyed[v] {
			t.Fatalf("destroyed unexpected VMID %d", v)
		}
		delete(wantDestroyed, v)
	}
	if len(wantDestroyed) != 0 {
		t.Fatalf("expected sandbox VMIDs were not destroyed: %v", wantDestroyed)
	}
}

// TestReconcileSandboxGuests_CountsOnlySuccesses verifies that a destroy failure is
// not counted as cleaned (and does not abort the rest of the sweep).
func TestReconcileSandboxGuests_CountsOnlySuccesses(t *testing.T) {
	s := newTestBackupService() // discord nil → notifyZombieSandbox is a no-op

	vms := []models.VM{
		{ID: 9500, Type: "VM"},
		{ID: 9501, Type: "VM"}, // this one will fail to destroy
		{ID: 9502, Type: "VM"},
	}

	destroy := func(vmid int, _ string) error {
		if vmid == 9501 {
			return fmt.Errorf("boom")
		}
		return nil
	}

	if cleaned := s.reconcileSandboxGuests(vms, destroy); cleaned != 2 {
		t.Fatalf("cleaned = %d, want 2 (the failed one must not count)", cleaned)
	}
}

// TestBuildSandboxNetN_MultipleInterfaces documents that buildSandboxNetN is applied
// per-interface (the C1 fix forces tag=99 on every netN, not just net0).
func TestBuildSandboxNetN_MultipleInterfaces(t *testing.T) {
	ifaces := map[string]string{
		"net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,tag=20",
		"net1": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0,tag=30",
		"net2": "name=eth2,bridge=vmbr0", // no tag yet
	}
	want := map[string]string{
		"net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr1,tag=99,link_down=1",
		"net1": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr1,tag=99,link_down=1",
		"net2": "name=eth2,bridge=vmbr1,tag=99,link_down=1",
	}
	for key, cur := range ifaces {
		got := buildSandboxNetN(cur, "qemu", 99, "vmbr1")
		if got != want[key] {
			t.Errorf("%s: buildSandboxNetN(%q) = %q, want %q", key, cur, got, want[key])
		}
	}
}

// TestProvenLevel est le garde-fou d'HONNÊTETÉ du verdict : un test ne peut afficher
// N3 (« l'application répond ») que si la cible déclare un healthcheck exploitable.
// Le cas nominal d'une cible auto-découverte (healthcheck_type='none') doit être
// rétrogradé en N2 — sinon le produit certifie une restauration qu'il n'a pas vérifiée.
func TestProvenLevel(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		hcType    string
		hcTarget  string
		want      string
	}{
		// Chemin 1 — healthcheck configuré : le N3 demandé reste un N3.
		{"n3 with service healthcheck stays n3", "N3", "service", "nginx", "N3"},
		{"n3 with port healthcheck stays n3", "N3", "port", "8080", "N3"},
		{"n3 with padded type stays n3", "N3", " Service ", "nginx", "N3"},
		// Chemin 2 — aucun healthcheck exploitable : rétrogradation en N2.
		{"n3 without healthcheck is demoted", "N3", "none", "", "N2"},
		{"n3 with empty type is demoted", "N3", "", "", "N2"},
		{"n3 with type but no target is demoted", "N3", "service", "", "N2"},
		{"n3 with target but type none is demoted", "N3", "none", "nginx", "N2"},
		{"n3 with blank target is demoted", "N3", "port", "   ", "N2"},
		// Les autres niveaux ne promettent rien sur l'application : inchangés.
		{"n2 unchanged without healthcheck", "N2", "none", "", "N2"},
		{"n2 unchanged with healthcheck", "N2", "service", "nginx", "N2"},
		{"n1 unchanged", "N1", "none", "", "N1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := provenLevel(tc.requested, tc.hcType, tc.hcTarget); got != tc.want {
				t.Fatalf("provenLevel(%q, %q, %q) = %q, want %q", tc.requested, tc.hcType, tc.hcTarget, got, tc.want)
			}
		})
	}
}

// TestArchiveFileName couvre la réduction d'un volid au nom d'archive, nécessaire pour
// rattacher un test au run qui a produit l'archive (les runs locaux enregistrent le
// volid, les runs off-site le nom de fichier rendu par le helper).
func TestArchiveFileName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst", "vzdump-lxc-110-2026_06_22-03_19_36.tar.zst"},
		{"vzdump-lxc-110-2026_06_22-03_19_36.tar.zst", "vzdump-lxc-110-2026_06_22-03_19_36.tar.zst"},
		{"local:vzdump-qemu-105.vma.zst", "vzdump-qemu-105.vma.zst"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := archiveFileName(tc.in); got != tc.want {
			t.Errorf("archiveFileName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPickFreeSandboxVMID_StopsOnDeadTransport vérifie que le scan abandonne dès que
// le canal est manifestement injoignable, au lieu d'enchaîner une centaine de dials
// SSH à 15 s (jusqu'à ~25 min de blocage observées).
func TestPickFreeSandboxVMID_StopsOnDeadTransport(t *testing.T) {
	s := newTestBackupService()
	probes := 0
	ping := func(int) (string, error) {
		probes++
		return "", fmt.Errorf("dial tcp 192.0.2.1:22: i/o timeout")
	}

	_, err := s.pickFreeSandboxVMIDBounded(ping, noopLogf, time.Now().Add(time.Minute), 5)
	if err == nil {
		t.Fatal("attendu une erreur explicite de transport, obtenu nil")
	}
	if probes != 5 {
		t.Fatalf("scan poursuivi au-delà du budget d'échecs: %d sondes, attendu 5", probes)
	}
	if !strings.Contains(err.Error(), "injoignable") {
		t.Fatalf("erreur peu explicite pour l'opérateur: %v", err)
	}
}

// TestPickFreeSandboxVMID_ToleratesIsolatedProbeFailure vérifie que le compteur
// d'échecs consécutifs se remet à zéro : un slot capricieux ne doit pas faire échouer
// tout le scan.
func TestPickFreeSandboxVMID_ToleratesIsolatedProbeFailure(t *testing.T) {
	s := newTestBackupService()
	ping := func(vmid int) (string, error) {
		// Un échec isolé tous les deux slots, jamais deux d'affilée.
		if (vmid-sandboxVMIDMin)%2 == 0 {
			return "", fmt.Errorf("hoquet transitoire")
		}
		return "absent", nil
	}

	got, err := s.pickFreeSandboxVMIDBounded(ping, noopLogf, time.Now().Add(time.Minute), 5)
	if err != nil {
		t.Fatalf("un échec isolé ne doit pas avorter le scan: %v", err)
	}
	if got != sandboxVMIDMin+1 {
		t.Fatalf("VMID retenu %d, attendu %d", got, sandboxVMIDMin+1)
	}
}

// TestPickFreeSandboxVMID_StopsAtDeadline vérifie la borne de temps totale : même sans
// erreur de transport, le scan ne peut pas s'éterniser.
func TestPickFreeSandboxVMID_StopsAtDeadline(t *testing.T) {
	s := newTestBackupService()
	ping := func(int) (string, error) { return "running", nil } // jamais libre

	// Deadline déjà dépassée : le tout premier candidat doit suffire à abandonner.
	probes := 0
	countingPing := func(vmid int) (string, error) {
		probes++
		return ping(vmid)
	}
	_, err := s.pickFreeSandboxVMIDBounded(countingPing, noopLogf, time.Now().Add(-time.Second), 5)
	if err == nil {
		t.Fatal("attendu un abandon sur dépassement de délai")
	}
	if probes != 0 {
		t.Fatalf("%d sonde(s) émise(s) après le délai, attendu 0", probes)
	}
}

// TestWait_DrainsTasksAndRefusesNewOnes couvre le cycle de vie applicatif : Wait attend
// les orchestrations en vol (dont le defer de destruction du sandbox) puis refuse toute
// nouvelle tâche.
func TestWait_DrainsTasksAndRefusesNewOnes(t *testing.T) {
	s := newTestBackupService()

	release := make(chan struct{})
	finished := make(chan struct{})
	if !s.startTask(func() {
		<-release
		close(finished)
	}) {
		t.Fatal("startTask a refusé une tâche sur un service actif")
	}

	waited := make(chan error, 1)
	go func() { waited <- s.Wait(context.Background()) }()

	// Wait ne doit pas rendre la main tant que la tâche tourne.
	select {
	case err := <-waited:
		t.Fatalf("Wait a rendu la main avant la fin de la tâche (err=%v)", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-finished
	if err := <-waited; err != nil {
		t.Fatalf("Wait = %v, want nil", err)
	}
	if s.startTask(func() {}) {
		t.Fatal("une nouvelle orchestration a été acceptée pendant l'arrêt")
	}
}

// TestWait_HonoursContextDeadline vérifie qu'une tâche qui ne se termine pas ne bloque
// pas l'arrêt indéfiniment : Wait rend la main sur expiration du contexte.
func TestWait_HonoursContextDeadline(t *testing.T) {
	s := newTestBackupService()
	release := make(chan struct{})
	if !s.startTask(func() { <-release }) {
		t.Fatal("startTask a refusé une tâche sur un service actif")
	}
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait = %v, want context.DeadlineExceeded", err)
	}
}

// TestIsNetKey verifies only real netN keys are treated as interfaces.
func TestIsNetKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"net0", true},
		{"net1", true},
		{"net12", true},
		{"net", false},
		{"netfoo", false},
		{"net0x", false},
		{"name", false},
		{"ethernet0", false},
		{"", false},
		{"NET0", false}, // case-sensitive: PVE keys are lowercase
	}
	for _, tc := range tests {
		if got := isNetKey(tc.key); got != tc.want {
			t.Errorf("isNetKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
