package services

import (
	"strings"
	"testing"

	"goacore/internal/config"
)

// TestResolveRestoreStorage_Overrides covers the no-network branches of the
// resolution order: a dedicated restore_storage wins, else the creation storage,
// before any auto-detection is attempted. The auto-detect + literal floor branch is
// network-bound (live Proxmox) and is exercised by detectStorage's own tests; here
// we assert the precedence that must short-circuit before any API call.
func TestResolveRestoreStorage_Overrides(t *testing.T) {
	p := NewProxmoxService(nil, true)

	// 1. Dedicated restore_storage override wins over pm.Storage.
	pm := config.ProxmoxConn{Storage: "create-lvm", RestoreStorage: "restore-zfs"}
	if got := p.resolveRestoreStorage(pm, "qemu"); got != "restore-zfs" {
		t.Errorf("restore_storage override = %q, want restore-zfs", got)
	}

	// 2. No dedicated restore_storage → fall back to the creation storage (pm.Storage),
	// still without touching the network.
	pm = config.ProxmoxConn{Storage: "create-lvm"}
	if got := p.resolveRestoreStorage(pm, "lxc"); got != "create-lvm" {
		t.Errorf("pm.Storage fallback = %q, want create-lvm", got)
	}
}

func TestIsSandboxVMID(t *testing.T) {
	tests := []struct {
		name string
		vmid int
		want bool
	}{
		{"below range lower bound", 9499, false},
		{"lower bound inclusive", 9500, true},
		{"mid range", 9550, true},
		{"upper bound inclusive", 9599, true},
		{"above range upper bound", 9600, false},
		{"zero", 0, false},
		{"negative", -1, false},
		{"production guest 110", 110, false},
		{"production guest 100", 100, false},
		{"large out of range", 100000, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSandboxVMID(tc.vmid); got != tc.want {
				t.Fatalf("isSandboxVMID(%d) = %v, want %v", tc.vmid, got, tc.want)
			}
		})
	}
}

func TestBuildSandboxNetN(t *testing.T) {
	tests := []struct {
		name    string
		current string
		pveType string
		vlan    int
		bridge  string
		want    string
	}{
		{"lxc empty fallback", "", "lxc", 99, "vmbr1", "name=eth0,bridge=vmbr1,tag=99,link_down=1"},
		{"qemu empty fallback", "", "qemu", 99, "vmbr1", "virtio,bridge=vmbr1,tag=99,link_down=1"},
		{
			"lxc replace existing tag and bridge",
			"name=eth0,bridge=vmbr0,ip=192.0.2.11/24,tag=20",
			"lxc", 99, "vmbr1",
			"name=eth0,bridge=vmbr1,ip=192.0.2.11/24,tag=99,link_down=1",
		},
		{
			"qemu add tag, keep model+mac",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
			"qemu", 99, "vmbr1",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=99,link_down=1",
		},
		{
			// Incident 2026-06-28: un OPNsense restauré (QEMU) doit démarrer lien coupé.
			"qemu forces link_down on every NIC",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=20,link_down=0",
			"qemu", 99, "vmbr1",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=99,link_down=1",
		},
		{
			// link_down fait partie du schéma net[n] de pve-container : un CT restauré
			// démarre avec la conf réseau de la PROD (IP statique, passerelle) et
			// entrerait en conflit avec le conteneur de production encore en ligne.
			"lxc also gets link_down",
			"name=eth0,bridge=vmbr0,tag=20",
			"lxc", 99, "vmbr1",
			"name=eth0,bridge=vmbr1,tag=99,link_down=1",
		},
		{
			// Une valeur link_down=0 héritée de l'archive doit être écrasée, pas gardée.
			"lxc link_down=0 from the archive is forced back to 1",
			"name=eth0,bridge=vmbr0,tag=20,link_down=0",
			"lxc", 99, "vmbr1",
			"name=eth0,bridge=vmbr1,tag=99,link_down=1",
		},
		{
			"no bridge present gets one",
			"name=eth0,ip=dhcp",
			"lxc", 99, "vmbr1",
			"name=eth0,ip=dhcp,bridge=vmbr1,tag=99,link_down=1",
		},
		{
			// Jalon 2: a custom sandbox bridge is honoured (override/pm.Bridge), and a
			// restored prod NIC's bridge is rewritten to it — never kept.
			"custom sandbox bridge rewrites prod bridge",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=20",
			"qemu", 42, "vmbr9",
			"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr9,tag=42,link_down=1",
		},
		{
			// Empty bridge floors to the hard vmbr1 fallback — never bridgeless.
			"empty bridge floors to vmbr1",
			"name=eth0,ip=dhcp",
			"lxc", 99, "",
			"name=eth0,ip=dhcp,bridge=vmbr1,tag=99,link_down=1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSandboxNetN(tc.current, tc.pveType, tc.vlan, tc.bridge)
			if got != tc.want {
				t.Fatalf("buildSandboxNetN(%q,%q,%d,%q) = %q, want %q", tc.current, tc.pveType, tc.vlan, tc.bridge, got, tc.want)
			}
		})
	}
}

// TestBuildSandboxNetN_AlwaysCutsTheLink est le garde-fou d'isolation : QUEL QUE SOIT
// le type de machine et la configuration réseau portée par l'archive, l'interface du
// sandbox sort avec link_down=1. Un CT de production restauré sans lien coupé
// entrerait en conflit d'IP avec le conteneur de production toujours en ligne.
func TestBuildSandboxNetN_AlwaysCutsTheLink(t *testing.T) {
	currents := []string{
		"",
		"name=eth0,bridge=vmbr0,ip=192.0.2.11/24,gw=192.0.2.1,tag=20",
		"name=eth0,bridge=vmbr0,ip=dhcp,link_down=0",
		"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
		"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,link_down=0,tag=10",
	}
	for _, pveType := range []string{"lxc", "qemu"} {
		for _, cur := range currents {
			got := buildSandboxNetN(cur, pveType, 99, "vmbr1")
			if !strings.Contains(got, "link_down=1") {
				t.Errorf("%s: buildSandboxNetN(%q) = %q — lien non coupé, isolation non garantie", pveType, cur, got)
			}
			if strings.Contains(got, "link_down=0") {
				t.Errorf("%s: buildSandboxNetN(%q) = %q — link_down=0 hérité de l'archive", pveType, cur, got)
			}
			if !strings.Contains(got, "tag=99") || !strings.Contains(got, "bridge=vmbr1") {
				t.Errorf("%s: buildSandboxNetN(%q) = %q — VLAN/bridge d'isolation non forcés", pveType, cur, got)
			}
		}
	}
}

// TestVolIDBelongsToVMID couvre le garde-fou de la rotation de rétention : une archive
// n'est supprimable que si son NOM DE FICHIER porte le VMID attendu.
func TestVolIDBelongsToVMID(t *testing.T) {
	tests := []struct {
		name  string
		volID string
		vmid  int
		want  bool
	}{
		{"lxc archive of the target", "local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst", 110, true},
		{"qemu archive of the target", "local:backup/vzdump-qemu-105-2026_06_22-03_19_36.vma.zst", 105, true},
		{"archive of ANOTHER guest", "local:backup/vzdump-lxc-113-2026_06_22-03_19_36.tar.zst", 110, false},
		{"prefix collision 1100 vs 110", "local:backup/vzdump-lxc-1100-2026_06_22-03_19_36.tar.zst", 110, false},
		{"unparseable volid", "local:backup/whatever.tar.zst", 110, false},
		{"empty volid", "", 110, false},
		{"zero vmid", "local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst", 0, false},
		{"negative vmid", "local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst", -1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := volIDBelongsToVMID(tc.volID, tc.vmid); got != tc.want {
				t.Fatalf("volIDBelongsToVMID(%q, %d) = %v, want %v", tc.volID, tc.vmid, got, tc.want)
			}
		})
	}
}

// TestDeleteBackupArchive_RefusesForeignArchive vérifie que la suppression refuse —
// SANS appel API — une archive qui n'appartient pas au VMID attendu. L'URL passée est
// volontairement injoignable : si la garde ne fonctionnait pas, le test échouerait sur
// une erreur réseau au lieu du refus de sûreté.
func TestDeleteBackupArchive_RefusesForeignArchive(t *testing.T) {
	p := NewProxmoxService(nil, true)
	_, err := p.DeleteBackupArchive("https://127.0.0.1:1/", "pve", "id", "secret",
		"local", "local:backup/vzdump-lxc-113-2026_06_22-03_19_36.tar.zst", 110)
	if err == nil {
		t.Fatal("suppression acceptée pour une archive d'un AUTRE VMID — brèche de sûreté")
	}
	if !strings.Contains(err.Error(), "refus de sûreté") {
		t.Fatalf("erreur inattendue (attendu un refus de sûreté, pas un appel réseau): %v", err)
	}
}
