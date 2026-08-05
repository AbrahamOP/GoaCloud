package services

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"goacore/internal/models"
)

func TestParseVMIDFromVolID(t *testing.T) {
	tests := []struct {
		name  string
		volid string
		want  int
	}{
		{"lxc archive", "local:backup/vzdump-lxc-110-2026_06_22-03_19_36.tar.zst", 110},
		{"qemu archive", "local:backup/vzdump-qemu-105-2026_06_22-03_19_36.vma.zst", 105},
		{"no slash prefix", "vzdump-lxc-202-2026_06_22-03_19_36.tar.zst", 202},
		{"non-numeric vmid", "local:backup/vzdump-lxc-abc-2026_06_22.tar.zst", 0},
		{"too few parts", "local:backup/vzdump-lxc", 0},
		{"empty string", "", 0},
		{"unrelated path", "local:iso/debian.iso", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVMIDFromVolID(tt.volid); got != tt.want {
				t.Errorf("parseVMIDFromVolID(%q) = %d, want %d", tt.volid, got, tt.want)
			}
		})
	}
}

func TestNodeFromUPID(t *testing.T) {
	tests := []struct {
		name string
		upid string
		want string
	}{
		{"standard upid", "UPID:pve:0008F1A3:0123ABCD:66775533:vzdump::root@pam:", "pve"},
		{"other node", "UPID:node2:00001:0002:0003:vzdump:110:root@pam:", "node2"},
		{"empty node", "UPID::0001:0002:0003:vzdump::root@pam:", ""},
		{"missing prefix", "pve:0001:vzdump", ""},
		{"empty string", "", ""},
		{"only prefix", "UPID", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nodeFromUPID(tt.upid); got != tt.want {
				t.Errorf("nodeFromUPID(%q) = %q, want %q", tt.upid, got, tt.want)
			}
		})
	}
}

func TestRPOStatus(t *testing.T) {
	tests := []struct {
		name     string
		age      time.Duration
		rpoHours int
		want     string
	}{
		{"no rpo configured is ok", 100 * time.Hour, 0, "ok"},
		{"negative rpo is ok", time.Hour, -5, "ok"},
		{"within rpo", 12 * time.Hour, 24, "ok"},
		{"exactly at rpo", 24 * time.Hour, 24, "ok"},
		{"just over rpo is warn", 25 * time.Hour, 24, "warn"},
		{"at double rpo is warn", 48 * time.Hour, 24, "warn"},
		{"over double rpo is breach", 49 * time.Hour, 24, "breach"},
		{"way over is breach", 200 * time.Hour, 24, "breach"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rpoStatus(tt.age, tt.rpoHours); got != tt.want {
				t.Errorf("rpoStatus(%v, %d) = %q, want %q", tt.age, tt.rpoHours, got, tt.want)
			}
		})
	}
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want string
	}{
		{"zero bytes", 0, "0 B"},
		{"sub kilo", 512, "512 B"},
		{"one kibibyte", 1024, "1.0 KiB"},
		{"one and half kib", 1536, "1.5 KiB"},
		{"one mebibyte", 1024 * 1024, "1.0 MiB"},
		{"one gibibyte", 1024 * 1024 * 1024, "1.0 GiB"},
		{"two and half gib", 2560 * 1024 * 1024, "2.5 GiB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanSize(tt.in); got != tt.want {
				t.Errorf("humanSize(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHumanAge(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"minutes", 30 * time.Minute, "30 min"},
		{"zero is minutes", 0, "0 min"},
		{"one hour", time.Hour, "1 h"},
		{"hours under two days", 47 * time.Hour, "47 h"},
		{"two days in hours", 48 * time.Hour, "2 j"},
		{"several days", 100 * time.Hour, "4 j"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanAge(tt.in); got != tt.want {
				t.Errorf("humanAge(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		vmid int
		want string
	}{
		{"plain name", "web-server", 110, "web-server"},
		{"allowed punctuation", "VM_01.prod-A 2", 110, "VM_01.prod-A 2"},
		{"strips backticks", "evil`whoami`", 110, "evilwhoami"},
		{"strips discord mention", "@everyone hi", 110, "everyone hi"},
		{"strips angle/markdown", "<b>x</b> [y](z)", 110, "bxb yz"},
		{"empty falls back", "", 42, "VM 42"},
		{"whitespace only falls back", "   ", 7, "VM 7"},
		{"only forbidden chars falls back", "@#$%^&*()", 99, "VM 99"},
		{"trims surrounding spaces", "   hello   ", 110, "hello"},
		{
			name: "truncates to 64 chars",
			in:   strings.Repeat("a", 80),
			vmid: 110,
			want: strings.Repeat("a", 64),
		},
		{
			name: "truncation re-trims trailing space",
			in:   strings.Repeat("a", 63) + "   bbb",
			vmid: 110,
			want: strings.Repeat("a", 63),
		},
		{"unicode stripped", "héllo→wörld", 110, "hllowrld"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeName(tt.in, tt.vmid)
			if got != tt.want {
				t.Errorf("sanitizeName(%q, %d) = %q, want %q", tt.in, tt.vmid, got, tt.want)
			}
			if len(got) > 64 {
				t.Errorf("sanitizeName(%q) returned %d chars, want <= 64", tt.in, len(got))
			}
		})
	}
}

func TestRotationLevel(t *testing.T) {
	tests := []struct {
		name            string
		healthcheckType string
		want            string
	}{
		{"empty -> N2", "", "N2"},
		{"none -> N2", "none", "N2"},
		{"NONE uppercase -> N2", "NONE", "N2"},
		{"none padded -> N2", "  none  ", "N2"},
		{"service -> N3", "service", "N3"},
		{"port -> N3", "port", "N3"},
		{"PORT uppercase -> N3", "PORT", "N3"},
		{"arbitrary non-empty -> N3", "http", "N3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rotationLevel(tt.healthcheckType); got != tt.want {
				t.Errorf("rotationLevel(%q) = %q, want %q", tt.healthcheckType, got, tt.want)
			}
		})
	}
}

func TestValidateTargetSettings(t *testing.T) {
	tests := []struct {
		name       string
		hcType     string
		hcTarget   string
		retention  int
		wantType   string
		wantTarget string
		wantErr    bool
	}{
		{"none normalizes empty target", "none", "ignored", 3, "none", "", false},
		{"empty type defaults to none", "", "", 3, "none", "", false},
		{"service ok", "Service", "nginx", 5, "service", "nginx", false},
		{"port numeric ok", "port", "443", 2, "port", "443", false},
		{"uppercase port normalized", "PORT", "8080", 1, "port", "8080", false},
		{"invalid type rejected", "ping", "x", 3, "", "", true},
		{"port non-numeric rejected", "port", "abc", 3, "", "", true},
		{"port out of range rejected", "port", "70000", 3, "", "", true},
		{"port empty rejected", "port", "", 3, "", "", true},
		{"negative retention rejected", "none", "", -1, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotTarget, err := validateTargetSettings(tt.hcType, tt.hcTarget, tt.retention)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateTargetSettings(%q,%q,%d) err = %v, wantErr %v", tt.hcType, tt.hcTarget, tt.retention, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gotType != tt.wantType || gotTarget != tt.wantTarget {
				t.Errorf("validateTargetSettings(%q,%q,%d) = (%q,%q), want (%q,%q)",
					tt.hcType, tt.hcTarget, tt.retention, gotType, gotTarget, tt.wantType, tt.wantTarget)
			}
		})
	}
}

func TestValidateDestination(t *testing.T) {
	tests := []struct {
		name       string
		dest       string
		remote     string
		wantDest   string
		wantRemote string
		wantErr    error // nil, or a sentinel to match with errors.Is
	}{
		{"empty defaults to local", "", "", "local", "", nil},
		{"local drops remote", "local", "gcrypt", "local", "", nil},
		{"local case-insensitive", "LOCAL", "", "local", "", nil},
		{"local padded", "  local  ", "", "local", "", nil},
		{"both with remote ok", "both", "gdrive", "both", "gdrive", nil},
		{"both trims remote", "both", "  gdrive  ", "both", "gdrive", nil},
		{"remote with remote ok", "remote", "wasabi", "remote", "wasabi", nil},
		{"both case-insensitive", "BOTH", "gdrive", "both", "gdrive", nil},
		{"both without remote rejected", "both", "", "", "", ErrUnknownRemote},
		{"both whitespace remote rejected", "both", "   ", "", "", ErrUnknownRemote},
		{"remote without remote rejected", "remote", "", "", "", ErrUnknownRemote},
		{"invalid destination rejected", "cloud", "gdrive", "", "", errSentinelAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDest, gotRemote, err := validateDestination(tt.dest, tt.remote)
			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Fatalf("validateDestination(%q,%q) unexpected err %v", tt.dest, tt.remote, err)
				}
				if gotDest != tt.wantDest || gotRemote != tt.wantRemote {
					t.Errorf("validateDestination(%q,%q) = (%q,%q), want (%q,%q)",
						tt.dest, tt.remote, gotDest, gotRemote, tt.wantDest, tt.wantRemote)
				}
			case tt.wantErr == errSentinelAny:
				if err == nil {
					t.Fatalf("validateDestination(%q,%q) want error, got nil", tt.dest, tt.remote)
				}
			default:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("validateDestination(%q,%q) err = %v, want %v", tt.dest, tt.remote, err, tt.wantErr)
				}
			}
		})
	}
}

// errSentinelAny is a test-only marker meaning "any non-nil error is acceptable".
var errSentinelAny = errors.New("any error")

func TestDestinationLabel(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		remote      string
		want        string
	}{
		{"local", "local", "", "Local"},
		{"unknown falls back to local", "weird", "", "Local"},
		{"both", "both", "gdrive", "Local + gdrive"},
		{"remote", "remote", "wasabi", "wasabi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := destinationLabel(tt.destination, tt.remote); got != tt.want {
				t.Errorf("destinationLabel(%q,%q) = %q, want %q", tt.destination, tt.remote, got, tt.want)
			}
		})
	}
}

func TestValidateRotationHour(t *testing.T) {
	tests := []struct {
		name    string
		hour    int
		wantErr bool
	}{
		{"min bound", 0, false},
		{"max bound", 23, false},
		{"mid", 4, false},
		{"negative", -1, true},
		{"too large", 24, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRotationHour(tt.hour); (err != nil) != tt.wantErr {
				t.Errorf("validateRotationHour(%d) err = %v, wantErr %v", tt.hour, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRPOHours(t *testing.T) {
	tests := []struct {
		name    string
		hours   int
		wantErr bool
	}{
		{"one hour", 1, false},
		{"schema default", 24, false},
		{"one week", 168, false},
		{"max bound one year", maxRPOHours, false},
		// 0 est refusé : rpoStatus() lit toute valeur <= 0 comme « toujours ok », ce qui
		// peindrait en vert une cible jamais sauvegardée dans le KPI de couverture.
		{"zero would silently green the KPI", 0, true},
		{"negative", -5, true},
		{"beyond one year", maxRPOHours + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRPOHours(tt.hours); (err != nil) != tt.wantErr {
				t.Errorf("validateRPOHours(%d) err = %v, wantErr %v", tt.hours, err, tt.wantErr)
			}
		})
	}
}

// archive fabrique une entrée d'archive de test pour la rotation de rétention.
func archive(vmid int, day int) models.BackupEntry {
	name := fmt.Sprintf("local:backup/vzdump-lxc-%d-2026_06_%02d-03_19_36.tar.zst", vmid, day)
	return models.BackupEntry{
		VolID:   name,
		VMID:    vmid,
		Type:    "lxc",
		Storage: "local",
		CTime:   time.Date(2026, 6, day, 3, 19, 36, 0, time.UTC),
	}
}

// TestArchivesToPrune couvre la décision la PLUS destructive du produit : quelles
// sauvegardes d'un client sont supprimées. Toute ambiguïté doit se résoudre par « on
// ne supprime rien ».
func TestArchivesToPrune(t *testing.T) {
	five := []models.BackupEntry{
		archive(110, 1), archive(110, 2), archive(110, 3), archive(110, 4), archive(110, 5),
	}

	t.Run("retention disabled keeps everything", func(t *testing.T) {
		for _, keep := range []int{0, -1} {
			if got := archivesToPrune(five, 110, keep); got != nil {
				t.Fatalf("keep=%d a élu %d archive(s) à supprimer, attendu aucune", keep, len(got))
			}
		}
	})

	t.Run("fewer archives than the retention keeps everything", func(t *testing.T) {
		if got := archivesToPrune(five, 110, 5); got != nil {
			t.Fatalf("élu %d archive(s), attendu aucune", len(got))
		}
		if got := archivesToPrune(five, 110, 9); got != nil {
			t.Fatalf("élu %d archive(s), attendu aucune", len(got))
		}
	})

	t.Run("keeps the N most recent", func(t *testing.T) {
		got := archivesToPrune(five, 110, 3)
		if len(got) != 2 {
			t.Fatalf("élu %d archive(s), attendu 2", len(got))
		}
		pruned := map[string]bool{}
		for _, e := range got {
			pruned[e.VolID] = true
		}
		if !pruned[archive(110, 1).VolID] || !pruned[archive(110, 2).VolID] {
			t.Fatalf("mauvaises archives élues: %v (attendu les deux plus anciennes)", pruned)
		}
	})

	t.Run("never touches another guest", func(t *testing.T) {
		mixed := append([]models.BackupEntry{}, five...)
		mixed = append(mixed, archive(113, 1), archive(113, 2), archive(113, 3))
		for _, e := range archivesToPrune(mixed, 110, 1) {
			if e.VMID != 110 {
				t.Fatalf("archive du VMID %d élue à la suppression pour la cible 110", e.VMID)
			}
		}
	})

	t.Run("ignores an entry whose volid does not carry the vmid", func(t *testing.T) {
		// Incohérence de listing : l'entrée prétend appartenir à 110 mais le fichier est
		// celui de 113. Défense en profondeur — on ne la supprime jamais.
		bogus := models.BackupEntry{
			VolID: "local:backup/vzdump-lxc-113-2026_06_01-03_19_36.tar.zst",
			VMID:  110,
			CTime: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), // la plus ancienne
		}
		for _, e := range archivesToPrune(append([]models.BackupEntry{bogus}, five...), 110, 2) {
			if e.VolID == bogus.VolID {
				t.Fatal("archive incohérente élue à la suppression")
			}
		}
	})

	t.Run("no archive at all", func(t *testing.T) {
		if got := archivesToPrune(nil, 110, 3); got != nil {
			t.Fatalf("élu %d archive(s) sur une liste vide", len(got))
		}
	})

	t.Run("unknown vmid prunes nothing", func(t *testing.T) {
		if got := archivesToPrune(five, 0, 1); got != nil {
			t.Fatalf("élu %d archive(s) pour un VMID nul", len(got))
		}
	})
}
