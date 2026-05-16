package detect

import (
	"encoding/json"
	"testing"
	"testing/fstest"
)

func TestParseHostConfigBinds(t *testing.T) {
	raw := json.RawMessage(`{
		"Binds": [
			"/srv/sonarr/config:/config",
			"/srv/sonarr/media:/media:ro",
			"sonarr_data:/data",
			"/srv/sonarr/backups:/backups:rw,Z"
		],
		"NetworkMode": "bridge"
	}`)
	got, err := ParseHostConfigBinds(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d binds, want 3 (named volume excluded): %+v", len(got), got)
	}
	want := []BindMount{
		{Source: "/srv/sonarr/config", Destination: "/config"},
		{Source: "/srv/sonarr/media", Destination: "/media"},
		{Source: "/srv/sonarr/backups", Destination: "/backups"},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("bind[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestParseHostConfigBinds_EmptyRawIsNil(t *testing.T) {
	got, err := ParseHostConfigBinds(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("empty raw HostConfig should yield nil; got %+v", got)
	}
}

func TestInferTargetFromBinds_ZFS(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"tank/services/sonarr /mnt/data/sonarr zfs rw 0 0\n" +
				"tank/data /mnt/data zfs rw 0 0\n",
		)},
	}
	tbl, _ := loadMountTableFromFS(probe)
	binds := []BindMount{
		{Source: "/etc/timezone", Destination: "/etc/timezone"},
		{Source: "/mnt/data/sonarr/config", Destination: "/config"},
	}
	target, ok := InferTargetFromBinds(binds, tbl)
	if !ok {
		t.Fatal("expected an inferred target")
	}
	if target != "tank/services/sonarr" {
		t.Errorf("target = %q, want tank/services/sonarr", target)
	}
}

func TestInferTargetFromBinds_Btrfs(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"/dev/sdb /mnt/btrfs btrfs rw 0 0\n",
		)},
	}
	tbl, _ := loadMountTableFromFS(probe)
	target, ok := InferTargetFromBinds([]BindMount{
		{Source: "/mnt/btrfs/sonarr", Destination: "/config"},
	}, tbl)
	if !ok {
		t.Fatal("expected an inferred target on btrfs")
	}
	if target != "/mnt/btrfs/sonarr" {
		t.Errorf("target = %q, want /mnt/btrfs/sonarr", target)
	}
}

func TestInferTargetFromBinds_NoMatchReturnsFalse(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"tank/data /mnt/data zfs rw 0 0\n",
		)},
	}
	tbl, _ := loadMountTableFromFS(probe)
	if _, ok := InferTargetFromBinds([]BindMount{
		{Source: "/etc/timezone", Destination: "/etc/timezone"},
	}, tbl); ok {
		t.Error("expected no match for non-zfs binds")
	}
}

func TestInferTargetFromBinds_NilTableSafe(t *testing.T) {
	if _, ok := InferTargetFromBinds([]BindMount{{Source: "/x"}}, nil); ok {
		t.Error("nil table should yield no match (and not panic)")
	}
}
