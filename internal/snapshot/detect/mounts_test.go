package detect

import (
	"testing"
	"testing/fstest"
)

func TestLoadMountTable_ParsesZFSAndBtrfs(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"sysfs /sys sysfs rw 0 0\n" +
				"tank/data /mnt/data zfs rw,relatime 0 0\n" +
				"tank/services/sonarr /mnt/data/sonarr zfs rw,relatime 0 0\n" +
				"/dev/sdc /mnt/btrfs btrfs rw,relatime 0 0\n",
		)},
	}
	tbl, err := loadMountTableFromFS(probe)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(tbl.all); got != 3 {
		t.Fatalf("got %d mounts, want 3 (sysfs filtered): %+v", got, tbl.all)
	}
	// Sort order: deepest first.
	if tbl.all[0].MountPoint != "/mnt/data/sonarr" {
		t.Errorf("deepest mount = %q, want /mnt/data/sonarr", tbl.all[0].MountPoint)
	}
}

func TestMountTable_FindContaining_DeepestWins(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"tank/data /mnt/data zfs rw 0 0\n" +
				"tank/services/sonarr /mnt/data/sonarr zfs rw 0 0\n",
		)},
	}
	tbl, _ := loadMountTableFromFS(probe)

	m, ok := tbl.FindContaining("/mnt/data/sonarr/config")
	if !ok {
		t.Fatal("expected match")
	}
	if m.Source != "tank/services/sonarr" {
		t.Errorf("got %q, want tank/services/sonarr", m.Source)
	}

	// Sibling under /mnt/data falls back to the parent dataset.
	m2, ok := tbl.FindContaining("/mnt/data/jellyfin")
	if !ok {
		t.Fatal("expected match for /mnt/data/jellyfin")
	}
	if m2.Source != "tank/data" {
		t.Errorf("got %q, want tank/data", m2.Source)
	}
}

func TestMountTable_FindContaining_NoMatchReturnsFalse(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"tank/data /mnt/data zfs rw 0 0\n",
		)},
	}
	tbl, _ := loadMountTableFromFS(probe)
	if _, ok := tbl.FindContaining("/var/lib/docker"); ok {
		t.Error("expected no match for non-zfs path")
	}
}

func TestInferSnapshotTarget(t *testing.T) {
	zfs := Mount{Source: "tank/data", MountPoint: "/mnt/data", FSType: "zfs"}
	got := InferSnapshotTarget(zfs, "/mnt/data/sonarr/config")
	if got != "tank/data" {
		t.Errorf("zfs target = %q, want tank/data", got)
	}

	btrfs := Mount{Source: "/dev/sdb", MountPoint: "/mnt/btrfs/sonarr", FSType: "btrfs"}
	got = InferSnapshotTarget(btrfs, "/mnt/btrfs/sonarr/data")
	if got != "/mnt/btrfs/sonarr/data" {
		t.Errorf("btrfs target = %q, want /mnt/btrfs/sonarr/data", got)
	}

	// Unsupported fs type.
	got = InferSnapshotTarget(Mount{FSType: "ext4"}, "/foo")
	if got != "" {
		t.Errorf("ext4 should yield empty target, got %q", got)
	}
}

func TestUnescapeMount(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/mnt/data", "/mnt/data"},
		{`/mnt/with\040space`, "/mnt/with space"},
		{`/mnt/tab\011here`, "/mnt/tab\there"},
		{`/mnt/back\134slash`, `/mnt/back\slash`},
	}
	for _, c := range cases {
		got := unescapeMount(c.in)
		if got != c.want {
			t.Errorf("unescapeMount(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
