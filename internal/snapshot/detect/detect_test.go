package detect

import (
	"testing"
	"testing/fstest"
)

func TestDetectFS_TrueNASScale(t *testing.T) {
	// TrueNAS SCALE writes its release info to /etc/version. The ZFS
	// module is always loaded; the platform value must win over the
	// generic ZFS classification.
	probe := fstest.MapFS{
		"etc/version":    &fstest.MapFile{Data: []byte("TrueNAS-SCALE-24.04.0\n")},
		"sys/module/zfs": &fstest.MapFile{Mode: 0o755 | (1 << 31)}, // directory
	}
	got := DetectFS(probe)
	if got.Platform != PlatformTrueNAS {
		t.Errorf("platform = %q, want %q", got.Platform, PlatformTrueNAS)
	}
	if got.VersionString != "TrueNAS-SCALE-24.04.0" {
		t.Errorf("version = %q", got.VersionString)
	}
	if !hasCap(got.Capabilities, CapZFS) {
		t.Errorf("expected ZFS capability on TrueNAS SCALE; got %v", got.Capabilities)
	}
	if got.SuggestedBackend != "zfs" {
		t.Errorf("suggested backend = %q, want zfs", got.SuggestedBackend)
	}
}

func TestDetectFS_ProxmoxVE(t *testing.T) {
	// Proxmox always mounts /etc/pve. Usually has ZFS too but not
	// guaranteed; we still classify it as proxmox.
	probe := fstest.MapFS{
		"etc/pve":         &fstest.MapFile{Mode: 0o755 | (1 << 31)},
		"etc/pve/version": &fstest.MapFile{Data: []byte("8.1.4\n")},
		"sys/module/zfs":  &fstest.MapFile{Mode: 0o755 | (1 << 31)},
	}
	got := DetectFS(probe)
	if got.Platform != PlatformProxmox {
		t.Errorf("platform = %q, want %q", got.Platform, PlatformProxmox)
	}
	if got.VersionString != "8.1.4" {
		t.Errorf("version = %q, want 8.1.4", got.VersionString)
	}
	if !hasCap(got.Capabilities, CapProxmoxAPI) {
		t.Errorf("expected proxmox-api capability; got %v", got.Capabilities)
	}
	if !hasCap(got.Capabilities, CapZFS) {
		t.Errorf("expected ZFS capability alongside proxmox; got %v", got.Capabilities)
	}
}

func TestDetectFS_ProxmoxWithoutZFS(t *testing.T) {
	// Proxmox node booted from ext4 only (rare but legitimate). No
	// ZFS module, suggested backend should fall back to empty.
	probe := fstest.MapFS{
		"etc/pve": &fstest.MapFile{Mode: 0o755 | (1 << 31)},
	}
	got := DetectFS(probe)
	if got.Platform != PlatformProxmox {
		t.Errorf("platform = %q, want proxmox", got.Platform)
	}
	if got.SuggestedBackend != "proxmox" {
		t.Errorf("suggested backend = %q, want proxmox", got.SuggestedBackend)
	}
}

func TestDetectFS_Unraid(t *testing.T) {
	probe := fstest.MapFS{
		"etc/unraid-version": &fstest.MapFile{Data: []byte(`version="6.12.10"` + "\n")},
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"/dev/md0 /mnt/disk1 btrfs rw,relatime 0 0\n" +
				"/dev/loop1 /mnt/cache btrfs rw,relatime 0 0\n",
		)},
	}
	got := DetectFS(probe)
	if got.Platform != PlatformUnraid {
		t.Errorf("platform = %q, want %q", got.Platform, PlatformUnraid)
	}
	if got.VersionString != "6.12.10" {
		t.Errorf("version = %q, want 6.12.10", got.VersionString)
	}
	if !hasCap(got.Capabilities, CapBtrfs) {
		t.Errorf("expected btrfs capability on Unraid; got %v", got.Capabilities)
	}
	if got.SuggestedBackend != "btrfs" {
		t.Errorf("suggested backend = %q, want btrfs", got.SuggestedBackend)
	}
}

func TestDetectFS_UnraidWithZFSPlugin(t *testing.T) {
	// Unraid users who installed the ZFS plugin should get the ZFS
	// suggestion (ZFS wins over Btrfs on Unraid because Bulwark's ZFS
	// backend ships today and the operator clearly opted into it).
	probe := fstest.MapFS{
		"etc/unraid-version": &fstest.MapFile{Data: []byte("6.12.10\n")},
		"sys/module/zfs":     &fstest.MapFile{Mode: 0o755 | (1 << 31)},
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"tank /mnt/data zfs rw,relatime 0 0\n",
		)},
	}
	got := DetectFS(probe)
	if got.Platform != PlatformUnraid {
		t.Errorf("platform = %q, want unraid", got.Platform)
	}
	if got.SuggestedBackend != "zfs" {
		t.Errorf("suggested backend = %q, want zfs (ZFS plugin should win on Unraid)", got.SuggestedBackend)
	}
}

func TestDetectFS_GenericZFS(t *testing.T) {
	probe := fstest.MapFS{
		"sys/module/zfs": &fstest.MapFile{Mode: 0o755 | (1 << 31)},
	}
	got := DetectFS(probe)
	if got.Platform != PlatformZFS {
		t.Errorf("platform = %q, want zfs", got.Platform)
	}
	if got.SuggestedBackend != "zfs" {
		t.Errorf("suggested backend = %q, want zfs", got.SuggestedBackend)
	}
}

func TestDetectFS_GenericBtrfs(t *testing.T) {
	probe := fstest.MapFS{
		"proc/mounts": &fstest.MapFile{Data: []byte(
			"/dev/sda1 / btrfs rw,relatime,subvol=/ 0 0\n",
		)},
	}
	got := DetectFS(probe)
	if got.Platform != PlatformBtrfs {
		t.Errorf("platform = %q, want btrfs", got.Platform)
	}
	if got.SuggestedBackend != "btrfs" {
		t.Errorf("suggested backend = %q, want btrfs", got.SuggestedBackend)
	}
}

func TestDetectFS_EmptyFilesystem(t *testing.T) {
	got := DetectFS(fstest.MapFS{})
	if got.Platform != PlatformUnknown {
		t.Errorf("platform = %q, want unknown", got.Platform)
	}
	if len(got.Capabilities) != 0 {
		t.Errorf("expected zero capabilities on bare host; got %v", got.Capabilities)
	}
	if got.SuggestedBackend != "" {
		t.Errorf("suggested backend = %q, want empty", got.SuggestedBackend)
	}
}

func TestParseUnraidVersion(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`version="6.12.10"`, "6.12.10"},
		{`version="6.12.10"` + "\n", "6.12.10"},
		{"6.12.10", "6.12.10"},
		{"  version=6.12  ", "6.12"},
	} {
		got := parseUnraidVersion(c.in)
		if got != c.want {
			t.Errorf("parseUnraidVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func hasCap(s []Capability, want Capability) bool {
	for _, c := range s {
		if c == want {
			return true
		}
	}
	return false
}
