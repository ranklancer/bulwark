// Package detect probes the host filesystem for well-known platform
// markers so Bulwark can auto-suggest a snapshot backend on operator
// systems it knows about. Detection is read-only and runs once at
// daemon start (results are cached on the StateHandler for the dashboard
// to render).
//
// Platforms covered for v1.0:
//
//   - TrueNAS SCALE — Linux ZFS appliance with k3s. /etc/version exists
//     and contains "TrueNAS"; ZFS module loaded.
//   - Proxmox VE — Debian-based virtualization host. /etc/pve directory
//     present (the Proxmox cluster filesystem).
//   - Unraid — array-based NAS distro. /etc/unraid-version is the
//     canonical marker, version reflects the Unraid release.
//   - Generic ZFS — `/sys/module/zfs` directory exists (ZFS module
//     loaded) AND /etc/version doesn't already identify a vendor
//     platform.
//   - Generic Btrfs — at least one mount is type=btrfs; identified
//     via /proc/mounts.
//
// The detector deliberately reads from a probeFS (an fs.FS rooted at
// "/" by default) so tests can stub the filesystem with fstest.MapFS.
// Each platform check is a pure function of file presence + contents.
package detect

import (
	"bufio"
	"io/fs"
	"os"
	"strings"
)

// Platform enumerates the host classes Bulwark recognizes. The order of
// detection priority is significant: vendor platforms (TrueNAS, Proxmox,
// Unraid) win over generic filesystem markers because their preferred
// snapshot integration is more specific (e.g. Proxmox API vs. raw ZFS).
type Platform string

const (
	PlatformTrueNAS Platform = "truenas-scale"
	PlatformProxmox Platform = "proxmox-ve"
	PlatformUnraid  Platform = "unraid"
	PlatformZFS     Platform = "zfs"     // generic ZFS, no vendor distro
	PlatformBtrfs   Platform = "btrfs"   // generic Btrfs
	PlatformUnknown Platform = "unknown" // no recognized markers
)

// Capability describes one snapshot-relevant feature the daemon can use.
type Capability string

const (
	CapZFS         Capability = "zfs"          // zfs binary + module present
	CapBtrfs       Capability = "btrfs"        // btrfs binary + at least one mount
	CapProxmoxAPI  Capability = "proxmox-api"  // /etc/pve cluster fs present
)

// Result is the full output of one detection pass. Platform is the
// "primary" classification; Capabilities is the deduplicated set of
// every snapshot-relevant marker found (a TrueNAS host shows both
// truenas-scale platform AND zfs capability, for example, so the UI
// can fall back gracefully when the platform-specific integration is
// unavailable).
//
// VersionString carries the platform's self-reported version where it's
// trivially readable (Unraid's /etc/unraid-version, TrueNAS's
// /etc/version) so the dashboard can show "Unraid 6.12.x" without an
// extra round-trip. Empty when unknown.
type Result struct {
	Platform       Platform     `json:"platform"`
	VersionString  string       `json:"version,omitempty"`
	Capabilities   []Capability `json:"capabilities"`
	SuggestedBackend string     `json:"suggested_backend,omitempty"` // "zfs" | "btrfs" | ""
}

// Detect runs a detection pass against the live host filesystem.
func Detect() Result {
	return DetectFS(os.DirFS("/"))
}

// DetectFS runs a detection pass against an arbitrary fs.FS rooted at
// the equivalent of "/". Paths passed to fs.ReadFile must be relative
// (no leading slash) — DetectFS strips the leading slash from the
// canonical "/etc/..." paths internally.
func DetectFS(probeFS fs.FS) Result {
	caps := make([]Capability, 0, 3)
	platform := PlatformUnknown
	version := ""

	// /etc/version is set on both TrueNAS SCALE and some other distros;
	// the marker we look for is the literal substring "TrueNAS".
	if data, ok := tryRead(probeFS, "etc/version"); ok {
		s := strings.TrimSpace(string(data))
		if strings.Contains(s, "TrueNAS") {
			platform = PlatformTrueNAS
			version = s
		}
	}

	// Proxmox VE always mounts /etc/pve (the cluster filesystem).
	// Higher priority than generic ZFS but lower than TrueNAS because a
	// Proxmox node could theoretically be running on TrueNAS SCALE
	// hardware (rare; vendor platforms win).
	if platform == PlatformUnknown {
		if exists(probeFS, "etc/pve") {
			platform = PlatformProxmox
			if data, ok := tryRead(probeFS, "etc/pve/version"); ok {
				version = strings.TrimSpace(string(data))
			}
		}
	}
	if platform == PlatformProxmox || hasProxmox(probeFS) {
		caps = appendOnce(caps, CapProxmoxAPI)
	}

	// Unraid: /etc/unraid-version always exists on the appliance and
	// contains `version="6.12.x"`-style lines. The presence of the file
	// alone is enough; the contents drive the dashboard's version
	// badge.
	if platform == PlatformUnknown {
		if data, ok := tryRead(probeFS, "etc/unraid-version"); ok {
			platform = PlatformUnraid
			version = parseUnraidVersion(string(data))
		}
	}

	// ZFS: /sys/module/zfs is a directory on any host with the ZFS
	// kernel module loaded — including TrueNAS, Proxmox, and Unraid
	// with the ZFS plugin. Recorded as a capability regardless of
	// platform so the UI can show "ZFS available" everywhere.
	if exists(probeFS, "sys/module/zfs") {
		caps = appendOnce(caps, CapZFS)
		if platform == PlatformUnknown {
			platform = PlatformZFS
		}
	}

	// Btrfs: /proc/mounts has lines like
	//   /dev/foo  /mnt/bar  btrfs  rw,relatime,...  0 0
	// — the third field is the filesystem type. We scan and bail out as
	// soon as we find one btrfs row.
	if hasBtrfsMount(probeFS) {
		caps = appendOnce(caps, CapBtrfs)
		if platform == PlatformUnknown {
			platform = PlatformBtrfs
		}
	}

	return Result{
		Platform:         platform,
		VersionString:    version,
		Capabilities:     caps,
		SuggestedBackend: suggestedBackend(platform, caps),
	}
}

// suggestedBackend picks the snapshots.backend value the daemon should
// default to when the operator hasn't set one. Operator-set values in
// yaml always win; this is purely a UI hint and a default for new
// installs.
//
// Order: ZFS-aware platforms (TrueNAS / Proxmox / Unraid-with-ZFS /
// generic ZFS) → ZFS. Anything else with Btrfs → btrfs. Unknown →
// empty (we don't want to silently enable a backend on hosts where it
// won't work).
func suggestedBackend(p Platform, caps []Capability) string {
	hasCap := func(c Capability) bool {
		for _, x := range caps {
			if x == c {
				return true
			}
		}
		return false
	}
	if hasCap(CapZFS) {
		return "zfs"
	}
	switch p {
	case PlatformTrueNAS:
		// Almost certainly ZFS even when the module probe missed
		// (TrueNAS containerized sandbox, etc.). Fall back to zfs.
		return "zfs"
	}
	if hasCap(CapBtrfs) {
		return "btrfs"
	}
	return ""
}

// parseUnraidVersion extracts the version string from
// /etc/unraid-version which Unraid writes as `version="6.12.4"`.
// Returns the trimmed value or the raw input if it doesn't match.
func parseUnraidVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "version="); i >= 0 {
		v := raw[i+len("version="):]
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		return v
	}
	return raw
}

func hasBtrfsMount(probeFS fs.FS) bool {
	f, err := probeFS.Open("proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// fields: device mountpoint fstype options dump pass
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "btrfs" {
			return true
		}
	}
	return false
}

// hasProxmox lets the Proxmox capability flag fire even when /etc/pve
// is a regular file (single-node deployments, test stubs).
func hasProxmox(probeFS fs.FS) bool {
	return exists(probeFS, "etc/pve")
}

func tryRead(probeFS fs.FS, name string) ([]byte, bool) {
	data, err := fs.ReadFile(probeFS, name)
	if err != nil {
		return nil, false
	}
	return data, true
}

func exists(probeFS fs.FS, name string) bool {
	_, err := fs.Stat(probeFS, name)
	return err == nil
}

func appendOnce(s []Capability, c Capability) []Capability {
	for _, x := range s {
		if x == c {
			return s
		}
	}
	return append(s, c)
}
