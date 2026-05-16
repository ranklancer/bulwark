package detect

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Mount represents one line from /proc/mounts in the form Bulwark cares
// about. Source is the device or dataset name (zfs dataset for zfs,
// device path for btrfs); MountPoint is the absolute host path the fs
// is mounted at; FSType is "zfs" / "btrfs" / etc.
type Mount struct {
	Source     string
	MountPoint string
	FSType     string
}

// MountTable holds the deduplicated zfs + btrfs mounts the daemon has
// discovered. The list is sorted by MountPoint length descending so
// FindContaining picks the deepest match (closest to the operator's
// bind path) on the first hit.
type MountTable struct {
	all []Mount
}

// LoadMountTable parses /proc/mounts from the live host filesystem.
func LoadMountTable() (*MountTable, error) {
	return loadMountTableFromFS(os.DirFS("/"))
}

func loadMountTableFromFS(probeFS fs.FS) (*MountTable, error) {
	f, err := probeFS.Open("proc/mounts")
	if err != nil {
		// No /proc/mounts (containers without /proc bind, BSDs, etc.):
		// return an empty table — callers fall back to "no inference"
		// rather than failing the scan/apply.
		return &MountTable{}, nil
	}
	defer f.Close()

	mounts := []Mount{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		fstype := fields[2]
		// Only fs types Bulwark can snapshot today. Adding new
		// backends extends this allowlist.
		if fstype != "zfs" && fstype != "btrfs" {
			continue
		}
		// Decode space → \040 escapes (mount paths can contain spaces).
		mp := unescapeMount(fields[1])
		mounts = append(mounts, Mount{
			Source:     unescapeMount(fields[0]),
			MountPoint: mp,
			FSType:     fstype,
		})
	}
	// Deepest mount point first so FindContaining's linear scan hits
	// the most specific match before any parent.
	sort.SliceStable(mounts, func(i, j int) bool {
		return len(mounts[i].MountPoint) > len(mounts[j].MountPoint)
	})
	return &MountTable{all: mounts}, nil
}

// FindContaining returns the deepest known snapshot-capable mount that
// contains hostPath, or ok=false when no such mount exists. The
// returned Mount is safe to pass to InferSnapshotTarget.
func (t *MountTable) FindContaining(hostPath string) (Mount, bool) {
	if t == nil || hostPath == "" {
		return Mount{}, false
	}
	// Canonicalise: trim trailing slash + resolve "."/".." segments.
	clean := filepath.Clean(hostPath)
	if !strings.HasPrefix(clean, "/") {
		// Bind sources are always absolute when Docker hands them back;
		// anything else is malformed and shouldn't auto-snapshot.
		return Mount{}, false
	}
	for _, m := range t.all {
		if pathContains(m.MountPoint, clean) {
			return m, true
		}
	}
	return Mount{}, false
}

// pathContains reports whether the candidate path lives at or under the
// parent path. Both paths must already be filepath.Clean'd.
func pathContains(parent, candidate string) bool {
	if parent == candidate {
		return true
	}
	if parent == "/" {
		return true
	}
	return strings.HasPrefix(candidate, parent+"/")
}

// InferSnapshotTarget translates a Mount + host bind path into the
// argument the snapshot backend wants. For ZFS that's the dataset
// name with any sub-path appended via dataset semantics; for Btrfs
// that's the host path itself (the existing btrfs backend takes a
// path, not a subvolume identifier).
//
// Returns empty string when the mount's filesystem isn't supported.
func InferSnapshotTarget(m Mount, hostPath string) string {
	clean := filepath.Clean(hostPath)
	switch m.FSType {
	case "zfs":
		// /proc/mounts shows the dataset name in field 0 (e.g.
		// "tank/data"). For any descendant path inside that mount,
		// we want the same dataset — the ZFS backend snapshots the
		// dataset and its descendants atomically.
		return m.Source
	case "btrfs":
		// The btrfs backend's existing contract: pass the filesystem
		// path. The deepest matching mount.MountPoint is the
		// subvolume root that contains hostPath.
		return clean
	}
	return ""
}

// unescapeMount decodes /proc/mounts's octal-escape sequences. The
// kernel only emits four: space (\040), tab (\011), newline (\012),
// backslash (\134). We handle them inline rather than reaching for a
// general unescape library.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			switch s[i : i+4] {
			case `\040`:
				b.WriteByte(' ')
				i += 3
				continue
			case `\011`:
				b.WriteByte('\t')
				i += 3
				continue
			case `\012`:
				b.WriteByte('\n')
				i += 3
				continue
			case `\134`:
				b.WriteByte('\\')
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
