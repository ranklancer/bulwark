// Package snapshot exposes filesystem-level snapshot backends used by the
// updater to provide *data* rollback (not just container/image rollback).
//
// Backends shell out to the relevant CLI tools (zfs, btrfs) — the only
// portable option that doesn't drag in large C bindings. Tests inject a
// FakeRunner so the package can be exercised without root and without an
// actual filesystem to operate on.
//
// Backend choice is configured by name in YAML; the registry below maps
// names to constructors. Backends advertise their availability at startup
// via Available() so the daemon can fall back to "no snapshots" with a
// clear log warning when the chosen backend isn't usable on the current
// host.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Backend is the contract every snapshot implementation satisfies.
type Backend interface {
	// Name is a stable identifier for log lines and config selection.
	Name() string

	// Available reports whether this backend can be used on the current
	// host. The check is done once at startup; if Available returns false,
	// callers should treat the backend as if it weren't configured.
	Available(ctx context.Context) bool

	// Snapshot creates a snapshot of target labeled with label. The
	// returned id is opaque to callers — it must be passed back into
	// Restore or Destroy.
	Snapshot(ctx context.Context, target, label string) (string, error)

	// Restore reverts target to the snapshot identified by id. The
	// behaviour is destructive: any state written since the snapshot is
	// discarded.
	Restore(ctx context.Context, id string) error

	// Destroy removes a snapshot. Used for routine cleanup after a
	// successful update where the snapshot is no longer needed.
	Destroy(ctx context.Context, id string) error

	// List enumerates Bulwark-created snapshots for target. Implementations
	// filter by the bulwark- prefix — third-party snapshots are never
	// returned.
	List(ctx context.Context, target string) ([]Snapshot, error)
}

// Snapshot is the minimal record returned by List. The ID is whatever the
// backend uses to identify the snapshot internally (e.g. "pool/data@bulwark-20260501T0900").
type Snapshot struct {
	ID        string
	Target    string
	Label     string
	CreatedAt time.Time
}

// ErrUnsupported is returned by backends that can't service a particular
// operation on this system (e.g. the underlying CLI is missing).
var ErrUnsupported = errors.New("snapshot: backend unsupported on this host")

// labelPrefix tags every Bulwark-created snapshot so users (and the List
// implementations) can distinguish ours from their own.
const labelPrefix = "bulwark"

// snapshotName composes the snapshot suffix used after the "@" in ZFS or
// in the Btrfs subvolume name. The format is bulwark-{label}-{timestamp},
// where timestamp is RFC3339 collapsed to a filename-safe form.
func snapshotName(label string, when time.Time) string {
	ts := when.UTC().Format("20060102T150405Z")
	clean := sanitizeLabel(label)
	if clean == "" {
		return labelPrefix + "-" + ts
	}
	return labelPrefix + "-" + clean + "-" + ts
}

// sanitizeLabel makes labels safe to embed in filesystem names. Only ASCII
// letters, digits, hyphens, and dots survive; everything else is dropped.
func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '.':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseSnapshotName extracts the label and creation timestamp from a
// snapshot name produced by snapshotName. Returns ok=false for names
// that aren't Bulwark-created.
func parseSnapshotName(name string) (label string, when time.Time, ok bool) {
	if !strings.HasPrefix(name, labelPrefix+"-") {
		return "", time.Time{}, false
	}
	rest := strings.TrimPrefix(name, labelPrefix+"-")
	// Timestamp is the LAST 16 characters: yyyymmddThhmmssZ.
	if len(rest) < len("20060102T150405Z") {
		return "", time.Time{}, false
	}
	tsStr := rest[len(rest)-len("20060102T150405Z"):]
	t, err := time.Parse("20060102T150405Z", tsStr)
	if err != nil {
		return "", time.Time{}, false
	}
	prefix := strings.TrimSuffix(rest, tsStr)
	prefix = strings.TrimSuffix(prefix, "-")
	return prefix, t, true
}

// New returns a backend by name. Unknown names yield (nil, error) — callers
// can fall back to running without snapshots.
func New(name string) (Backend, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "none":
		return nil, nil
	case "zfs":
		return NewZFS(nil), nil
	case "btrfs":
		return NewBtrfs(nil), nil
	default:
		return nil, fmt.Errorf("snapshot: unknown backend %q", name)
	}
}
