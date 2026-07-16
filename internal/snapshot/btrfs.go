package snapshot

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// BtrfsBackend snapshots Btrfs subvolumes via the btrfs(8) CLI.
//
// Unlike ZFS, Btrfs doesn't have a built-in "rollback" verb. The
// equivalent dance is:
//
//  1. snapshot of the live subvolume → "<target>/.bulwark-snapshots/<name>"
//  2. on rollback: rename live subvolume to "<target>-failed-<ts>",
//     then recursively snapshot the backup back into the original path.
//
// Bulwark stores its snapshots under a hidden ".bulwark-snapshots"
// directory inside the parent of the target so they don't pollute the
// user's view of their data.
//
// Targets here are filesystem paths to Btrfs subvolumes (e.g.
// "/mnt/data/sonarr"), not dataset names.
type BtrfsBackend struct {
	Runner Runner
	Now    func() time.Time
}

// NewBtrfs returns a BtrfsBackend. Pass nil for the real ExecRunner.
func NewBtrfs(r Runner) *BtrfsBackend {
	if r == nil {
		r = ExecRunner{}
	}
	return &BtrfsBackend{Runner: r, Now: time.Now}
}

func (b *BtrfsBackend) Name() string { return "btrfs" }

// Available reports whether the btrfs binary is present.
func (b *BtrfsBackend) Available(ctx context.Context) bool {
	return b.Runner.Available(ctx, "btrfs")
}

// snapshotDir is the hidden directory under target's parent where
// Bulwark stores its read-only snapshots.
func snapshotDir(target string) string {
	return filepath.Join(filepath.Dir(target), ".bulwark-snapshots")
}

// snapshotPath builds the full path to a snapshot named "<basename>-<name>"
// under snapshotDir(target).
func (b *BtrfsBackend) snapshotPath(target, snapName string) string {
	base := filepath.Base(target)
	return filepath.Join(snapshotDir(target), base+"--"+snapName)
}

// Snapshot creates a read-only Btrfs snapshot of target. Returns the
// snapshot's filesystem path as the opaque ID.
func (b *BtrfsBackend) Snapshot(ctx context.Context, target, label string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("btrfs: target subvolume is required")
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	// Make sure the .bulwark-snapshots directory exists. mkdir -p is the
	// simplest path; if it already exists we're fine.
	if _, err := b.Runner.Run(ctx, "mkdir", "-p", snapshotDir(target)); err != nil {
		return "", fmt.Errorf("btrfs: prepare snapshot dir: %w", err)
	}
	id := b.snapshotPath(target, snapshotName(label, now()))
	if _, err := b.Runner.Run(ctx, "btrfs", "subvolume", "snapshot", "-r", target, id); err != nil {
		return "", fmt.Errorf("btrfs: snapshot %s → %s: %w", target, id, err)
	}
	return id, nil
}

// Restore reverts the original subvolume to the snapshot identified by id.
// Implementation: rename the current live subvolume aside, then snapshot
// the backup back into place. We then clean up the renamed-aside live
// version so the user's filesystem stays tidy.
//
// IDs are the path that Snapshot returned (e.g.
// /mnt/data/.bulwark-snapshots/sonarr--bulwark-...).
func (b *BtrfsBackend) Restore(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("btrfs: snapshot id is required")
	}
	target, err := targetFromSnapshotID(id)
	if err != nil {
		return err
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	asideName := target + "-bulwark-failed-" + now().UTC().Format("20060102T150405Z")

	// 1. Move the live subvolume aside.
	if _, err := b.Runner.Run(ctx, "mv", target, asideName); err != nil {
		return fmt.Errorf("btrfs: move live aside: %w", err)
	}
	// 2. Recreate by snapshotting the backup (writable this time).
	if _, err := b.Runner.Run(ctx, "btrfs", "subvolume", "snapshot", id, target); err != nil {
		// Try to put the aside subvolume back.
		_, _ = b.Runner.Run(ctx, "mv", asideName, target)
		return fmt.Errorf("btrfs: restore from %s: %w", id, err)
	}
	// 3. Cleanup the failed-aside subvolume. Errors here are non-fatal —
	//    we've successfully rolled the user's data forward.
	_, _ = b.Runner.Run(ctx, "btrfs", "subvolume", "delete", asideName)
	return nil
}

// Destroy removes a snapshot via `btrfs subvolume delete`.
func (b *BtrfsBackend) Destroy(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("btrfs: snapshot id is required")
	}
	if _, err := b.Runner.Run(ctx, "btrfs", "subvolume", "delete", id); err != nil {
		return fmt.Errorf("btrfs: destroy %s: %w", id, err)
	}
	return nil
}

// List enumerates Bulwark-created snapshots for target by reading
// ".bulwark-snapshots/" entries via `ls -1`. We don't use `btrfs subvolume
// list` here because it requires the FS root and a different argument
// shape; the directory listing gives us everything we need.
func (b *BtrfsBackend) List(ctx context.Context, target string) ([]Snapshot, error) {
	if target == "" {
		return nil, fmt.Errorf("btrfs: target subvolume is required")
	}
	out, err := b.Runner.Run(ctx, "ls", "-1", snapshotDir(target))
	if err != nil {
		// Missing directory is "no snapshots", not an error.
		if strings.Contains(err.Error(), "No such file or directory") {
			return nil, nil
		}
		return nil, fmt.Errorf("btrfs: list snapshot dir: %w", err)
	}
	base := filepath.Base(target)
	prefix := base + "--"
	var snaps []Snapshot
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(entry, prefix) {
			continue
		}
		name := strings.TrimPrefix(entry, prefix)
		label, when, ok := parseSnapshotName(name)
		if !ok {
			continue
		}
		snaps = append(snaps, Snapshot{
			ID:        filepath.Join(snapshotDir(target), entry),
			Target:    target,
			Label:     label,
			CreatedAt: when,
		})
	}
	return snaps, scanner.Err()
}

// targetFromSnapshotID derives the live-subvolume path from a snapshot ID
// produced by Snapshot. The encoding is:
//
//	<target-parent>/.bulwark-snapshots/<basename>--<snapname>
func targetFromSnapshotID(id string) (string, error) {
	dir, name := filepath.Split(id)
	if !strings.HasSuffix(filepath.Clean(dir), "/.bulwark-snapshots") {
		return "", fmt.Errorf("btrfs: snapshot id %q is not a Bulwark snapshot path", id)
	}
	parent := filepath.Dir(filepath.Clean(dir))
	dashIdx := strings.Index(name, "--")
	if dashIdx <= 0 {
		return "", fmt.Errorf("btrfs: snapshot id %q has no recoverable target name", id)
	}
	return filepath.Join(parent, name[:dashIdx]), nil
}
