package snapshot

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
)

// ZFSBackend implements Backend over the local zfs(8) CLI. Targets are
// dataset names (e.g. "tank/docker/sonarr"); snapshot IDs are the full
// dataset@name reference.
type ZFSBackend struct {
	Runner Runner
	Now    func() time.Time
}

// NewZFS returns a ZFSBackend. Pass nil to use the real ExecRunner.
func NewZFS(r Runner) *ZFSBackend {
	if r == nil {
		r = ExecRunner{}
	}
	return &ZFSBackend{Runner: r, Now: time.Now}
}

func (z *ZFSBackend) Name() string { return "zfs" }

// Available reports whether the zfs binary is present. We don't try to
// query datasets here — that would require root and a real pool. The
// daemon falls back to "no snapshots" with a log warning when this
// returns false.
func (z *ZFSBackend) Available(ctx context.Context) bool {
	return z.Runner.Available(ctx, "zfs")
}

// Snapshot creates "target@bulwark-{label}-{timestamp}" via `zfs snapshot`.
func (z *ZFSBackend) Snapshot(ctx context.Context, target, label string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("zfs: target dataset is required")
	}
	now := z.Now
	if now == nil {
		now = time.Now
	}
	id := target + "@" + snapshotName(label, now())
	if _, err := z.Runner.Run(ctx, "zfs", "snapshot", id); err != nil {
		return "", fmt.Errorf("zfs: snapshot %s: %w", id, err)
	}
	return id, nil
}

// Restore runs `zfs rollback -r <id>`. The -r flag destroys any snapshots
// or filesystems newer than the target — required when there have been
// snapshots taken between the target and now. Bulwark only ever creates
// one snapshot per (container, update) so this is safe in practice.
func (z *ZFSBackend) Restore(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("zfs: snapshot id is required")
	}
	if _, err := z.Runner.Run(ctx, "zfs", "rollback", "-r", id); err != nil {
		return fmt.Errorf("zfs: rollback %s: %w", id, err)
	}
	return nil
}

// Destroy runs `zfs destroy <id>`. We deliberately omit -R so we never
// recursively delete filesystems — if a snapshot has dependent clones,
// the user has to clean them up first.
func (z *ZFSBackend) Destroy(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("zfs: snapshot id is required")
	}
	if _, err := z.Runner.Run(ctx, "zfs", "destroy", id); err != nil {
		return fmt.Errorf("zfs: destroy %s: %w", id, err)
	}
	return nil
}

// List returns Bulwark-created snapshots for target, parsed from
// `zfs list -H -o name,creation -p -t snapshot -r <target>`. We add -d 1
// to limit to direct children so we don't scan child filesystems.
func (z *ZFSBackend) List(ctx context.Context, target string) ([]Snapshot, error) {
	if target == "" {
		return nil, fmt.Errorf("zfs: target dataset is required")
	}
	out, err := z.Runner.Run(ctx, "zfs", "list", "-H", "-p", "-d", "1",
		"-o", "name,creation", "-t", "snapshot", target)
	if err != nil {
		return nil, fmt.Errorf("zfs: list %s: %w", target, err)
	}
	var result []Snapshot
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		fullName := fields[0]
		// Format: dataset@snapshot-name
		atIdx := strings.LastIndex(fullName, "@")
		if atIdx < 0 {
			continue
		}
		ds := fullName[:atIdx]
		snapPart := fullName[atIdx+1:]
		label, when, ok := parseSnapshotName(snapPart)
		if !ok {
			continue
		}
		// Creation is a Unix timestamp when -p (parsable) is used.
		// We prefer the timestamp encoded in the snapshot name (which
		// reflects Bulwark's clock at creation) over zfs's reported
		// creation time, since the latter may have second precision
		// while we want sub-second order in tests.
		_ = fields[1] // intentionally ignored
		result = append(result, Snapshot{
			ID:        fullName,
			Target:    ds,
			Label:     label,
			CreatedAt: when,
		})
	}
	return result, scanner.Err()
}
