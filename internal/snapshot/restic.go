package snapshot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ResticBackend implements Backend over the restic(1) CLI. Targets are
// absolute filesystem paths; snapshot IDs are the hex hashes restic
// assigns to each backup.
//
// Authentication uses --password-file rather than RESTIC_PASSWORD env
// vars so the secret never appears in the process table or in the
// daemon's environment dump. The password file's permissions are the
// operator's responsibility — Bulwark only reads through it.
type ResticBackend struct {
	Runner       Runner
	Repo         string
	PasswordFile string
	Now          func() time.Time
}

// NewRestic returns a ResticBackend. Pass nil for r to use the real
// ExecRunner. Repo and passwordFile are typically pulled from the YAML
// config block `snapshots.restic.{repository,password_file}`.
func NewRestic(repo, passwordFile string, r Runner) *ResticBackend {
	if r == nil {
		r = ExecRunner{}
	}
	return &ResticBackend{
		Runner:       r,
		Repo:         repo,
		PasswordFile: passwordFile,
		Now:          time.Now,
	}
}

func (b *ResticBackend) Name() string { return "restic" }

// Available reports whether the restic binary exists on PATH AND the
// backend has both a repository and password file configured. We don't
// dial the repository here — that requires network/filesystem access we
// might not have at startup probe time. Operators see the configuration
// gap reflected in this single check.
func (b *ResticBackend) Available(ctx context.Context) bool {
	if b == nil {
		return false
	}
	if b.Repo == "" || b.PasswordFile == "" {
		return false
	}
	return b.Runner.Available(ctx, "restic")
}

// repoArgs returns the universal flags every restic invocation needs.
// Using flags rather than RESTIC_REPOSITORY / RESTIC_PASSWORD env vars
// keeps the secret out of /proc/<pid>/environ.
func (b *ResticBackend) repoArgs() []string {
	return []string{"--repo", b.Repo, "--password-file", b.PasswordFile}
}

// Snapshot runs `restic backup <target> --tag bulwark --tag <name>` and
// returns the new snapshot's hex ID. The "bulwark" group tag lets
// listing match all of our snapshots; the per-call tag carries the
// label + timestamp for human readability and List() reverse-mapping.
func (b *ResticBackend) Snapshot(ctx context.Context, target, label string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("restic: target path is required")
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	tag := snapshotName(label, now())
	args := append(b.repoArgs(),
		"backup", target,
		"--tag", labelPrefix,
		"--tag", tag,
		"--json",
	)
	out, err := b.Runner.Run(ctx, "restic", args...)
	if err != nil {
		return "", fmt.Errorf("restic: backup %s: %w", target, err)
	}
	id := parseResticBackupID(out)
	if id == "" {
		return "", fmt.Errorf("restic: backup %s: no snapshot_id in output", target)
	}
	return id, nil
}

// Restore reverts via `restic restore <id> --target / --delete`. The
// --target / flag is correct here: restic snapshots store absolute
// paths, so extracting to / re-creates files at their original
// locations. --delete removes files that were added between the snapshot
// and the current state — required for proper rollback semantics
// (otherwise stray files written by the new image leak into the old).
func (b *ResticBackend) Restore(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("restic: snapshot id is required")
	}
	args := append(b.repoArgs(),
		"restore", id,
		"--target", "/",
		"--delete",
	)
	if _, err := b.Runner.Run(ctx, "restic", args...); err != nil {
		return fmt.Errorf("restic: restore %s: %w", id, err)
	}
	return nil
}

// Destroy runs `restic forget <id> --prune`. Without --prune the
// snapshot reference is removed but the underlying data is retained
// until the next prune; for routine cleanup we want the storage back
// immediately.
func (b *ResticBackend) Destroy(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("restic: snapshot id is required")
	}
	args := append(b.repoArgs(),
		"forget", id,
		"--prune",
	)
	if _, err := b.Runner.Run(ctx, "restic", args...); err != nil {
		return fmt.Errorf("restic: forget %s: %w", id, err)
	}
	return nil
}

// List enumerates Bulwark-created snapshots whose `paths` array contains
// target. The "bulwark" group tag filters at restic level; we still
// post-filter on path so a shared repo holding multiple containers'
// snapshots lists them per-container correctly.
func (b *ResticBackend) List(ctx context.Context, target string) ([]Snapshot, error) {
	if target == "" {
		return nil, fmt.Errorf("restic: target path is required")
	}
	args := append(b.repoArgs(),
		"snapshots",
		"--tag", labelPrefix,
		"--json",
	)
	out, err := b.Runner.Run(ctx, "restic", args...)
	if err != nil {
		return nil, fmt.Errorf("restic: list %s: %w", target, err)
	}
	return parseResticSnapshots(out, target)
}

// parseResticBackupID scans the line-delimited JSON emitted by
// `restic backup --json`. Each line is one JSON object; the final
// `message_type:"summary"` line carries snapshot_id.
func parseResticBackupID(out []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	id := ""
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var msg struct {
			MessageType string `json:"message_type"`
			SnapshotID  string `json:"snapshot_id"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		if msg.MessageType == "summary" && msg.SnapshotID != "" {
			id = msg.SnapshotID
		}
	}
	return id
}

// parseResticSnapshots decodes the JSON array emitted by
// `restic snapshots --json` and filters to entries whose paths contain
// target. The label is recovered from the bulwark- prefixed tag when
// present.
func parseResticSnapshots(out []byte, target string) ([]Snapshot, error) {
	type resticSnapshot struct {
		ID    string    `json:"id"`
		Time  time.Time `json:"time"`
		Paths []string  `json:"paths"`
		Tags  []string  `json:"tags"`
	}
	var raws []resticSnapshot
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&raws); err != nil {
		return nil, fmt.Errorf("restic: parse snapshots json: %w", err)
	}

	clean := strings.TrimSuffix(target, "/")
	matches := func(paths []string) bool {
		for _, p := range paths {
			if strings.TrimSuffix(p, "/") == clean {
				return true
			}
		}
		return false
	}

	var result []Snapshot
	for _, s := range raws {
		if !matches(s.Paths) {
			continue
		}
		label := ""
		for _, tag := range s.Tags {
			if !strings.HasPrefix(tag, labelPrefix+"-") {
				continue
			}
			if lab, _, ok := parseSnapshotName(tag); ok {
				label = lab
				break
			}
		}
		result = append(result, Snapshot{
			ID:        s.ID,
			Target:    target,
			Label:     label,
			CreatedAt: s.Time,
		})
	}
	return result, nil
}
