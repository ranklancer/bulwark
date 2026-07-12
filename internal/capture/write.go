package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WritePin applies a Proposal to the compose file IN PLACE, safely (the digest-pin capture design §5.6):
//   - idempotent: a no-op proposal, or a file already carrying NewValue, writes nothing;
//   - refuse-on-drift: the target line must still be an "image:" line carrying OldValue;
//   - backup: the original bytes are copied to BackupDir before any write;
//   - atomic: a temp file in the same dir is fsync'd and renamed over the original;
//   - format/comment preserving: only the image scalar on the target line changes,
//     leaving indentation, quotes, key order, comments, and every other byte intact.
func (s *ComposeSource) WritePin(_ context.Context, p Proposal) (Applied, error) {
	res := Applied{Path: p.Path, Line: p.Line, OldValue: p.OldValue, NewValue: p.NewValue}
	if p.NoOp {
		res.NoOp = true
		return res, nil
	}
	if p.Path == "" || p.Line <= 0 {
		return res, fmt.Errorf("capture: WritePin needs a Proposal with Path and Line (got %q line %d)", p.Path, p.Line)
	}
	if p.OldValue == "" || p.NewValue == "" {
		return res, fmt.Errorf("capture: WritePin: empty old/new image value")
	}
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return res, fmt.Errorf("capture: read %s: %w", p.Path, err)
	}
	// SplitAfter keeps line terminators, so a plain join is byte-identical.
	parts := strings.SplitAfter(string(data), "\n")
	idx := p.Line - 1
	if idx < 0 || idx >= len(parts) {
		return res, fmt.Errorf("capture: %s: line %d out of range — file changed since propose", p.Path, p.Line)
	}
	orig := parts[idx]
	keyIdx := strings.Index(orig, "image:")
	if keyIdx < 0 {
		return res, fmt.Errorf("capture: %s line %d is no longer an image: line — file changed since propose", p.Path, p.Line)
	}
	after := orig[keyIdx+len("image:"):]
	if strings.Contains(after, p.NewValue) {
		res.NoOp = true // already pinned to this exact digest
		return res, nil
	}
	vIdx := strings.Index(after, p.OldValue)
	if vIdx < 0 {
		return res, fmt.Errorf("capture: %s line %d no longer contains %q — refusing (file changed since propose)", p.Path, p.Line, p.OldValue)
	}
	parts[idx] = orig[:keyIdx+len("image:")] + after[:vIdx] + p.NewValue + after[vIdx+len(p.OldValue):]

	backupPath, err := s.backup(p.Path, data)
	if err != nil {
		return res, err
	}
	res.BackupPath = backupPath
	if err := atomicWrite(p.Path, strings.Join(parts, "")); err != nil {
		return res, err
	}
	return res, nil
}

// backup copies the original bytes to a timestamped file under BackupDir (or a
// .bulwark-pin-backups directory beside the compose file when BackupDir is empty).
func (s *ComposeSource) backup(path string, data []byte) (string, error) {
	dir := s.BackupDir
	if dir == "" {
		dir = filepath.Join(filepath.Dir(path), ".bulwark-pin-backups")
	}
	bdir := filepath.Join(dir, stackName(path))
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		return "", fmt.Errorf("capture: backup dir %s: %w", bdir, err)
	}
	bpath := filepath.Join(bdir, time.Now().UTC().Format("20060102T150405Z")+"-"+filepath.Base(path))
	if err := os.WriteFile(bpath, data, 0o600); err != nil {
		return "", fmt.Errorf("capture: write backup %s: %w", bpath, err)
	}
	return bpath, nil
}

// Rollback restores a backup over targetPath atomically (byte-for-byte).
func Rollback(backupPath, targetPath string) error {
	data, err := os.ReadFile(backupPath) // #nosec G304 -- backupPath is bulwark's own backup written by WritePin, not attacker input
	if err != nil {
		return fmt.Errorf("capture: read backup %s: %w", backupPath, err)
	}
	return atomicWrite(targetPath, string(data))
}

// atomicWrite writes content to path via a same-dir temp file + fsync + rename,
// so a crash mid-write never leaves a partially-written compose file. It
// preserves the destination's existing file mode.
func atomicWrite(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bulwark-pin-*.tmp")
	if err != nil {
		return fmt.Errorf("capture: temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if fi, statErr := os.Stat(path); statErr == nil {
		_ = os.Chmod(tmpName, fi.Mode().Perm())
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("capture: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("capture: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("capture: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("capture: rename temp over %s: %w", path, err)
	}
	return nil
}
