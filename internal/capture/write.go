package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/registry"
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
	// Host-file trust boundary: WritePin is the point where a digest actually
	// lands in an operator's compose file. ProposePin already validates the
	// digest, but re-assert fail-closed here so a hand-built or drifted
	// Proposal can never splice a non-digest-pinned reference.
	if at := strings.LastIndex(p.NewValue, "@"); at < 0 || !registry.IsSHA256Digest(strings.ToLower(p.NewValue[at+1:])) {
		return res, fmt.Errorf("capture: WritePin refusing to splice %q — not a sha256 digest-pinned reference", p.NewValue)
	}
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return res, fmt.Errorf("capture: read %s: %w", p.Path, err)
	}
	newContent, noOp, err := spliceImageValue(string(data), p.Line, p.OldValue, p.NewValue)
	if err != nil {
		return res, fmt.Errorf("capture: %s: %w", p.Path, err)
	}
	if noOp {
		res.NoOp = true
		return res, nil
	}
	backupPath, err := s.backup(p.Path, data)
	if err != nil {
		return res, err
	}
	res.BackupPath = backupPath
	if err := atomicWrite(p.Path, newContent); err != nil {
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

// spliceImageValue replaces oldValue with newValue in the "image:" scalar on
// 1-based line lineNo of content, preserving every other byte (indentation,
// quotes, comments, line terminators). It is the single splice implementation
// shared by every write path — file adapters and API/DB-managed adapters — so
// the format-preserving, drift-checked edit can never diverge between them.
//
// Returns (newContent, noOp, err). noOp is true when the line already carries
// newValue (idempotent). It is fail-closed on drift: the target line must still
// be an image: line that contains oldValue, else an error is returned and
// nothing is spliced.
func spliceImageValue(content string, lineNo int, oldValue, newValue string) (string, bool, error) {
	return spliceValueOnLine(content, lineNo, "image:", oldValue, newValue)
}

// spliceValueOnLine replaces oldValue with newValue in the scalar that follows
// key on 1-based line lineNo of content, preserving every other byte. It is the
// single, format-agnostic splice shared by every write path (compose "image:",
// quadlet "Image=", …) so the drift-checked edit can never diverge between them.
func spliceValueOnLine(content string, lineNo int, key, oldValue, newValue string) (string, bool, error) {
	parts := strings.SplitAfter(content, "\n")
	idx := lineNo - 1
	if idx < 0 || idx >= len(parts) {
		return "", false, fmt.Errorf("line %d out of range — content changed since propose", lineNo)
	}
	orig := parts[idx]
	keyIdx := strings.Index(orig, key)
	if keyIdx < 0 {
		return "", false, fmt.Errorf("line %d is no longer a %s line — content changed since propose", lineNo, strings.TrimRight(key, ":="))
	}
	after := orig[keyIdx+len(key):]
	if strings.Contains(after, newValue) {
		return content, true, nil // already pinned to this exact value
	}
	vIdx := strings.Index(after, oldValue)
	if vIdx < 0 {
		return "", false, fmt.Errorf("line %d no longer contains %q — refusing (content changed since propose)", lineNo, oldValue)
	}
	parts[idx] = orig[:keyIdx+len(key)] + after[:vIdx] + newValue + after[vIdx+len(oldValue):]
	return strings.Join(parts, ""), false, nil
}
