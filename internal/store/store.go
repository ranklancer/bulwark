// Package store persists Bulwark's small set of stateful artifacts:
// notification de-duplication memory and scan history.
//
// The current implementation is a flat JSON-on-disk store. It's deliberate:
// the data shape is small and simple (lookups by composite key, append-only
// scan log with retention), so the cost of pulling in SQLite isn't justified
// yet. The interface (NotificationsStore, HistoryStore) is designed so the
// implementation can be swapped for SQLite when the web UI's queries demand
// it, without changing callers.
//
// Concurrency: writes are atomic (tmp file + rename), but the package does
// not use file locking. Two concurrent processes mutating the same store
// can clobber each other's last write. In practice Bulwark is run from cron
// or interactively — not both at once — so this is an acceptable trade-off
// for stdlib-only storage. Upgrade to SQLite when this becomes a real issue.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound is returned by lookup methods when the requested record does
// not exist. It is exported so callers can distinguish "no record" from
// transport / decode errors.
var ErrNotFound = errors.New("store: not found")

// Store is the file-backed implementation of NotificationsStore + HistoryStore.
// It keeps two artifacts under DataDir:
//
//	<DataDir>/notifications.json     dedup map, single file
//	<DataDir>/history/scan-*.json    one file per recorded scan
//
// The directory is created on Open if it doesn't exist.
type Store struct {
	DataDir string

	// MaxHistory caps the number of retained scan files. Older files are
	// pruned during RecordScan. Zero or negative disables pruning.
	MaxHistory int
}

// Open prepares the data directory and returns a Store ready for use.
// dataDir must be a writable absolute or relative path; it is created
// (with parents) if it does not already exist.
func Open(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("store: data directory is required")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("store: resolve data dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "history"), 0o755); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	return &Store{DataDir: abs, MaxHistory: 100}, nil
}

// Close releases any held resources. The current file-based implementation
// holds nothing beyond per-call file handles, so this is a no-op — but the
// method exists so callers can adopt the future SQLite-backed Store without
// changing call sites.
func (s *Store) Close() error { return nil }

// notificationsPath returns the path to the dedup state file.
func (s *Store) notificationsPath() string {
	return filepath.Join(s.DataDir, "notifications.json")
}

// historyDir returns the directory holding per-scan record files.
func (s *Store) historyDir() string {
	return filepath.Join(s.DataDir, "history")
}

// writeAtomic writes data to path via a tmp file + rename, so an interrupted
// write never leaves a half-written file in place. tmp lives in the same
// directory as path so the rename is on the same filesystem.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bulwark-tmp-*")
	if err != nil {
		return fmt.Errorf("store: create tmp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// If we failed before rename, clean up the orphan tmp.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: write tmp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: chmod tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("store: rename tmp: %w", err)
	}
	return nil
}
