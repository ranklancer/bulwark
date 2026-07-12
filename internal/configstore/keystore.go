// Package configstore persists UI-mutable Bulwark configuration (notifiers,
// editable settings sections) as an AES-GCM-encrypted JSON blob at
// <datadir>/config.enc. The encryption key lives in <datadir>/config.key
// (mode 0600, generated on first use). The yaml file remains the bootstrap
// + advanced override path; this store layers on top of it for sections an
// operator wants to manage via the dashboard.
//
// Why encrypted on disk: notifier configs carry secrets (Slack/Discord
// webhook URLs, SMTP passwords, Home Assistant tokens). The yaml path
// already accepts ${ENV_VAR} substitution so the file itself never sees
// the plaintext; once we move those values into a daemon-owned file we
// have to defend them in turn. AES-GCM with a per-install random key gives
// confidentiality + integrity; the threat model is "someone with read
// access to <datadir>/config.enc but not the matching .key file".
//
// Why a plain file + atomic rename (vs. sqlite): data volume is small,
// writes are rare, and the existing internal/store/ package already
// demonstrates the same JSON-on-disk pattern works well for Bulwark.
// Adding sqlite would mean ~3 MB of binary weight (modernc.org/sqlite)
// or CGO, both unwelcome at this stage.
package configstore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// KeyFileName is the basename of the on-disk key file. Kept exported so
// tests + operators have a single source of truth.
const KeyFileName = "config.key"

// KeyLen is the AES-256-GCM key size in bytes.
const KeyLen = 32

// LoadOrGenerateKey returns the AES key from <dataDir>/config.key, creating
// a fresh 32-byte random key if the file does not yet exist. Existing files
// are validated for size (a wrong-size file is treated as corruption — fail
// loud rather than risk silent data loss).
//
// The created file is written with mode 0600 and parents are not created;
// the caller is expected to have ensured dataDir exists (Open() handles
// this for the canonical entrypoint).
func LoadOrGenerateKey(dataDir string) ([]byte, error) {
	if dataDir == "" {
		return nil, errors.New("configstore: data directory is required")
	}
	path := filepath.Join(dataDir, KeyFileName)
	data, err := os.ReadFile(path) // #nosec G304 -- bulwark's own keystore under the data dir
	if err == nil {
		if len(data) != KeyLen {
			return nil, fmt.Errorf("configstore: key file %s has wrong size (%d bytes; expected %d) — refusing to proceed", path, len(data), KeyLen)
		}
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("configstore: read key file: %w", err)
	}
	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("configstore: generate key: %w", err)
	}
	if err := writeKeyAtomic(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// writeKeyAtomic writes key bytes to path via a tmp-file-and-rename
// sequence so a partial write never leaves an unreadable file in place.
// File mode is set to 0600 before the rename so the final visible file
// is never world-readable, even briefly.
func writeKeyAtomic(path string, key []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "config.key.*.tmp")
	if err != nil {
		return fmt.Errorf("configstore: create key tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("configstore: write key tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("configstore: chmod key tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("configstore: close key tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("configstore: rename key tmp: %w", err)
	}
	return nil
}
