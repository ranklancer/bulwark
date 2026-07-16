package configstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileName is the basename of the on-disk encrypted blob.
const FileName = "config.enc"

// dataVersion is the schema version of the stored JSON. Bumped when a
// migration is required; readers tolerant of older versions migrate on
// load, then re-persist at the current version.
const dataVersion = 1

// Data is the in-memory representation of the encrypted store. New
// UI-managed sections get added here as their phases land.
type Data struct {
	Version    int                          `json:"version"`
	Notifiers  []NotifierEntry              `json:"notifiers,omitempty"`
	Settings   SettingsOverride             `json:"settings,omitempty"`
	Containers map[string]ContainerOverride `json:"containers,omitempty"`
}

// Store is a thread-safe, AES-GCM-encrypted JSON file store.
type Store struct {
	path string
	aead cipher.AEAD

	mu   sync.RWMutex
	data Data
}

// Open reads the encrypted store from <dataDir>/config.enc, decrypting it
// with the key at <dataDir>/config.key (generated on first use). When the
// .enc file does not exist yet, an empty store is returned and persisted
// on the next Save() — this lets callers treat Open() as a constructor
// that always returns a usable Store.
func Open(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("configstore: data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("configstore: mkdir %s: %w", dataDir, err)
	}
	key, err := LoadOrGenerateKey(dataDir)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("configstore: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("configstore: build gcm: %w", err)
	}
	s := &Store{path: filepath.Join(dataDir, FileName), aead: aead, data: Data{Version: dataVersion}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Snapshot returns a deep copy of the current store data, safe for the
// caller to mutate without affecting the live store.
func (s *Store) Snapshot() Data {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.clone()
}

// Notifiers returns a copy of the current notifier list.
func (s *Store) Notifiers() []NotifierEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NotifierEntry, len(s.data.Notifiers))
	copy(out, s.data.Notifiers)
	return out
}

// FindNotifier returns the notifier with the given ID. The second return
// value reports whether a match was found.
func (s *Store) FindNotifier(id string) (NotifierEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.data.Notifiers {
		if n.ID == id {
			return n, true
		}
	}
	return NotifierEntry{}, false
}

// load reads and decrypts the on-disk blob into s.data. A missing file is
// treated as "empty store" (not an error). Any decrypt failure is
// surfaced unchanged — the operator likely lost the key file and needs
// to recover from backup.
func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("configstore: read %s: %w", s.path, err)
	}
	if len(raw) < s.aead.NonceSize() {
		return fmt.Errorf("configstore: %s is shorter than the GCM nonce — file is truncated or corrupt", s.path)
	}
	nonce := raw[:s.aead.NonceSize()]
	ciphertext := raw[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("configstore: decrypt %s (wrong key, or file corrupted): %w", s.path, err)
	}
	var d Data
	if err := json.Unmarshal(plain, &d); err != nil {
		return fmt.Errorf("configstore: decode %s: %w", s.path, err)
	}
	if d.Version == 0 {
		d.Version = dataVersion
	}
	s.data = d
	return nil
}

// Save persists the current in-memory data to disk, atomically (tmp file
// + rename) and encrypted under the AEAD key.
func (s *Store) Save() error {
	s.mu.RLock()
	plain, err := json.Marshal(s.data)
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("configstore: encode: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("configstore: nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nonce, nonce, plain, nil)
	return writeAtomic(s.path, ciphertext, 0o600)
}

// Mutate runs fn under the write lock, passing a pointer to the live Data
// so callers can append/edit/remove entries. If fn returns an error,
// nothing is persisted and the in-memory state is left unchanged. On
// success the new state is encrypted and saved atomically, then a fresh
// snapshot is returned.
func (s *Store) Mutate(fn func(*Data) error) (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	working := s.data.clone()
	if err := fn(&working); err != nil {
		return Data{}, err
	}
	prev := s.data
	s.data = working

	plain, err := json.Marshal(s.data)
	if err != nil {
		s.data = prev
		return Data{}, fmt.Errorf("configstore: encode: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		s.data = prev
		return Data{}, fmt.Errorf("configstore: nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nonce, nonce, plain, nil)
	if err := writeAtomic(s.path, ciphertext, 0o600); err != nil {
		s.data = prev
		return Data{}, err
	}
	return s.data.clone(), nil
}

func (d Data) clone() Data {
	out := Data{Version: d.Version, Settings: d.Settings.clone()}
	if len(d.Notifiers) > 0 {
		out.Notifiers = make([]NotifierEntry, len(d.Notifiers))
		copy(out.Notifiers, d.Notifiers)
	}
	if len(d.Containers) > 0 {
		out.Containers = make(map[string]ContainerOverride, len(d.Containers))
		for k, v := range d.Containers {
			out.Containers[k] = v
		}
	}
	return out
}

// writeAtomic writes data to path via a tmp-file-and-rename so a partial
// write never replaces a valid existing file in place.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("configstore: create tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("configstore: write tmp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("configstore: chmod tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("configstore: close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("configstore: rename tmp: %w", err)
	}
	return nil
}
