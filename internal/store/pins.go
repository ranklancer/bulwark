package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PinRecord is one captured digest pin (the digest-pin capture design §5.3). It records the
// authoritative index digest plus enough provenance to audit, detect drift,
// and roll back. No secrets or credentials are ever stored here.
type PinRecord struct {
	Ref         string   `json:"ref"`                    // e.g. "nginx:1.27"
	IndexDigest string   `json:"index_digest"`           // sha256:<index>
	MediaType   string   `json:"media_type,omitempty"`   // manifest media type
	Arches      []string `json:"arches,omitempty"`       // platforms an index advertises
	Source      string   `json:"source,omitempty"`       // adapter kind/name (e.g. "file:dockge-main")
	ComposePath string   `json:"compose_path,omitempty"` // file adapters
	BackupPath  string   `json:"backup_path,omitempty"`  // for rollback
	Service     string   `json:"service,omitempty"`
	CapturedAt  string   `json:"captured_at"`
	CanaryState string   `json:"canary_state,omitempty"` // candidate|canary|promoted|rolled-back
}

type pinsFile struct {
	Version int                  `json:"version"`
	Pins    map[string]PinRecord `json:"pins"`
}

const pinsSchemaVersion = 1

// Canary states (the digest-pin capture design §6.2): candidate -> canary -> promoted, with
// rolled-back as the failure terminal.
const (
	CanaryCandidate  = "candidate"
	CanaryActive     = "canary"
	CanaryPromoted   = "promoted"
	CanaryRolledBack = "rolled-back"
)

// PinStore persists captured pins as a versioned JSON file under the data dir
// (the digest-pin capture design §8.3). Keys are "<stack>/<service>". Writes are atomic (tmp+rename).
// A nil-safe zero value is not valid; construct with OpenPinStore.
type PinStore struct {
	path string
	mu   sync.Mutex
}

// OpenPinStore returns a PinStore backed by <dataDir>/pins.json.
func OpenPinStore(dataDir string) *PinStore {
	return &PinStore{path: filepath.Join(dataDir, "pins.json")}
}

// load reads and parses the pins file. A missing file is a legitimate,
// error-free empty store (case 2 of the 3-case pin-state model: nothing has
// ever been captured yet). A file that exists but cannot be read or parsed
// returns a non-nil error (case 3: the pin state is UNKNOWN, not "empty") --
// callers MUST propagate that distinction rather than collapsing it into
// not-found. See Get.
func (s *PinStore) load() (pinsFile, error) {
	pf := pinsFile{Version: pinsSchemaVersion, Pins: map[string]PinRecord{}}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return pf, nil
		}
		return pf, fmt.Errorf("store: read pins: %w", err)
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		return pf, fmt.Errorf("store: parse pins: %w", err)
	}
	if pf.Pins == nil {
		pf.Pins = map[string]PinRecord{}
	}
	return pf, nil
}

func (s *PinStore) save(pf pinsFile) error {
	pf.Version = pinsSchemaVersion
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode pins: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("store: pins dir: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: write pins tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("store: rename pins: %w", err)
	}
	return nil
}

// Set upserts a pin record. CapturedAt defaults to now (UTC) when unset.
func (s *PinStore) Set(key string, rec PinRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pf, err := s.load()
	if err != nil {
		return err
	}
	if rec.CapturedAt == "" {
		rec.CapturedAt = time.Now().UTC().Format(time.RFC3339)
	}
	pf.Pins[key] = rec
	return s.save(pf)
}

// Get returns the pin for key, distinguishing three outcomes (the admission-gate design
// fail-closed pin-state model):
//
//  1. ok=true, err=nil:  key is pinned; rec is populated.
//  2. ok=false, err=nil: the store loaded fine (including a store that does
//     not exist yet -- a fresh install) but genuinely has no pin recorded
//     for key. This is legitimate not-found; existing --pin-mode policy
//     (warn/off/block) applies unchanged.
//  3. ok=false, err!=nil: the store's underlying file exists but could not
//     be read or parsed (corruption, bad permissions, a writer crashing
//     mid-rename, etc.). The pin state for key is UNKNOWN -- callers MUST
//     NOT treat this the same as case 2. Callers that gate a security
//     decision on pin state (cmd/bulwark/admit.go) must fail closed on a
//     non-nil error regardless of any configured enforcement mode.
func (s *PinStore) Get(key string) (PinRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pf, err := s.load()
	if err != nil {
		return PinRecord{}, false, err
	}
	r, ok := pf.Pins[key]
	return r, ok, nil
}

// List returns all pins keyed by "<stack>/<service>".
func (s *PinStore) List() (map[string]PinRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pf, err := s.load()
	if err != nil {
		return nil, err
	}
	return pf.Pins, nil
}
