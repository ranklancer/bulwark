package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// ScanRecord is the persisted form of a complete scan run.
type ScanRecord struct {
	ID         string             `json:"id"` // unique, derived from StartedAt
	StartedAt  time.Time          `json:"started_at"`
	FinishedAt time.Time          `json:"finished_at"`
	Host       string             `json:"host,omitempty"`
	Summary    ScanSummary        `json:"summary"`
	Results    []ScanResultRecord `json:"results"`
}

// ScanSummary is the aggregate view used by `bulwark history` listings.
type ScanSummary struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Breaking int `json:"breaking"`
	Review   int `json:"review"`
	Safe     int `json:"safe"`
	Skipped  int `json:"skipped"`
	Errored  int `json:"errored"`
}

// ScanResultRecord is the persisted form of a single per-container scan
// result. We keep it independent from internal/scanner.Result so the store
// package doesn't depend on scanner — that would create an import cycle as
// soon as the scanner ever needs to talk to the store directly.
type ScanResultRecord struct {
	ContainerID    string           `json:"container_id"`
	ContainerName  string           `json:"container_name"`
	Image          string           `json:"image"`
	ComposeProject string           `json:"compose_project,omitempty"`
	Skipped        bool             `json:"skipped,omitempty"`
	SkipReason     string           `json:"skip_reason,omitempty"`
	UpdateAvailable bool            `json:"update_available"`
	LocalDigest    string           `json:"local_digest,omitempty"`
	RegistryDigest string           `json:"registry_digest,omitempty"`
	Level          types.RiskLevel  `json:"level,omitempty"`
	Kind           types.ChangeKind `json:"kind,omitempty"`
	Confidence     types.Confidence `json:"confidence,omitempty"`
	From           string           `json:"from,omitempty"`
	To             string           `json:"to,omitempty"`
	Rationale      string           `json:"rationale,omitempty"`
	NotesSource    string           `json:"notes_source,omitempty"`
	ReleaseURL     string           `json:"release_url,omitempty"`
	Error          string           `json:"error,omitempty"`
}

const (
	historyFilePrefix = "scan-"
	historyFileSuffix = ".json"
	historySchemaVersion = 1
)

// historyFile is the on-disk wire shape. Versioned for forward-compat.
type historyFile struct {
	Version int        `json:"version"`
	Record  ScanRecord `json:"record"`
}

// RecordScan persists the given record and prunes older history files past
// the retention limit. A nil receiver is a no-op so callers can pass nil
// unconditionally to opt out of history.
func (s *Store) RecordScan(rec ScanRecord) (ScanRecord, error) {
	if s == nil {
		return rec, nil
	}
	if rec.ID == "" {
		// We use start-time + nanosecond fraction as the ID. It's
		// deterministic, sortable, and safe to embed in a filename.
		rec.ID = rec.StartedAt.UTC().Format("20060102T150405.000000000Z")
		rec.ID = strings.ReplaceAll(rec.ID, ".", "")
		rec.ID = strings.ReplaceAll(rec.ID, ":", "")
	}
	body, err := json.MarshalIndent(historyFile{
		Version: historySchemaVersion,
		Record:  rec,
	}, "", "  ")
	if err != nil {
		return rec, fmt.Errorf("store: encode scan: %w", err)
	}
	path := filepath.Join(s.historyDir(), historyFilePrefix+rec.ID+historyFileSuffix)
	if err := writeAtomic(path, body, 0o644); err != nil {
		return rec, err
	}
	if s.MaxHistory > 0 {
		if _, err := s.pruneHistory(s.MaxHistory); err != nil {
			// Pruning failures shouldn't fail the record itself; log via
			// the returned error to let the caller decide.
			return rec, fmt.Errorf("store: prune history: %w", err)
		}
	}
	return rec, nil
}

// pruneHistory deletes the oldest scan files beyond keep most-recent records.
// Returns the number of files removed.
func (s *Store) pruneHistory(keep int) (int, error) {
	files, err := s.listHistoryFiles()
	if err != nil {
		return 0, err
	}
	if len(files) <= keep {
		return 0, nil
	}
	// listHistoryFiles returns newest-first; everything past `keep` is excess.
	removed := 0
	for _, f := range files[keep:] {
		if err := os.Remove(filepath.Join(s.historyDir(), f)); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// PruneHistory exposes pruneHistory for direct use by `bulwark history prune`.
// It returns the number of scan records removed.
func (s *Store) PruneHistory(keep int) (int, error) {
	if s == nil {
		return 0, nil
	}
	return s.pruneHistory(keep)
}

// listHistoryFiles returns scan filenames sorted newest-first.
func (s *Store) listHistoryFiles() ([]string, error) {
	entries, err := os.ReadDir(s.historyDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read history dir: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, historyFilePrefix) || !strings.HasSuffix(name, historyFileSuffix) {
			continue
		}
		out = append(out, name)
	}
	// Filenames embed sortable timestamps, so lexical reverse-sort = newest-first.
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// ListScans returns up to limit most-recent scan summaries (ID + Summary +
// timestamps), without loading the full per-container results. Pass 0 to
// return all retained records.
func (s *Store) ListScans(limit int) ([]ScanRecord, error) {
	if s == nil {
		return nil, nil
	}
	files, err := s.listHistoryFiles()
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(files) > limit {
		files = files[:limit]
	}
	out := make([]ScanRecord, 0, len(files))
	for _, name := range files {
		rec, err := s.readHistory(name)
		if err != nil {
			return out, err
		}
		// The filename is the canonical handle GetScan expects. Rewrite
		// rec.ID from the filename so it survives any drift between the
		// JSON's embedded id and disk reality (hand-edited files, future
		// schema migrations, partial writes, etc.) — without this, a
		// drifted record would appear in `bulwark history list` but
		// vanish on `bulwark history show <id>`.
		rec.ID = strings.TrimSuffix(strings.TrimPrefix(name, historyFilePrefix), historyFileSuffix)
		// Strip Results — listings only need the summary. Callers that want
		// full detail should call GetScan with the ID.
		rec.Results = nil
		out = append(out, rec)
	}
	return out, nil
}

// validScanID matches the alphabet of IDs the store actually produces:
// digits, letters, dots (RFC3339-style timestamps), dashes, underscores.
// Anything else is a sign of misuse — including the path-traversal payload
// "../etc/passwd" — and is rejected at this boundary so no caller can
// bypass the check by passing through the wrong layer.
var validScanID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ErrInvalidScanID is returned by GetScan when the supplied id contains
// characters that would let it escape the history directory (slashes,
// dot-dot segments, NUL bytes, etc.). Distinct from ErrNotFound so
// callers can map it to a 400 instead of a 404.
var ErrInvalidScanID = errors.New("store: scan id contains invalid characters")

// GetScan returns the full record with the given ID, or ErrNotFound.
// Returns ErrInvalidScanID when the id is malformed.
func (s *Store) GetScan(id string) (*ScanRecord, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	if id == "" {
		return nil, errors.New("store: scan ID is required")
	}
	if !validScanID.MatchString(id) {
		return nil, ErrInvalidScanID
	}
	rec, err := s.readHistory(historyFilePrefix + id + historyFileSuffix)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) readHistory(filename string) (ScanRecord, error) {
	path := filepath.Join(s.historyDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("store: read scan: %w", err)
	}
	var f historyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return ScanRecord{}, fmt.Errorf("store: decode scan %s: %w", filename, err)
	}
	return f.Record, nil
}
