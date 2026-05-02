package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// ApprovalDecision records the user's verdict on a pending REVIEW update.
type ApprovalDecision int

const (
	DecisionUnknown  ApprovalDecision = iota
	DecisionApproved                  // user said yes (will be applied when orchestration arrives)
	DecisionRejected                  // user said skip this version
)

// String renders the decision for log/output use.
func (d ApprovalDecision) String() string {
	switch d {
	case DecisionApproved:
		return "approved"
	case DecisionRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// MarshalJSON renders DecisionApproved/Rejected as their string form so
// approvals.json is human-readable.
func (d ApprovalDecision) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON accepts the string form (current) and numeric form (legacy)
// so loaded data never breaks across schema evolution.
func (d *ApprovalDecision) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*d = DecisionUnknown
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		switch s {
		case "approved":
			*d = DecisionApproved
		case "rejected":
			*d = DecisionRejected
		default:
			*d = DecisionUnknown
		}
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = ApprovalDecision(n)
	return nil
}

// ApprovalKey uniquely identifies an approval record. Same shape as
// NotificationKey — they cover the same identity (container × image
// version), but live in separate maps so a user's approval choices aren't
// erased by ClearNotifications.
type ApprovalKey struct {
	ContainerID    string `json:"container_id"`
	RegistryDigest string `json:"registry_digest"`
}

// ApprovalRecord is the persisted form of one decision.
type ApprovalRecord struct {
	ApprovalKey
	ContainerName string           `json:"container_name,omitempty"`
	Image         string           `json:"image,omitempty"`
	Decision      ApprovalDecision `json:"decision"`
	Note          string           `json:"note,omitempty"`
	DecidedBy     string           `json:"decided_by,omitempty"`
	DecidedAt     time.Time        `json:"decided_at"`
	Level         types.RiskLevel  `json:"level,omitempty"`
	From          string           `json:"from,omitempty"`
	To            string           `json:"to,omitempty"`
}

const approvalsSchemaVersion = 1

type approvalsFile struct {
	Version int              `json:"version"`
	Entries []ApprovalRecord `json:"entries"`
}

func (s *Store) approvalsPath() string {
	return s.DataDir + "/approvals.json"
}

// loadApprovals reads the approvals file. A missing file is an empty store
// (not an error).
func (s *Store) loadApprovals() ([]ApprovalRecord, error) {
	data, err := os.ReadFile(s.approvalsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read approvals: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var f approvalsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("store: decode approvals: %w", err)
	}
	return f.Entries, nil
}

func (s *Store) saveApprovals(entries []ApprovalRecord) error {
	f := approvalsFile{Version: approvalsSchemaVersion, Entries: entries}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode approvals: %w", err)
	}
	return writeAtomic(s.approvalsPath(), data, 0o644)
}

// RecordDecision persists rec, updating any existing entry for the same key.
// A nil receiver is a no-op so callers can pass nil unconditionally to opt
// out of approval tracking.
func (s *Store) RecordDecision(rec ApprovalRecord) error {
	if s == nil {
		return nil
	}
	if rec.ContainerID == "" || rec.RegistryDigest == "" {
		return errors.New("store: RecordDecision requires ContainerID and RegistryDigest")
	}
	if rec.Decision == DecisionUnknown {
		return errors.New("store: RecordDecision requires a non-unknown decision")
	}
	if rec.DecidedAt.IsZero() {
		rec.DecidedAt = time.Now().UTC()
	}
	entries, err := s.loadApprovals()
	if err != nil {
		return err
	}
	found := false
	for i, e := range entries {
		if e.ApprovalKey != rec.ApprovalKey {
			continue
		}
		entries[i] = rec
		found = true
		break
	}
	if !found {
		entries = append(entries, rec)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].ContainerName != entries[j].ContainerName {
			return entries[i].ContainerName < entries[j].ContainerName
		}
		return entries[i].RegistryDigest < entries[j].RegistryDigest
	})
	return s.saveApprovals(entries)
}

// LookupDecision returns the persisted decision for key, or nil if no
// record exists. A nil receiver returns nil — callers can branch on the
// pointer to decide whether to apply approval semantics.
func (s *Store) LookupDecision(key ApprovalKey) (*ApprovalRecord, error) {
	if s == nil {
		return nil, nil
	}
	entries, err := s.loadApprovals()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.ApprovalKey == key {
			rec := e
			return &rec, nil
		}
	}
	return nil, nil
}

// ListApprovals returns every recorded decision, sorted by container name.
func (s *Store) ListApprovals() ([]ApprovalRecord, error) {
	if s == nil {
		return nil, nil
	}
	return s.loadApprovals()
}

// ForgetDecision removes a single decision. Returns ErrNotFound when the
// key is unknown.
func (s *Store) ForgetDecision(key ApprovalKey) error {
	if s == nil {
		return nil
	}
	entries, err := s.loadApprovals()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.ApprovalKey != key {
			continue
		}
		entries = append(entries[:i], entries[i+1:]...)
		return s.saveApprovals(entries)
	}
	return ErrNotFound
}

// ClearApprovals wipes every recorded decision.
func (s *Store) ClearApprovals() error {
	if s == nil {
		return nil
	}
	return s.saveApprovals(nil)
}
