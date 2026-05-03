package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// AuditEvent is one append-only entry in the audit log. Persisted as
// newline-delimited JSON in `<datadir>/audit.jsonl` so a `tail -f`
// integration is trivial — no schema gymnastics required for the
// sysadmin who wants to follow what Bulwark did last night.
type AuditEvent struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // see Action* constants below
	Actor  string    `json:"actor,omitempty"`
	// Container / Image / Decision / Note / Level surface a stable shape
	// across action types so downstream tooling (jq, grafana-loki, etc.)
	// can filter without per-action conditional logic.
	Container string           `json:"container,omitempty"`
	Image     string           `json:"image,omitempty"`
	Decision  ApprovalDecision `json:"decision,omitempty"`
	Note      string           `json:"note,omitempty"`
	Level     types.RiskLevel  `json:"level,omitempty"`
	Digest    string           `json:"digest,omitempty"`
	// Detail captures action-specific extras (apply outcome counts,
	// rollback reasons, etc.) that don't fit the structured fields.
	Detail string `json:"detail,omitempty"`
}

// Audit action vocabulary. Stable strings — operators and dashboards
// filter on these.
const (
	ActionDecisionRecorded = "decision.recorded"
	ActionDecisionForgot   = "decision.forgot"
	ActionDecisionsCleared = "decisions.cleared"
	ActionDedupCleared     = "dedup.cleared"
	ActionApplied          = "apply.success"
	ActionAppliedFailed    = "apply.failed"
	ActionRolledBack       = "apply.rolled_back"
	ActionScanRecorded     = "scan.recorded"
)

// auditPath is where the JSONL log lives.
func (s *Store) auditPath() string { return filepath.Join(s.DataDir, "audit.jsonl") }

// Audit appends an event to the log. Errors are non-fatal as far as the
// caller's primary work is concerned — we don't want a full disk to take
// down the daemon mid-update — so this method ALWAYS returns nil after
// best-effort write. Errors land in stderr via the slog default logger.
//
// A nil receiver is a no-op so callers can pass nil unconditionally to
// opt out of audit logging.
func (s *Store) Audit(e AuditEvent) {
	if s == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	} else {
		e.Time = e.Time.UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		// Marshal failures should be impossible for our schema; log
		// and move on so the caller's primary action isn't affected.
		return
	}
	line = append(line, '\n')
	f, err := os.OpenFile(s.auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// ReadAudit returns up to limit most-recent audit events, newest-first.
// Returns nil + nil when the file doesn't exist (no events yet).
//
// We read the whole file and slice — for a homelab daemon writing maybe
// a few hundred events per day this is fine; if anyone hits a
// performance ceiling on this, the right answer is rotation, not
// streaming. Document that rotation is the operator's responsibility
// (logrotate / systemd-journald-style — Bulwark only writes).
func (s *Store) ReadAudit(limit int) ([]AuditEvent, error) {
	if s == nil {
		return nil, nil
	}
	f, err := os.Open(s.auditPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: open audit log: %w", err)
	}
	defer f.Close()

	var events []AuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// Don't fail the entire read on a malformed line — log
			// position would be useful but isn't critical. Skip.
			continue
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		return events, fmt.Errorf("store: scan audit log: %w", err)
	}
	// Newest-first ordering: simple in-place reverse.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// ClearAudit truncates the audit log. Used by `bulwark history clear` and
// kindred housekeeping — but ALWAYS records its own ClearAudit event
// first so the log has a tombstone showing the intentional truncation.
func (s *Store) ClearAudit(actor string) error {
	if s == nil {
		return nil
	}
	if err := os.Truncate(s.auditPath(), 0); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store: truncate audit log: %w", err)
	}
	// Re-create with the tombstone.
	s.Audit(AuditEvent{Action: "audit.cleared", Actor: actor})
	return nil
}
