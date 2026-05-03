package store

import (
	"errors"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestAudit_AppendsAndReadsNewestFirst(t *testing.T) {
	s := openTestStore(t)
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		s.Audit(AuditEvent{
			Time:      base.Add(time.Duration(i) * time.Second),
			Action:    ActionDecisionRecorded,
			Container: "sonarr",
			Actor:     "alice",
		})
	}
	got, err := s.ReadAudit(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	// Newest first.
	if !got[0].Time.After(got[1].Time) || !got[1].Time.After(got[2].Time) {
		t.Errorf("not newest-first: %v", []time.Time{got[0].Time, got[1].Time, got[2].Time})
	}
}

func TestAudit_LimitTruncates(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 5; i++ {
		s.Audit(AuditEvent{Action: "x", Time: time.Unix(int64(i), 0)})
	}
	got, err := s.ReadAudit(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("limit=2 returned %d", len(got))
	}
}

func TestAudit_MissingFileNotAnError(t *testing.T) {
	s := openTestStore(t)
	got, err := s.ReadAudit(0)
	if err != nil {
		t.Fatalf("missing audit log should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestAudit_NilStoreNoOp(t *testing.T) {
	var s *Store
	s.Audit(AuditEvent{Action: "x"}) // must not panic
	got, err := s.ReadAudit(0)
	if err != nil || got != nil {
		t.Errorf("nil ReadAudit = (%v, %v)", got, err)
	}
}

func TestAudit_RecordDecision_ProducesEntry(t *testing.T) {
	s := openTestStore(t)
	if err := s.RecordDecision(ApprovalRecord{
		ApprovalKey:   ApprovalKey{ContainerID: "abc", RegistryDigest: "sha256:x"},
		ContainerName: "sonarr",
		Decision:      DecisionApproved,
		DecidedBy:     "alice",
		Note:          "tested",
		Level:         types.RiskReview,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ReadAudit(0)
	if len(got) != 1 {
		t.Fatalf("expected 1 audit event from RecordDecision, got %d", len(got))
	}
	e := got[0]
	if e.Action != ActionDecisionRecorded {
		t.Errorf("Action = %q", e.Action)
	}
	if e.Actor != "alice" || e.Container != "sonarr" || e.Note != "tested" {
		t.Errorf("event = %+v", e)
	}
	if !errors.Is(error(nil), nil) { // keep errors import alive
		t.Skip()
	}
}

func TestAudit_ClearAuditWritesTombstone(t *testing.T) {
	s := openTestStore(t)
	s.Audit(AuditEvent{Action: "before-clear"})
	if err := s.ClearAudit("alice"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ReadAudit(0)
	if len(got) != 1 || got[0].Action != "audit.cleared" || got[0].Actor != "alice" {
		t.Errorf("expected single tombstone after clear, got %+v", got)
	}
}
