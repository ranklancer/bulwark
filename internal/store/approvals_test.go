package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestApprovalDecision_RoundTripJSON(t *testing.T) {
	cases := []ApprovalDecision{DecisionUnknown, DecisionApproved, DecisionRejected}
	for _, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out ApprovalDecision
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if out != in {
			t.Errorf("round-trip %v → %s → %v", in, b, out)
		}
	}
}

func TestApprovalDecision_UnmarshalLegacyNumeric(t *testing.T) {
	var d ApprovalDecision
	if err := json.Unmarshal([]byte("1"), &d); err != nil {
		t.Fatal(err)
	}
	if d != DecisionApproved {
		t.Errorf("legacy numeric 1 = %v, want Approved", d)
	}
}

func TestRecordDecision_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	rec := ApprovalRecord{
		ApprovalKey:   ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:abc"},
		ContainerName: "sonarr",
		Image:         "lscr.io/linuxserver/sonarr:4.0.10",
		Decision:      DecisionApproved,
		Note:          "tested in dev",
		DecidedBy:     "alice",
		DecidedAt:     time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC),
		Level:         types.RiskReview,
		From:          "4.0.9", To: "4.0.10",
	}
	if err := s.RecordDecision(rec); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	got, err := s.LookupDecision(rec.ApprovalKey)
	if err != nil {
		t.Fatalf("LookupDecision: %v", err)
	}
	if got == nil {
		t.Fatal("got nil after recording")
	}
	if got.Decision != DecisionApproved {
		t.Errorf("decision = %v", got.Decision)
	}
	if got.Note != "tested in dev" {
		t.Errorf("note = %q", got.Note)
	}
	if got.DecidedBy != "alice" {
		t.Errorf("decided_by = %q", got.DecidedBy)
	}
}

func TestRecordDecision_OverwritesExisting(t *testing.T) {
	s := openTestStore(t)
	key := ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:abc"}

	_ = s.RecordDecision(ApprovalRecord{
		ApprovalKey: key, ContainerName: "sonarr", Decision: DecisionApproved,
	})
	_ = s.RecordDecision(ApprovalRecord{
		ApprovalKey: key, ContainerName: "sonarr", Decision: DecisionRejected,
	})

	got, _ := s.LookupDecision(key)
	if got == nil || got.Decision != DecisionRejected {
		t.Errorf("expected most-recent decision (rejected), got %+v", got)
	}
	all, _ := s.ListApprovals()
	if len(all) != 1 {
		t.Errorf("expected 1 entry after overwrite, got %d", len(all))
	}
}

func TestRecordDecision_RejectsMissingKey(t *testing.T) {
	s := openTestStore(t)
	err := s.RecordDecision(ApprovalRecord{Decision: DecisionApproved})
	if err == nil {
		t.Error("expected error when ContainerID/RegistryDigest are empty")
	}
}

func TestRecordDecision_RejectsUnknownDecision(t *testing.T) {
	s := openTestStore(t)
	err := s.RecordDecision(ApprovalRecord{
		ApprovalKey: ApprovalKey{ContainerID: "x", RegistryDigest: "y"},
	})
	if err == nil {
		t.Error("expected error when Decision is Unknown")
	}
}

func TestLookupDecision_Missing(t *testing.T) {
	s := openTestStore(t)
	got, err := s.LookupDecision(ApprovalKey{ContainerID: "nope", RegistryDigest: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil for missing key, got %+v", got)
	}
}

func TestForgetDecision_RemovesAndReportsMissing(t *testing.T) {
	s := openTestStore(t)
	key := ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:abc"}
	_ = s.RecordDecision(ApprovalRecord{ApprovalKey: key, Decision: DecisionApproved})

	if err := s.ForgetDecision(key); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if err := s.ForgetDecision(key); !errors.Is(err, ErrNotFound) {
		t.Errorf("second forget: %v, want ErrNotFound", err)
	}
}

func TestClearApprovals_Empties(t *testing.T) {
	s := openTestStore(t)
	_ = s.RecordDecision(ApprovalRecord{
		ApprovalKey: ApprovalKey{ContainerID: "a", RegistryDigest: "x"}, Decision: DecisionApproved,
	})
	_ = s.RecordDecision(ApprovalRecord{
		ApprovalKey: ApprovalKey{ContainerID: "b", RegistryDigest: "y"}, Decision: DecisionRejected,
	})
	if err := s.ClearApprovals(); err != nil {
		t.Fatal(err)
	}
	all, _ := s.ListApprovals()
	if len(all) != 0 {
		t.Errorf("clear left %d entries", len(all))
	}
}

func TestApprovals_PersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1, _ := Open(dir)
	_ = s1.RecordDecision(ApprovalRecord{
		ApprovalKey: ApprovalKey{ContainerID: "x", RegistryDigest: "y"},
		Decision:    DecisionApproved,
	})
	_ = s1.Close()

	s2, _ := Open(dir)
	got, err := s2.LookupDecision(ApprovalKey{ContainerID: "x", RegistryDigest: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Decision != DecisionApproved {
		t.Errorf("after reopen: got %+v, want Approved", got)
	}
}

func TestApprovals_NilReceiverIsNoop(t *testing.T) {
	var s *Store
	if err := s.RecordDecision(ApprovalRecord{
		ApprovalKey: ApprovalKey{ContainerID: "x", RegistryDigest: "y"},
		Decision:    DecisionApproved,
	}); err != nil {
		t.Errorf("nil store RecordDecision should not error: %v", err)
	}
	got, err := s.LookupDecision(ApprovalKey{ContainerID: "x", RegistryDigest: "y"})
	if err != nil || got != nil {
		t.Errorf("nil store LookupDecision = (%v, %v), want (nil, nil)", got, err)
	}
}
