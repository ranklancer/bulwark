package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/pkg/types"
)

func TestCmdAudit_Empty(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	var stdout, stderr bytes.Buffer
	if err := cmdAuditWith(nil, &stdout, &stderr, auditDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "no audit events") {
		t.Errorf("expected empty-state message, got: %s", stdout.String())
	}
}

func TestCmdAudit_Text(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	st.Audit(store.AuditEvent{
		Action: store.ActionDecisionRecorded, Actor: "alice", Container: "sonarr",
		Decision: store.DecisionApproved, Level: types.RiskReview,
	})
	st.Audit(store.AuditEvent{
		Action: store.ActionApplied, Container: "sonarr",
		Detail: "lscr.io/.../sonarr:1 → :2",
	})
	var stdout, stderr bytes.Buffer
	if err := cmdAuditWith(nil, &stdout, &stderr, auditDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"TIME", "ACTION", "alice", "sonarr", "decision.recorded", "apply.success"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output\n%s", want, out)
		}
	}
}

func TestCmdAudit_JSONLines(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	st.Audit(store.AuditEvent{Action: store.ActionDecisionRecorded, Container: "sonarr"})
	var stdout, stderr bytes.Buffer
	if err := cmdAuditWith([]string{"--json"}, &stdout, &stderr, auditDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	// JSON-Lines: one event per line.
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var got store.AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("decode: %v\nline: %s", err, lines[0])
	}
	if got.Action != store.ActionDecisionRecorded {
		t.Errorf("Action = %q", got.Action)
	}
}

func TestCmdAudit_LimitTruncates(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	for i := 0; i < 5; i++ {
		st.Audit(store.AuditEvent{Action: store.ActionDecisionRecorded})
	}
	var stdout, stderr bytes.Buffer
	if err := cmdAuditWith([]string{"--limit", "2", "--json"}, &stdout, &stderr,
		auditDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines with --limit=2, got %d", len(lines))
	}
}

func TestCmdAudit_DataDirRequiredWhenNoStoreInjected(t *testing.T) {
	t.Setenv("BULWARK_DATA_DIR", "")
	var stdout, stderr bytes.Buffer
	if err := cmdAuditWith(nil, &stdout, &stderr, auditDeps{}); err == nil {
		t.Error("expected error when neither --data-dir nor injected Store is given")
	}
}
