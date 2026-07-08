package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// queueFixture seeds a store with one scan that has a pending REVIEW
// update for "sonarr" and one with a pending BREAKING for "auth".
func queueFixture(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.RecordScan(store.ScanRecord{
		StartedAt:  time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 5, 1, 9, 0, 5, 0, time.UTC),
		Summary:    store.ScanSummary{Total: 2, Pending: 2, Review: 1, Breaking: 1},
		Results: []store.ScanResultRecord{
			{
				ContainerName:   "sonarr",
				Image:           "lscr.io/linuxserver/sonarr:4.0.10",
				UpdateAvailable: true,
				Level:           types.RiskReview,
				Kind:            types.ChangeMinor,
				From:            "4.0.10", To: "4.1.0",
				RegistryDigest: "sha256:sonarrnew",
			},
			{
				ContainerName:   "auth",
				Image:           "ghcr.io/owner/auth:1.0",
				UpdateAvailable: true,
				Level:           types.RiskBreaking,
				Kind:            types.ChangeMajor,
				From:            "1.0", To: "2.0",
				RegistryDigest: "sha256:authmajor",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCmdQueueList_PendingFromLatestScan(t *testing.T) {
	st := queueFixture(t)
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"list"}, &stdout, &stderr,
		queueDeps{Store: st}); err != nil {
		t.Fatalf("queue list: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"CONTAINER", "sonarr", "auth", "pending"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestCmdQueueList_JSON(t *testing.T) {
	st := queueFixture(t)
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"list", "--json"}, &stdout, &stderr,
		queueDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if len(got) != 2 {
		t.Errorf("rows = %d, want 2", len(got))
	}
}

func TestCmdQueueApprove_RecordsDecisionAndSurfaces(t *testing.T) {
	st := queueFixture(t)
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith(
		[]string{"approve", "--note", "tested in dev", "--by", "alice", "sonarr"},
		&stdout, &stderr, queueDeps{Store: st}); err != nil {
		t.Fatalf("queue approve: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "approved: sonarr") {
		t.Errorf("expected confirmation, got: %s", stdout.String())
	}

	got, err := st.LookupDecision(store.ApprovalKey{
		ContainerID: "sonarr", RegistryDigest: "sha256:sonarrnew",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Decision != store.DecisionApproved {
		t.Errorf("decision not recorded; got %+v", got)
	}
	if got.Note != "tested in dev" || got.DecidedBy != "alice" {
		t.Errorf("metadata not preserved: %+v", got)
	}
}

func TestCmdQueueReject_AlsoWorks(t *testing.T) {
	st := queueFixture(t)
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"reject", "auth"}, &stdout, &stderr,
		queueDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.LookupDecision(store.ApprovalKey{
		ContainerID: "auth", RegistryDigest: "sha256:authmajor",
	})
	if got == nil || got.Decision != store.DecisionRejected {
		t.Errorf("expected rejected, got %+v", got)
	}
}

func TestCmdQueueApprove_UnknownContainer(t *testing.T) {
	st := queueFixture(t)
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"approve", "ghostly"}, &stdout, &stderr,
		queueDeps{Store: st}); err == nil {
		t.Error("expected error for unknown container")
	}
}

func TestCmdQueueApprove_NoScanHistory(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"approve", "anything"}, &stdout, &stderr,
		queueDeps{Store: st}); err == nil {
		t.Error("expected error when no scan history exists")
	} else if !strings.Contains(err.Error(), "scan history") {
		t.Errorf("error should mention scan history; got %v", err)
	}
}

func TestCmdQueueList_ReflectsRecordedDecision(t *testing.T) {
	st := queueFixture(t)
	// Approve sonarr first.
	var stdout, stderr bytes.Buffer
	_ = cmdQueueWith([]string{"approve", "sonarr"}, &stdout, &stderr,
		queueDeps{Store: st})
	stdout.Reset()
	stderr.Reset()
	// List should now show "approved" for sonarr.
	if err := cmdQueueWith([]string{"list", "--json"}, &stdout, &stderr,
		queueDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	_ = json.Unmarshal(stdout.Bytes(), &rows)
	for _, r := range rows {
		if r["container"] == "sonarr" && r["decision"] != "approved" {
			t.Errorf("sonarr decision = %v, want approved", r["decision"])
		}
	}
}

func TestCmdQueueForget_RemovesDecision(t *testing.T) {
	st := queueFixture(t)
	_ = cmdQueueWith([]string{"approve", "sonarr"}, &bytes.Buffer{}, &bytes.Buffer{},
		queueDeps{Store: st})

	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"forget", "sonarr"}, &stdout, &stderr,
		queueDeps{Store: st}); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if !strings.Contains(stdout.String(), "forgot 1") {
		t.Errorf("expected 'forgot 1' confirmation, got %q", stdout.String())
	}
	got, _ := st.LookupDecision(store.ApprovalKey{
		ContainerID: "sonarr", RegistryDigest: "sha256:sonarrnew",
	})
	if got != nil {
		t.Errorf("decision still present after forget: %+v", got)
	}
}

func TestCmdQueueClear_EmptiesAll(t *testing.T) {
	st := queueFixture(t)
	_ = cmdQueueWith([]string{"approve", "sonarr"}, &bytes.Buffer{}, &bytes.Buffer{}, queueDeps{Store: st})
	_ = cmdQueueWith([]string{"reject", "auth"}, &bytes.Buffer{}, &bytes.Buffer{}, queueDeps{Store: st})

	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith([]string{"clear"}, &stdout, &stderr,
		queueDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "cleared 2") {
		t.Errorf("expected 'cleared 2', got %q", stdout.String())
	}
	all, _ := st.ListApprovals()
	if len(all) != 0 {
		t.Errorf("approvals not cleared: %+v", all)
	}
}

func TestCmdQueue_NoArgsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := cmdQueueWith(nil, &stdout, &stderr, queueDeps{}); err == nil {
		t.Error("expected usage error on no subcommand")
	}
	if !strings.Contains(stderr.String(), "Subcommands") {
		t.Errorf("expected usage in stderr, got %q", stderr.String())
	}
}
