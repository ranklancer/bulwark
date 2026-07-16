package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/pkg/types"
)

func newPopulatedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		_, err := st.RecordScan(store.ScanRecord{
			StartedAt:  ts,
			FinishedAt: ts.Add(time.Second),
			Summary:    store.ScanSummary{Total: 1, Pending: 1, Review: 1},
			Results: []store.ScanResultRecord{{
				ContainerName:   "app",
				Image:           "ghcr.io/owner/app:1.0.0",
				UpdateAvailable: true,
				Level:           types.RiskReview,
				Kind:            types.ChangeMinor,
				From:            "1.0.0", To: "1.1.0",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = st.MarkNotified(
		store.NotificationKey{ContainerID: "app", RegistryDigest: "sha256:abc"},
		store.NotificationRecord{Level: types.RiskReview, ContainerName: "app"},
		base,
	)
	return st
}

func TestCmdHistoryList_Text(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"list"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatalf("history list: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"STARTED", "TOTAL", "PENDING"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	// 3 data rows + 1 header = 4 lines minimum
	if got := strings.Count(out, "\n"); got < 4 {
		t.Errorf("expected at least 4 lines, got %d:\n%s", got, out)
	}
}

func TestCmdHistoryList_JSON(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"list", "--json"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatalf("history list --json: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode json: %v\n%s", err, stdout.String())
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

func TestCmdHistoryList_LimitTruncates(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"list", "--json", "--limit", "2"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	_ = json.Unmarshal(stdout.Bytes(), &got)
	if len(got) != 2 {
		t.Errorf("limit ignored: got %d records", len(got))
	}
}

func TestCmdHistoryShow_LatestResolves(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"show", "latest"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatalf("history show latest: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"Scan ", "started:", "summary:", "app", "REVIEW"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestCmdHistoryShow_RequiresArg(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"show"}, &stdout, &stderr,
		historyDeps{Store: st}); err == nil {
		t.Error("expected error when ID is missing")
	}
}

func TestCmdHistoryShow_UnknownID(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"show", "nonexistent"}, &stdout, &stderr,
		historyDeps{Store: st}); err == nil {
		t.Error("expected error for unknown ID")
	}
}

func TestCmdHistoryClear_RemovesDedupState(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"clear"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatalf("history clear: %v", err)
	}
	if !strings.Contains(stdout.String(), "1 notification") {
		t.Errorf("expected count of 1 cleared, got: %s", stdout.String())
	}
	entries, _ := st.ListNotifications()
	if len(entries) != 0 {
		t.Errorf("notifications not cleared: %+v", entries)
	}
}

func TestCmdHistoryPrune_TrimsToKeep(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"prune", "--keep", "1"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatalf("history prune: %v", err)
	}
	scans, _ := st.ListScans(0)
	if len(scans) != 1 {
		t.Errorf("post-prune scans = %d, want 1", len(scans))
	}
	if !strings.Contains(stdout.String(), "pruned 2") {
		t.Errorf("expected 'pruned 2' in output, got: %s", stdout.String())
	}
}

func TestCmdHistoryPrune_NoOpWhenUnderThreshold(t *testing.T) {
	st := newPopulatedStore(t)
	var stdout, stderr bytes.Buffer
	if err := cmdHistoryWith([]string{"prune", "--keep", "10"}, &stdout, &stderr,
		historyDeps{Store: st}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "nothing to prune") {
		t.Errorf("expected 'nothing to prune', got: %s", stdout.String())
	}
}

func TestCmdHistory_NoArgsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := cmdHistoryWith(nil, &stdout, &stderr, historyDeps{})
	if err == nil {
		t.Error("expected usage error when no subcommand")
	}
	if !strings.Contains(stderr.String(), "Subcommands") {
		t.Errorf("expected usage in stderr, got: %s", stderr.String())
	}
}
