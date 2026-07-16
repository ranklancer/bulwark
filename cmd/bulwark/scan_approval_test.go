package main

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/pkg/types"
)

// approvalScanFixture is the same single-container update used elsewhere.
func approvalScanFixture(t *testing.T) (*store.Store, scanDeps, *recordingNotifier) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "sonarr",
			Image:   "lscr.io/linuxserver/sonarr:4.0.10-ls45",
			ImageID: "sha256:l1",
			Labels:  map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45": "sha256:new",
	}}
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}
	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}
	return st, deps, rec
}

func TestScan_ApprovedDecisionSilencesNotification(t *testing.T) {
	st, deps, rec := approvalScanFixture(t)

	// First scan: notification fires.
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if atomic.LoadInt32(&rec.calls) != 1 {
		t.Fatalf("first scan calls = %d, want 1", rec.calls)
	}

	// User decides about that exact (container, digest).
	if err := st.RecordDecision(store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:new"},
		Decision:    store.DecisionApproved,
	}); err != nil {
		t.Fatal(err)
	}

	// Second scan: even with TTL=0 (dedup disabled), the recorded decision
	// must silence the notification.
	stdout.Reset()
	stderr.Reset()
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify", "--dedup-ttl", "0"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("second scan calls = %d, want 1 (approval must silence regardless of TTL)", got)
	}
	if !strings.Contains(stdout.String(), "silenced by recorded decision") {
		t.Errorf("expected approval-silenced summary line, got:\n%s", stdout.String())
	}
}

func TestScan_RejectedDecisionAlsoSilences(t *testing.T) {
	st, deps, rec := approvalScanFixture(t)

	// Pre-record a rejection BEFORE the first scan.
	if err := st.RecordDecision(store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:new"},
		Decision:    store.DecisionRejected,
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 0 {
		t.Errorf("rejected decision should silence; got %d notifier calls", got)
	}
}

func TestScan_NewDigestReopensDecidedContainer(t *testing.T) {
	st, deps, rec := approvalScanFixture(t)

	// Approve sha256:new.
	if err := st.RecordDecision(store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:new"},
		Decision:    store.DecisionApproved,
	}); err != nil {
		t.Fatal(err)
	}
	// Mutate the registry to advertise yet another digest.
	deps.Registry.(*fakeRegistry).digests["lscr.io/linuxserver/sonarr:4.0.10-ls45"] = "sha256:newer"

	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("new digest must re-open the question; got %d calls", got)
	}
	// The old approval is still there but irrelevant; verify that's the case.
	old, _ := st.LookupDecision(store.ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:new"})
	if old == nil {
		t.Errorf("old approval should still be on disk (orphaned but harmless)")
	}
}
