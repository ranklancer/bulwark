package main

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// minimalScanFixture returns a scanDeps + a recording notifier for a single
// container that has a digest movement (so it'll classify as an LSIO rebuild).
func minimalScanFixture(t *testing.T, st *store.Store, fixedNow time.Time) (scanDeps, *recordingNotifier) {
	t.Helper()
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
	return scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Now:       func() time.Time { return fixedNow },
	}, rec
}

func TestScan_DedupSilencesRepeatNotificationsWithinTTL(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	deps, rec := minimalScanFixture(t, st, now)

	// First scan: notification dispatches.
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatalf("first scan: %v\nstderr: %s", err, stderr.String())
	}
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Fatalf("first scan calls = %d, want 1", got)
	}

	// Second scan, 1 hour later: dedup must silence.
	deps.Now = func() time.Time { return now.Add(time.Hour) }
	stdout.Reset()
	stderr.Reset()
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("second scan calls = %d, want 1 (dedup must silence within TTL)", got)
	}
	if !strings.Contains(stdout.String(), "silenced by dedup") {
		t.Errorf("dedup summary missing from output:\n%s", stdout.String())
	}

	// Third scan, 25 hours later: TTL elapsed, must re-notify.
	deps.Now = func() time.Time { return now.Add(25 * time.Hour) }
	stdout.Reset()
	stderr.Reset()
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 2 {
		t.Errorf("third scan calls = %d, want 2 (TTL must re-notify)", got)
	}
}

func TestScan_DedupTTLZeroDisablesSilencing(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	deps, rec := minimalScanFixture(t, st, now)

	// Two back-to-back scans with TTL=0.
	for i := 0; i < 2; i++ {
		var stdout, stderr bytes.Buffer
		if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify", "--dedup-ttl", "0"},
			&stdout, &stderr, deps); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&rec.calls); got != 2 {
		t.Errorf("ttl=0 calls = %d, want 2 (dedup must be disabled)", got)
	}
}

func TestScan_DedupEscalationBypassesSilencing(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

	// First scan: REVIEW-level update.
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "app", Image: "ghcr.io/owner/app:1.2.3", ImageID: "sha256:l",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l": {RepoDigests: []string{"ghcr.io/owner/app@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/app:1.2.3": "sha256:new",
	}}
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	// Force REVIEW via a label.
	fd.containers[0].Labels = map[string]string{"bulwark.risk": "review"}
	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Now:       func() time.Time { return now },
	}

	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if atomic.LoadInt32(&rec.calls) != 1 {
		t.Fatal("first scan should have dispatched")
	}

	// Second scan, 1 hour later, label escalated to BREAKING. Within the TTL,
	// dedup should normally silence — but escalation must override.
	fd.containers[0].Labels = map[string]string{"bulwark.risk": "breaking"}
	deps.Now = func() time.Time { return now.Add(time.Hour) }

	stdout.Reset()
	stderr.Reset()
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 2 {
		t.Errorf("escalation calls = %d, want 2 (escalation must bypass dedup TTL)", got)
	}
}

func TestScan_RecordsHistoryWhenStoreProvided(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	deps, _ := minimalScanFixture(t, st, now)

	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color"},
		&stdout, &stderr, deps); err != nil {
		t.Fatalf("scan: %v", err)
	}

	scans, err := st.ListScans(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("history len = %d, want 1", len(scans))
	}
	if scans[0].Summary.Total != 1 || scans[0].Summary.Pending != 1 {
		t.Errorf("summary unexpected: %+v", scans[0].Summary)
	}
}

func TestScan_DispatchFailureLeavesNoMark(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "sonarr",
			Image: "lscr.io/linuxserver/sonarr:4.0.10-ls45", ImageID: "sha256:l1",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45": "sha256:new",
	}}
	bad := &alwaysFail{name: "bad"}
	deps := scanDeps{
		Docker: fd, Registry: fr,
		Notifiers: []notifier.Notifier{bad},
		Store:     st,
		Now:       func() time.Time { return now },
	}
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith([]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps); err != nil {
		t.Fatal(err)
	}
	// Failed dispatch must not pollute the dedup state — next scan should
	// re-attempt rather than silencing.
	entries, _ := st.ListNotifications()
	if len(entries) != 0 {
		t.Errorf("dedup should be empty after dispatch failure, got %+v", entries)
	}
}
