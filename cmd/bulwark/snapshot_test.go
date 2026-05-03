package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/snapshot"
)

// fakeSnapshotBackend records every call. Each method's behaviour is
// programmable via the matching field — tests set them per-case.
type fakeSnapshotBackend struct {
	available  bool
	listResult []snapshot.Snapshot
	listErr    error
	restoreErr error
	destroyErr error
	calls      []string
}

func (f *fakeSnapshotBackend) Name() string                         { return "fake" }
func (f *fakeSnapshotBackend) Available(_ context.Context) bool     { return f.available }
func (f *fakeSnapshotBackend) Snapshot(_ context.Context, t, l string) (string, error) {
	f.calls = append(f.calls, "snapshot "+t+" "+l)
	return "id-of-" + t, nil
}
func (f *fakeSnapshotBackend) Restore(_ context.Context, id string) error {
	f.calls = append(f.calls, "restore "+id)
	return f.restoreErr
}
func (f *fakeSnapshotBackend) Destroy(_ context.Context, id string) error {
	f.calls = append(f.calls, "destroy "+id)
	return f.destroyErr
}
func (f *fakeSnapshotBackend) List(_ context.Context, target string) ([]snapshot.Snapshot, error) {
	f.calls = append(f.calls, "list "+target)
	return f.listResult, f.listErr
}

func TestCmdSnapshot_NoArgsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(nil, &stdout, &stderr, snapshotDeps{})
	if !errors.Is(err, errUsage) {
		t.Errorf("err = %v, want errUsage", err)
	}
	if !strings.Contains(stderr.String(), "Subcommands:") {
		t.Errorf("usage not printed: %s", stderr.String())
	}
}

func TestCmdSnapshot_UnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith([]string{"reticulate"}, &stdout, &stderr, snapshotDeps{})
	if !errors.Is(err, errUsage) {
		t.Errorf("err = %v, want errUsage", err)
	}
	if !strings.Contains(stderr.String(), "unknown snapshot subcommand") {
		t.Errorf("error message missing: %s", stderr.String())
	}
}

func TestCmdSnapshot_ListEmpty(t *testing.T) {
	be := &fakeSnapshotBackend{}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"list", "/var/lib/sonarr"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(stdout.String(), "no snapshots recorded for /var/lib/sonarr") {
		t.Errorf("missing empty marker: %s", stdout.String())
	}
}

func TestCmdSnapshot_ListPrintsTable(t *testing.T) {
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	be := &fakeSnapshotBackend{
		listResult: []snapshot.Snapshot{
			{ID: "abc123", Target: "/var/lib/sonarr", Label: "sonarr", CreatedAt: now},
			{ID: "def456", Target: "/var/lib/sonarr", Label: "sonarr", CreatedAt: now.Add(time.Hour)},
		},
	}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"list", "/var/lib/sonarr"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"ID", "CREATED", "abc123", "def456", "/var/lib/sonarr"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestCmdSnapshot_ListJSON(t *testing.T) {
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	be := &fakeSnapshotBackend{
		listResult: []snapshot.Snapshot{
			{ID: "abc123", Target: "/var/lib/sonarr", Label: "sonarr", CreatedAt: now},
		},
	}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"list", "--json", "/var/lib/sonarr"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var rows []struct {
		ID     string `json:"id"`
		Target string `json:"target"`
		Label  string `json:"label"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatalf("invalid json: %v\noutput: %s", err, stdout.String())
	}
	if len(rows) != 1 || rows[0].ID != "abc123" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestCmdSnapshot_RestoreRequiresConfirmation(t *testing.T) {
	be := &fakeSnapshotBackend{}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"restore", "abc123"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err == nil {
		t.Fatal("destructive restore without --yes should fail")
	}
	if len(be.calls) != 0 {
		t.Errorf("backend should not have been called; calls = %v", be.calls)
	}
}

func TestCmdSnapshot_RestoreWithYes(t *testing.T) {
	be := &fakeSnapshotBackend{}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"restore", "--yes", "abc123"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(be.calls) != 1 || be.calls[0] != "restore abc123" {
		t.Errorf("calls = %v", be.calls)
	}
	if !strings.Contains(stdout.String(), "restored") {
		t.Errorf("missing success line: %s", stdout.String())
	}
}

func TestCmdSnapshot_PruneRequiresConfirmation(t *testing.T) {
	be := &fakeSnapshotBackend{}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"prune", "abc123"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err == nil {
		t.Fatal("destructive prune without --yes should fail")
	}
	if len(be.calls) != 0 {
		t.Errorf("backend should not have been called; calls = %v", be.calls)
	}
}

func TestCmdSnapshot_PruneWithYes(t *testing.T) {
	be := &fakeSnapshotBackend{}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"prune", "--yes", "abc123"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(be.calls) != 1 || be.calls[0] != "destroy abc123" {
		t.Errorf("calls = %v", be.calls)
	}
}

func TestCmdSnapshot_ListErrorPropagates(t *testing.T) {
	be := &fakeSnapshotBackend{listErr: errors.New("repository unreachable")}
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"list", "/var/lib/sonarr"},
		&stdout, &stderr,
		snapshotDeps{Backend: be},
	)
	if err == nil {
		t.Fatal("list error should propagate")
	}
}

func TestCmdSnapshot_NoBackendNoConfig(t *testing.T) {
	// No injected backend AND no --config: clear error, not a panic.
	var stdout, stderr bytes.Buffer
	err := cmdSnapshotWith(
		[]string{"list", "/var/lib/sonarr"},
		&stdout, &stderr,
		snapshotDeps{},
	)
	if err == nil {
		t.Fatal("missing config should fail")
	}
	if !strings.Contains(err.Error(), "config is required") {
		t.Errorf("err message %q", err.Error())
	}
}
