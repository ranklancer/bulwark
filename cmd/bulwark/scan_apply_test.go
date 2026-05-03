package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/updater"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// stubUpdaterDocker satisfies updater.DockerClient. The real *updater.Updater
// is wrapped around it so we exercise the actual recreate dance against an
// in-memory simulation rather than mocking out the orchestrator.
type stubUpdaterDocker struct {
	pulls    int32
	stops    int32
	starts   int32
	creates  int32
	removes  int32
	renames  int32
	inspects int32

	failPull bool

	// containers stores containers by ID. Fresh containers added by
	// CreateContainer end up here too.
	containers map[string]*docker.ContainerInspect

	// Once a container is started, this controls the health each
	// inspect returns. Use docker.HealthHealthy for a successful apply.
	startupHealth docker.HealthStatus
}

func (s *stubUpdaterDocker) PullImage(_ context.Context, _ string) error {
	atomic.AddInt32(&s.pulls, 1)
	if s.failPull {
		return errors.New("manifest unknown")
	}
	return nil
}
func (s *stubUpdaterDocker) InspectContainer(_ context.Context, id string) (*docker.ContainerInspect, error) {
	atomic.AddInt32(&s.inspects, 1)
	return s.containers[id], nil
}
func (s *stubUpdaterDocker) StopContainer(_ context.Context, _ string, _ int) error {
	atomic.AddInt32(&s.stops, 1)
	return nil
}
func (s *stubUpdaterDocker) StartContainer(_ context.Context, id string) error {
	atomic.AddInt32(&s.starts, 1)
	if c, ok := s.containers[id]; ok {
		c.Running = true
		c.Health = s.startupHealth
	}
	return nil
}
func (s *stubUpdaterDocker) RemoveContainer(_ context.Context, _ string, _ bool) error {
	atomic.AddInt32(&s.removes, 1)
	return nil
}
func (s *stubUpdaterDocker) RenameContainer(_ context.Context, id, newName string) error {
	atomic.AddInt32(&s.renames, 1)
	if c, ok := s.containers[id]; ok {
		c.Name = "/" + newName
	}
	return nil
}
func (s *stubUpdaterDocker) CreateContainer(_ context.Context, name string, _ docker.CreateContainerConfig) (string, error) {
	atomic.AddInt32(&s.creates, 1)
	id := "new-" + name
	s.containers[id] = &docker.ContainerInspect{
		ID:      id,
		Name:    "/" + name,
		Running: false,
		Health:  docker.HealthNone,
		Config:  json.RawMessage(`{"Image":"x"}`),
	}
	return id, nil
}

func TestScanApply_SafeUpdate_AppliesAndAdjustsAction(t *testing.T) {
	// Scan finds a SAFE update for a container. With --apply, the updater
	// runs and the resulting notification carries Action=AutoUpdated.

	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "sonarr",
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

	stubDoc := &stubUpdaterDocker{
		startupHealth: docker.HealthHealthy,
		containers: map[string]*docker.ContainerInspect{
			"old-id": {
				ID:              "old-id",
				Name:            "/sonarr",
				ImageRef:        "lscr.io/linuxserver/sonarr:4.0.10-ls45",
				Running:         true,
				Health:          docker.HealthNone,
				Config:          json.RawMessage(`{"Image":"lscr.io/linuxserver/sonarr:4.0.10-ls45","Env":["TZ=UTC"]}`),
				HostConfig:      json.RawMessage(`{"Binds":["/data:/data"]}`),
				NetworkSettings: json.RawMessage(`{"Networks":{"media":{}}}`),
			},
		},
	}
	upd := &updater.Updater{
		Docker:         stubDoc,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		StartupGrace:   1 * time.Millisecond,
	}

	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Updater:   upd,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}
	var stdout, stderr bytes.Buffer
	err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify", "--apply"},
		&stdout, &stderr, deps,
	)
	if err != nil {
		t.Fatalf("scan: %v\nstderr: %s", err, stderr.String())
	}

	if got := atomic.LoadInt32(&stubDoc.pulls); got != 1 {
		t.Errorf("pulls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&stubDoc.creates); got != 1 {
		t.Errorf("creates = %d, want 1", got)
	}
	// The notification dispatched must reflect AutoUpdated action.
	if len(rec.got) != 1 {
		t.Fatalf("dispatched events = %d, want 1; output: %s", len(rec.got), stdout.String())
	}
	if rec.got[0].Action != types.ActionAutoUpdated {
		t.Errorf("event action = %v, want AutoUpdated", rec.got[0].Action)
	}
}

func TestScanApply_BreakingDoesNotApply(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "auth", Image: "ghcr.io/owner/auth:1.0",
			ImageID: "sha256:l", Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l": {RepoDigests: []string{"ghcr.io/owner/auth@sha256:old"}},
		},
	}
	// Tag jump from 1.0 → 2.0 is a major bump → BREAKING.
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/auth:1.0": "sha256:new",
	}}
	// To produce a major-bump scenario, we need scan to see a different
	// target tag. The scanner reads container.Image and asks the registry
	// for that exact tag. So we have to simulate by changing the running
	// image's tag. Easier: just use a label override to force RiskBreaking.
	fd.containers[0].Labels = map[string]string{"bulwark.risk": "breaking"}

	stubDoc := &stubUpdaterDocker{}
	upd := &updater.Updater{Docker: stubDoc}

	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Updater:   upd,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify", "--apply"},
		&stdout, &stderr, deps,
	); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&stubDoc.pulls); got != 0 {
		t.Errorf("BREAKING must not auto-apply; pulls = %d, want 0", got)
	}
}

func TestScanApply_ReviewWithoutApprovalDoesNotApply(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "app", Image: "ghcr.io/owner/app:1.0",
			ImageID: "sha256:l",
			Labels:  map[string]string{"bulwark.risk": "review"}, // force REVIEW
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l": {RepoDigests: []string{"ghcr.io/owner/app@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/app:1.0": "sha256:new",
	}}

	stubDoc := &stubUpdaterDocker{}
	upd := &updater.Updater{Docker: stubDoc}

	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Updater:   upd,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify", "--apply"},
		&stdout, &stderr, deps,
	); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&stubDoc.pulls); got != 0 {
		t.Errorf("REVIEW without approval must not auto-apply; pulls = %d, want 0", got)
	}
}

func TestScanApply_ReviewWithApprovalApplies(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	// Pre-approve the (container, digest) pair.
	if err := st.RecordDecision(store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{
			ContainerID: "app", RegistryDigest: "sha256:new",
		},
		Decision: store.DecisionApproved,
	}); err != nil {
		t.Fatal(err)
	}

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "app", Image: "ghcr.io/owner/app:1.0",
			ImageID: "sha256:l",
			Labels:  map[string]string{"bulwark.risk": "review"},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l": {RepoDigests: []string{"ghcr.io/owner/app@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/app:1.0": "sha256:new",
	}}

	stubDoc := &stubUpdaterDocker{
		startupHealth: docker.HealthHealthy,
		containers: map[string]*docker.ContainerInspect{
			"old-id": {
				ID:              "old-id",
				Name:            "/app",
				ImageRef:        "ghcr.io/owner/app:1.0",
				Running:         true,
				Health:          docker.HealthNone,
				Config:          json.RawMessage(`{"Image":"ghcr.io/owner/app:1.0"}`),
				HostConfig:      json.RawMessage(`{}`),
				NetworkSettings: json.RawMessage(`{"Networks":{}}`),
			},
		},
	}
	upd := &updater.Updater{
		Docker:         stubDoc,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		StartupGrace:   1 * time.Millisecond,
	}

	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Updater:   upd,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify", "--apply"},
		&stdout, &stderr, deps,
	); err != nil {
		t.Fatalf("scan: %v\nstderr: %s", err, stderr.String())
	}
	if got := atomic.LoadInt32(&stubDoc.pulls); got != 1 {
		t.Errorf("approved REVIEW must auto-apply; pulls = %d, want 1", got)
	}
	// However: filterByApproval drops decided events from notifications,
	// so the recorder shouldn't have been called.
	if got := atomic.LoadInt32(&rec.calls); got != 0 {
		t.Errorf("approved decisions silence notifications; calls = %d, want 0", got)
	}
}

func TestScanApply_DryRunRecordsNoMutation(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "sonarr",
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
	stubDoc := &stubUpdaterDocker{}
	upd := &updater.Updater{Docker: stubDoc}
	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Updater:   upd,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}

	var stdout, stderr bytes.Buffer
	if err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify", "--apply", "--dry-run"},
		&stdout, &stderr, deps,
	); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Updater must NOT have been invoked at all.
	if stubDoc.pulls != 0 || stubDoc.creates != 0 || stubDoc.stops != 0 {
		t.Errorf("dry-run leaked mutations: pulls=%d creates=%d stops=%d",
			stubDoc.pulls, stubDoc.creates, stubDoc.stops)
	}
	// Notification still goes out, with AutoUpdated action (synthetic).
	if len(rec.got) != 1 || rec.got[0].Action != types.ActionAutoUpdated {
		t.Errorf("expected one synthetic AutoUpdated event, got %+v", rec.got)
	}
	// Audit log carries the dry-run tombstone.
	events, _ := st.ReadAudit(0)
	found := false
	for _, e := range events {
		if e.Action == store.ActionApplied && e.Detail == "dry-run" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dry-run audit event, got %+v", events)
	}
}

func TestScanApply_HealthFailureRollsBack(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "sonarr",
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

	// Health timeline: pre-recreate inspect returns None; later inspects
	// return Unhealthy → rollback path.
	stubDoc := &stubUpdaterDocker{
		startupHealth: docker.HealthUnhealthy,
		containers: map[string]*docker.ContainerInspect{
			"old-id": {
				ID:              "old-id",
				Name:            "/sonarr",
				ImageRef:        "lscr.io/linuxserver/sonarr:4.0.10-ls45",
				Running:         true,
				Health:          docker.HealthNone,
				Config:          json.RawMessage(`{"Image":"lscr.io/linuxserver/sonarr:4.0.10-ls45"}`),
				HostConfig:      json.RawMessage(`{}`),
				NetworkSettings: json.RawMessage(`{"Networks":{}}`),
			},
		},
	}
	upd := &updater.Updater{
		Docker:         stubDoc,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		StartupGrace:   1 * time.Millisecond,
	}

	deps := scanDeps{
		Docker:    fd,
		Registry:  fr,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Updater:   upd,
		Now:       func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
	}
	var stdout, stderr bytes.Buffer
	if err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify", "--apply"},
		&stdout, &stderr, deps,
	); err != nil {
		t.Fatalf("scan: %v\nstderr: %s", err, stderr.String())
	}
	// Rollback flow: stop new, remove new, rename old back, start old.
	if got := atomic.LoadInt32(&stubDoc.removes); got < 1 {
		t.Errorf("rollback should have removed the new container; removes = %d", got)
	}
	// The notification reflects ROLLBACK action.
	if len(rec.got) != 1 || rec.got[0].Action != types.ActionRolledBack {
		t.Errorf("expected one ROLLBACK notification, got %+v", rec.got)
	}
}
