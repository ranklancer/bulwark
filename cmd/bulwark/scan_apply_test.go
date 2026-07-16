package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/updater"
	"github.com/ranklancer/bulwark/pkg/types"
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

	// pullOrder records the image references passed to PullImage in the
	// order they arrived. Tests assert on this to verify Phase 12
	// dependency-first ordering.
	pullMu    sync.Mutex
	pullOrder []string
}

func (s *stubUpdaterDocker) PullImage(_ context.Context, ref string) error {
	atomic.AddInt32(&s.pulls, 1)
	s.pullMu.Lock()
	s.pullOrder = append(s.pullOrder, ref)
	s.pullMu.Unlock()
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

// composeStackFixture builds the (fakeDocker, fakeRegistry, stubUpdaterDocker)
// triple for a given list of compose-aware container specs. Each spec is
// (name, project, dependsOn, oldDigest, newDigest). All containers in the
// fixture share the same stub updater, which means startupHealth applies
// uniformly — fine for stack tests where we want the WHOLE stack to either
// roll back together or all succeed.
type composeSpec struct {
	name      string
	project   string
	dependsOn string // raw label value, e.g. "db:service_started:true"
	imageRef  string // e.g. "ghcr.io/owner/db:1.0"
	imageID   string // local image id
}

func buildComposeFixture(t *testing.T, specs []composeSpec, health docker.HealthStatus) (*fakeDocker, *fakeRegistry, *stubUpdaterDocker) {
	t.Helper()
	containers := make([]docker.Container, 0, len(specs))
	images := make(map[string]*docker.ImageInspect, len(specs))
	digests := make(map[string]string, len(specs))
	stubContainers := make(map[string]*docker.ContainerInspect, len(specs))
	for _, sp := range specs {
		labels := map[string]string{}
		if sp.project != "" {
			labels["com.docker.compose.project"] = sp.project
			labels["com.docker.compose.service"] = sp.name
		}
		if sp.dependsOn != "" {
			labels["com.docker.compose.depends_on"] = sp.dependsOn
		}
		oldID := "old-" + sp.name
		containers = append(containers, docker.Container{
			ID:      oldID,
			Name:    sp.name,
			Image:   sp.imageRef,
			ImageID: sp.imageID,
			Labels:  labels,
		})
		images[sp.imageID] = &docker.ImageInspect{
			RepoDigests: []string{repoOf(sp.imageRef) + "@sha256:old-" + sp.name},
		}
		digests[sp.imageRef] = "sha256:new-" + sp.name
		stubContainers[oldID] = &docker.ContainerInspect{
			ID:              oldID,
			Name:            "/" + sp.name,
			ImageRef:        sp.imageRef,
			Running:         true,
			Health:          docker.HealthNone,
			Config:          json.RawMessage(`{"Image":"` + sp.imageRef + `"}`),
			HostConfig:      json.RawMessage(`{}`),
			NetworkSettings: json.RawMessage(`{"Networks":{}}`),
		}
	}
	return &fakeDocker{containers: containers, images: images},
		&fakeRegistry{digests: digests},
		&stubUpdaterDocker{startupHealth: health, containers: stubContainers}
}

// repoOf strips ":<tag>" off an image reference, leaving the repository
// portion that DigestFor matches against.
func repoOf(ref string) string {
	for i := len(ref) - 1; i >= 0; i-- {
		switch ref[i] {
		case ':':
			return ref[:i]
		case '/':
			return ref
		}
	}
	return ref
}

func TestScanApply_ComposeStack_AppliesDepsBeforeDependents(t *testing.T) {
	// web depends_on db. Both have a SAFE update available. Apply must
	// pull db before web — this is the user-visible Phase 12 contract.
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd, fr, stubDoc := buildComposeFixture(t, []composeSpec{
		{name: "web", project: "demo", dependsOn: "db:service_started:true",
			imageRef: "ghcr.io/owner/web:1.0", imageID: "sha256:l-web"},
		{name: "db", project: "demo", dependsOn: "",
			imageRef: "ghcr.io/owner/db:1.0", imageID: "sha256:l-db"},
	}, docker.HealthHealthy)

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

	stubDoc.pullMu.Lock()
	order := append([]string(nil), stubDoc.pullOrder...)
	stubDoc.pullMu.Unlock()
	if len(order) != 2 {
		t.Fatalf("pull order = %v, want 2 entries", order)
	}
	if order[0] != "ghcr.io/owner/db:1.0" || order[1] != "ghcr.io/owner/web:1.0" {
		t.Errorf("dependency-first violated: pull order = %v", order)
	}
}

func TestScanApply_ComposeStack_StopsOnFailure_PeerStackSkipped(t *testing.T) {
	// db rolls back due to unhealthy startup; web depends_on db so it
	// MUST NOT be applied — pulls should be 1 (only db). The web event
	// in the dispatched notifications carries Action=ActionStackSkipped.
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd, fr, stubDoc := buildComposeFixture(t, []composeSpec{
		{name: "db", project: "demo", dependsOn: "",
			imageRef: "ghcr.io/owner/db:1.0", imageID: "sha256:l-db"},
		{name: "web", project: "demo", dependsOn: "db:service_started:true",
			imageRef: "ghcr.io/owner/web:1.0", imageID: "sha256:l-web"},
	}, docker.HealthUnhealthy)

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
		t.Errorf("only the failing dep should be pulled; pulls = %d, want 1", got)
	}

	var webEvent *notifier.Event
	for i := range rec.got {
		if rec.got[i].Container == "web" {
			webEvent = &rec.got[i]
			break
		}
	}
	if webEvent == nil {
		t.Fatalf("expected a notification for web; got %+v", rec.got)
	}
	if webEvent.Action != types.ActionStackSkipped {
		t.Errorf("web event Action = %v, want ActionStackSkipped", webEvent.Action)
	}

	// Audit log carries an apply.stack_skipped row for web.
	events, _ := st.ReadAudit(0)
	var skipped *store.AuditEvent
	for i := range events {
		if events[i].Action == store.ActionStackSkipped && events[i].Container == "web" {
			skipped = &events[i]
			break
		}
	}
	if skipped == nil {
		t.Fatalf("expected stack_skipped audit row for web; got %+v", events)
	}
	if skipped.Detail == "" {
		t.Errorf("audit Detail should explain the peer + project; got empty")
	}
}

func TestScanApply_DigestBuffer_BuffersNonUrgentDispatchesUrgent(t *testing.T) {
	// Two updates: one SAFE (should be buffered) and one BREAKING
	// (should be dispatched immediately). With a DigestBuffer set, the
	// notifier sees ONE event for this cycle (the BREAKING one) and the
	// buffer ends up holding the SAFE one for a later flush.
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}
	digestBuf := notifier.NewDigestBuffer()

	fd := &fakeDocker{
		containers: []docker.Container{
			{ID: "id-safe", Name: "safe-svc",
				Image:   "ghcr.io/owner/safe:1.0",
				ImageID: "sha256:l-safe", Labels: map[string]string{}},
			{ID: "id-breaking", Name: "breaking-svc",
				Image:   "ghcr.io/owner/breaking:1.0",
				ImageID: "sha256:l-breaking",
				// Force BREAKING via the existing label override path.
				Labels: map[string]string{"bulwark.risk": "breaking"}},
		},
		images: map[string]*docker.ImageInspect{
			"sha256:l-safe":     {RepoDigests: []string{"ghcr.io/owner/safe@sha256:old-safe"}},
			"sha256:l-breaking": {RepoDigests: []string{"ghcr.io/owner/breaking@sha256:old-breaking"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/safe:1.0":     "sha256:new-safe",
		"ghcr.io/owner/breaking:1.0": "sha256:new-breaking",
	}}

	deps := scanDeps{
		Docker:       fd,
		Registry:     fr,
		Notifiers:    []notifier.Notifier{rec},
		Store:        st,
		DigestBuffer: digestBuf,
		Now: func() time.Time {
			return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
		},
	}

	var stdout, stderr bytes.Buffer
	if err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr, deps,
	); err != nil {
		t.Fatalf("scan: %v\nstderr: %s", err, stderr.String())
	}

	// Recorded events: only BREAKING fired this cycle.
	if len(rec.got) != 1 {
		t.Fatalf("expected 1 dispatched event (BREAKING only); got %d: %+v", len(rec.got), rec.got)
	}
	if rec.got[0].Container != "breaking-svc" {
		t.Errorf("dispatched event = %s, want breaking-svc", rec.got[0].Container)
	}
	// Buffer holds the SAFE event waiting for a flush.
	if got := digestBuf.Len(); got != 1 {
		t.Errorf("digest buffer Len = %d, want 1", got)
	}

	// Now flush — the buffered SAFE event should hit the notifier.
	res := flushDigest(context.Background(), digestBuf, notifier.NewDispatcher(
		[]notifier.Notifier{rec}, nil, 0,
	), st, time.Date(2026, 5, 1, 17, 0, 0, 0, time.UTC), nil)
	if res.Drained != 1 {
		t.Errorf("flush drained = %d, want 1", res.Drained)
	}
	if len(rec.got) != 2 {
		t.Fatalf("after flush, dispatched = %d, want 2", len(rec.got))
	}
	if rec.got[1].Container != "safe-svc" {
		t.Errorf("flushed event = %s, want safe-svc", rec.got[1].Container)
	}
	// Buffer is now empty.
	if got := digestBuf.Len(); got != 0 {
		t.Errorf("buffer after flush = %d, want 0", got)
	}
}

func TestScanApply_ComposeStack_FailureDoesNotBlockOtherStacks(t *testing.T) {
	// Two stacks. demo's db rolls back → web is stack-skipped. The OTHER
	// stack's standalone-style container (project=other) must still be
	// pulled — cross-stack failures are independent.
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	fd, fr, stubDoc := buildComposeFixture(t, []composeSpec{
		{name: "db", project: "demo", dependsOn: "",
			imageRef: "ghcr.io/owner/db:1.0", imageID: "sha256:l-db"},
		{name: "web", project: "demo", dependsOn: "db:service_started:true",
			imageRef: "ghcr.io/owner/web:1.0", imageID: "sha256:l-web"},
		{name: "queue", project: "other", dependsOn: "",
			imageRef: "ghcr.io/owner/queue:1.0", imageID: "sha256:l-queue"},
	}, docker.HealthUnhealthy)

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

	// db pulled; queue pulled (different stack, not blocked); web NOT pulled.
	if got := atomic.LoadInt32(&stubDoc.pulls); got != 2 {
		t.Errorf("cross-stack independence violated; pulls = %d, want 2", got)
	}
	stubDoc.pullMu.Lock()
	pulled := append([]string(nil), stubDoc.pullOrder...)
	stubDoc.pullMu.Unlock()
	for _, ref := range pulled {
		if ref == "ghcr.io/owner/web:1.0" {
			t.Errorf("web should have been stack-skipped; pulled %v", pulled)
		}
	}
}
