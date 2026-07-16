package updater

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/hooks"
	"github.com/ranklancer/bulwark/internal/snapshot"
)

// fakeSnapshotBackend is a programmable snapshot.Backend for updater tests.
type fakeSnapshotBackend struct {
	snapshots []string // ids of snapshots taken
	restored  []string // ids restored
	destroyed []string // ids destroyed

	failOnSnapshot bool
	failOnRestore  bool
}

func (f *fakeSnapshotBackend) Name() string                     { return "fake" }
func (f *fakeSnapshotBackend) Available(_ context.Context) bool { return true }
func (f *fakeSnapshotBackend) List(_ context.Context, _ string) ([]snapshot.Snapshot, error) {
	return nil, nil
}
func (f *fakeSnapshotBackend) Snapshot(_ context.Context, target, label string) (string, error) {
	if f.failOnSnapshot {
		return "", errors.New("snapshot failed")
	}
	id := target + "@bulwark-" + label
	f.snapshots = append(f.snapshots, id)
	return id, nil
}
func (f *fakeSnapshotBackend) Restore(_ context.Context, id string) error {
	if f.failOnRestore {
		return errors.New("restore failed")
	}
	f.restored = append(f.restored, id)
	return nil
}
func (f *fakeSnapshotBackend) Destroy(_ context.Context, id string) error {
	f.destroyed = append(f.destroyed, id)
	return nil
}

// fakeDocker is a programmable test double for the Docker client. Each
// method records the calls it received and consults a dispatch table for
// scripted responses.
type fakeDocker struct {
	pulls   []string
	created []createRecord

	// containers maps an ID or name to its inspect result. Lookups try
	// both the literal key and the leading-slash form Docker uses for names.
	containers map[string]*docker.ContainerInspect

	// ops records every method invocation in order, so tests can assert
	// the recreate dance ran in the right sequence.
	ops []string

	// failurePoints lets a test inject an error at a specific operation:
	// e.g. {"start": errors.New("...")} fails the StartContainer call.
	failurePoints map[string]error

	// healthTimeline returns the next health status on each Inspect call,
	// or nil to use the container's stored Health verbatim.
	healthTimeline func(callIndex int) docker.HealthStatus

	inspectCalls atomic.Int32
}

type createRecord struct {
	Name  string
	Image string
}

func (f *fakeDocker) PullImage(_ context.Context, ref string) error {
	f.ops = append(f.ops, "pull:"+ref)
	if err := f.failurePoints["pull"]; err != nil {
		return err
	}
	f.pulls = append(f.pulls, ref)
	return nil
}

func (f *fakeDocker) InspectContainer(_ context.Context, id string) (*docker.ContainerInspect, error) {
	idx := int(f.inspectCalls.Add(1)) - 1
	f.ops = append(f.ops, "inspect:"+id)
	if err := f.failurePoints["inspect"]; err != nil {
		return nil, err
	}
	c, ok := f.containers[id]
	if !ok {
		return nil, nil
	}
	if f.healthTimeline != nil {
		// Clone so the timeline doesn't mutate stored state.
		cp := *c
		cp.Health = f.healthTimeline(idx)
		return &cp, nil
	}
	return c, nil
}

func (f *fakeDocker) StopContainer(_ context.Context, id string, _ int) error {
	f.ops = append(f.ops, "stop:"+id)
	return f.failurePoints["stop"]
}
func (f *fakeDocker) StartContainer(_ context.Context, id string) error {
	f.ops = append(f.ops, "start:"+id)
	if err := f.failurePoints["start"]; err != nil {
		return err
	}
	if c, ok := f.containers[id]; ok {
		c.Running = true
	}
	return nil
}
func (f *fakeDocker) RemoveContainer(_ context.Context, id string, _ bool) error {
	f.ops = append(f.ops, "remove:"+id)
	return f.failurePoints["remove"]
}
func (f *fakeDocker) RenameContainer(_ context.Context, id, newName string) error {
	f.ops = append(f.ops, "rename:"+id+"->"+newName)
	if err := f.failurePoints["rename"]; err != nil {
		return err
	}
	// Update the indexed entry so subsequent lookups by new name work.
	if c, ok := f.containers[id]; ok {
		c.Name = "/" + newName
	}
	return nil
}
func (f *fakeDocker) CreateContainer(_ context.Context, name string, _ docker.CreateContainerConfig) (string, error) {
	f.ops = append(f.ops, "create:"+name)
	if err := f.failurePoints["create"]; err != nil {
		return "", err
	}
	newID := "new-" + name
	f.containers[newID] = &docker.ContainerInspect{
		ID:      newID,
		Name:    "/" + name,
		Running: false,
		Health:  docker.HealthNone,
		Config:  json.RawMessage(`{"Image":"new"}`),
	}
	f.created = append(f.created, createRecord{Name: name, Image: "new"})
	return newID, nil
}

func sampleInspect(id, name, image string) *docker.ContainerInspect {
	return &docker.ContainerInspect{
		ID:              id,
		Name:            "/" + name,
		ImageRef:        image,
		Running:         true,
		Health:          docker.HealthNone,
		Config:          json.RawMessage(`{"Image":"` + image + `","Env":["TZ=UTC"]}`),
		HostConfig:      json.RawMessage(`{"Binds":["/data:/data"]}`),
		NetworkSettings: json.RawMessage(`{"Networks":{"media":{}}}`),
	}
}

// --- happy path -------------------------------------------------------------

func TestApply_HappyPath_NoHealthcheck(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
		},
	}
	// After create, simulate the new container becoming Running through
	// the grace period.
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }

	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	// After CreateContainer adds the entry, also flag it Running so the
	// no-HEALTHCHECK path accepts it.
	origCreate := fd.CreateContainer
	_ = origCreate

	res := u.Apply(context.Background(), "old-id", "lscr.io/linuxserver/sonarr:4.0.11-ls47")

	if res.Err != nil {
		t.Fatalf("Apply returned err: %v\nops: %v", res.Err, fd.ops)
	}
	if res.RolledBack {
		t.Errorf("expected no rollback")
	}

	// Expected operation order:
	//   inspect old → pull → stop old → rename old → create new → start new →
	//   inspect new (health) ... → remove old.
	// Inspect runs first so we know OldImage for hook context before pulling.
	want := []string{
		"inspect:old-id",
		"pull:lscr.io/linuxserver/sonarr:4.0.11-ls47",
		"stop:old-id",
		"rename:old-id->sonarr-bulwark-old",
		"create:sonarr",
		"start:new-sonarr",
	}
	for i, w := range want {
		if i >= len(fd.ops) || fd.ops[i] != w {
			t.Errorf("op[%d] = %q, want %q\nall: %v", i, opsAt(fd.ops, i), w, fd.ops)
		}
	}
	// remove of the preserved old container must come at the end.
	last := fd.ops[len(fd.ops)-1]
	if last != "remove:old-id" {
		t.Errorf("last op = %q, want remove:old-id\nall: %v", last, fd.ops)
	}
}

func TestApply_HappyPath_WithHealthcheck(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
	}
	// Inspect calls during waitForHealthy (the new container is "new-app"):
	//   1st inspect — starting
	//   2nd inspect — healthy
	// The first inspect call (idx 0) is for the old container during the
	// pre-recreate phase, so we bump the timeline accordingly.
	fd.healthTimeline = func(i int) docker.HealthStatus {
		switch i {
		case 0:
			return docker.HealthNone // pre-recreate inspect
		case 1:
			return docker.HealthStarting
		default:
			return docker.HealthHealthy
		}
	}

	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.Apply(context.Background(), "old-id", "ghcr.io/owner/app:2.0")
	if res.Err != nil {
		t.Fatalf("Apply: %v\nops: %v", res.Err, fd.ops)
	}
	if res.HealthStatus != docker.HealthHealthy {
		t.Errorf("HealthStatus = %v, want healthy", res.HealthStatus)
	}
}

// --- rollback paths ---------------------------------------------------------

func TestApplyWithOptions_TakesSnapshotAndDestroysOnSuccess(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "lscr.io/.../sonarr:1.0"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	snap := &fakeSnapshotBackend{}
	u := &Updater{
		Docker:         fd,
		Snapshots:      snap,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "lscr.io/.../sonarr:1.1",
		ApplyOptions{SnapshotTarget: "tank/data/sonarr", SnapshotLabel: "pre"})
	if res.Err != nil {
		t.Fatalf("Apply: %v\nops: %v", res.Err, fd.ops)
	}
	if res.SnapshotID == "" {
		t.Error("expected SnapshotID set on Result")
	}
	if len(snap.snapshots) != 1 {
		t.Errorf("expected 1 snapshot taken, got %d", len(snap.snapshots))
	}
	if len(snap.destroyed) != 1 {
		t.Errorf("expected 1 snapshot destroyed on success, got %d", len(snap.destroyed))
	}
	if len(snap.restored) != 0 {
		t.Errorf("snapshot must NOT be restored on success; got %d restores", len(snap.restored))
	}
}

func TestApplyWithOptions_RestoresSnapshotOnHealthFailure(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus {
		if i == 0 {
			return docker.HealthNone
		}
		return docker.HealthUnhealthy
	}
	snap := &fakeSnapshotBackend{}
	u := &Updater{
		Docker:         fd,
		Snapshots:      snap,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "ghcr.io/owner/app:2.0",
		ApplyOptions{SnapshotTarget: "tank/data/app"})
	if res.Err == nil {
		t.Fatal("expected error on Unhealthy")
	}
	if !res.RolledBack {
		t.Error("expected RolledBack=true")
	}
	if len(snap.restored) != 1 {
		t.Errorf("expected snapshot restored on rollback, got %d restores", len(snap.restored))
	}
	if len(snap.destroyed) != 0 {
		t.Errorf("snapshot must NOT be destroyed during rollback; got %d", len(snap.destroyed))
	}
}

func TestApplyWithOptions_NoSnapshotTargetSkipsSnapshotting(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "x:1"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	snap := &fakeSnapshotBackend{}
	u := &Updater{
		Docker:         fd,
		Snapshots:      snap,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "x:2", ApplyOptions{})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if len(snap.snapshots) != 0 {
		t.Errorf("no SnapshotTarget should mean no snapshot taken, got %d", len(snap.snapshots))
	}
	if res.SnapshotID != "" {
		t.Errorf("SnapshotID should be empty, got %q", res.SnapshotID)
	}
}

func TestApplyWithOptions_SnapshotFailureAbortsBeforeMutation(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "x:1"),
		},
	}
	snap := &fakeSnapshotBackend{failOnSnapshot: true}
	u := &Updater{
		Docker:    fd,
		Snapshots: snap,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "x:2",
		ApplyOptions{SnapshotTarget: "tank/data/x"})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "snapshot") {
		t.Fatalf("expected snapshot error, got %v", res.Err)
	}
	if res.RolledBack {
		t.Error("snapshot failure happens before mutations; RolledBack should be false")
	}
	// Should not have stopped, renamed, or recreated the container.
	for _, op := range fd.ops {
		if strings.HasPrefix(op, "stop:") || strings.HasPrefix(op, "rename:") || strings.HasPrefix(op, "create:") {
			t.Errorf("post-snapshot-failure op leaked: %s\nall: %v", op, fd.ops)
		}
	}
}

func TestApplyWithOptions_RollbackContinuesEvenIfSnapshotRestoreFails(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus {
		if i == 0 {
			return docker.HealthNone
		}
		return docker.HealthUnhealthy
	}
	snap := &fakeSnapshotBackend{failOnRestore: true}
	u := &Updater{
		Docker:         fd,
		Snapshots:      snap,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "ghcr.io/owner/app:2.0",
		ApplyOptions{SnapshotTarget: "tank/data/app"})
	if res.Err == nil {
		t.Fatal("expected health-failure error")
	}
	if !res.RolledBack {
		t.Error("expected RolledBack=true even when snapshot restore fails")
	}
	// The container-level rollback (rename old back, start old) should
	// still have been attempted.
	if !containsOp(fd.ops, "rename:old-id->app") {
		t.Errorf("container-level rollback skipped after snapshot-restore failure\nops: %v", fd.ops)
	}
}

func TestApply_RollbackOnUnhealthy(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus {
		if i == 0 {
			return docker.HealthNone
		}
		return docker.HealthUnhealthy
	}
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.Apply(context.Background(), "old-id", "ghcr.io/owner/app:2.0")
	if res.Err == nil {
		t.Fatal("expected error when health is Unhealthy")
	}
	if !res.RolledBack {
		t.Error("expected RolledBack=true")
	}

	// Rollback must:
	//   stop the new, remove the new, rename old back, start old.
	joined := strings.Join(fd.ops, "|")
	for _, want := range []string{
		"stop:new-app",
		"remove:new-app",
		"rename:old-id->app",
		"start:old-id",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("rollback ops missing %q\nall: %s", want, joined)
		}
	}
}

func TestApply_RollbackOnStartFailure(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
		failurePoints: map[string]error{"start": errors.New("oom")},
	}
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.Apply(context.Background(), "old-id", "ghcr.io/owner/app:2.0")
	// First start (the new container) fails; second start (the old one,
	// during rollback) is also configured to fail because failurePoints is
	// shared. That's fine — the test asserts the rollback sequence is
	// attempted, not that it succeeded.
	if res.Err == nil {
		t.Fatal("expected error when start fails")
	}
	if !res.RolledBack {
		t.Error("expected RolledBack=true")
	}
	// The rename-back attempt must be present.
	if !containsOp(fd.ops, "rename:old-id->app") {
		t.Errorf("rollback rename missing\nops: %v", fd.ops)
	}
}

func TestApply_PullFailure_AbortsBeforeAnyMutation(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
		failurePoints: map[string]error{"pull": errors.New("manifest unknown")},
	}
	u := &Updater{Docker: fd}
	res := u.Apply(context.Background(), "old-id", "ghcr.io/owner/app:9.9.9")
	if res.Err == nil || !strings.Contains(res.Err.Error(), "manifest unknown") {
		t.Fatalf("expected pull error, got %v", res.Err)
	}
	if res.RolledBack {
		t.Error("RolledBack should be false: nothing was changed yet")
	}
	// Inspect (read-only) is OK; no mutations should have happened.
	for _, op := range fd.ops {
		if strings.HasPrefix(op, "stop:") || strings.HasPrefix(op, "rename:") ||
			strings.HasPrefix(op, "create:") || strings.HasPrefix(op, "remove:") ||
			strings.HasPrefix(op, "start:") {
			t.Errorf("post-pull-failure mutation leaked: %s\nall: %v", op, fd.ops)
		}
	}
}

func TestApply_RenameFailure_TriesToStartOldBackUp(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
		},
		failurePoints: map[string]error{"rename": errors.New("name conflict")},
	}
	u := &Updater{Docker: fd}
	res := u.Apply(context.Background(), "old-id", "ghcr.io/owner/app:2.0")
	if res.Err == nil || !strings.Contains(res.Err.Error(), "rename old") {
		t.Fatalf("expected rename error, got %v", res.Err)
	}
	// A start of old-id must follow the failed rename so we don't leave
	// the user's container stopped.
	if !containsOp(fd.ops, "start:old-id") {
		t.Errorf("expected start:old-id after rename failure, got %v", fd.ops)
	}
}

func TestApply_InspectMissingContainerErrors(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{}}
	u := &Updater{Docker: fd}
	res := u.Apply(context.Background(), "absent", "x:1")
	if res.Err == nil || !strings.Contains(res.Err.Error(), "not found") {
		t.Errorf("expected not-found error, got %v", res.Err)
	}
}

// --- hook integration -------------------------------------------------------

func TestApplyWithOptions_PreUpdateHookFires(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "lscr.io/.../sonarr:1"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	hr := hooks.NewFakeRunner()
	hr.On("/hooks/pre.sh", []byte("ok"), nil)
	u := &Updater{
		Docker:         fd,
		Hooks:          hr,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "lscr.io/.../sonarr:2",
		ApplyOptions{PreUpdateHook: "/hooks/pre.sh"})
	if res.Err != nil {
		t.Fatalf("Apply: %v", res.Err)
	}
	calls := hr.Calls()
	if len(calls) < 1 {
		t.Fatal("expected at least one hook call")
	}
	if calls[0].Path != "/hooks/pre.sh" {
		t.Errorf("first hook = %q", calls[0].Path)
	}
	if calls[0].Ctx.Action != hooks.ActionPreUpdate {
		t.Errorf("first hook action = %q, want pre-update", calls[0].Ctx.Action)
	}
	if calls[0].Ctx.OldImage != "lscr.io/.../sonarr:1" {
		t.Errorf("hook OldImage = %q", calls[0].Ctx.OldImage)
	}
	if calls[0].Ctx.NewImage != "lscr.io/.../sonarr:2" {
		t.Errorf("hook NewImage = %q", calls[0].Ctx.NewImage)
	}
}

func TestApplyWithOptions_PreUpdateHookFailureAborts(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "x:1"),
		},
	}
	hr := hooks.NewFakeRunner()
	hr.On("/hooks/pre.sh", []byte("nope"), errors.New("exit 1"))
	u := &Updater{Docker: fd, Hooks: hr}
	res := u.ApplyWithOptions(context.Background(), "old-id", "x:2",
		ApplyOptions{PreUpdateHook: "/hooks/pre.sh"})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "pre-update hook") {
		t.Fatalf("expected pre-update hook error, got %v", res.Err)
	}
	// No mutations should have occurred.
	for _, op := range fd.ops {
		if strings.HasPrefix(op, "stop:") || strings.HasPrefix(op, "rename:") ||
			strings.HasPrefix(op, "create:") || strings.HasPrefix(op, "pull:") {
			t.Errorf("pre-update hook failure must abort before mutations; saw %s", op)
		}
	}
}

func TestApplyWithOptions_PostUpdateHookFiresOnSuccess(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "x:1"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	hr := hooks.NewFakeRunner()
	hr.On("/hooks/post.sh", nil, nil)
	u := &Updater{
		Docker:         fd,
		Hooks:          hr,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	if res := u.ApplyWithOptions(context.Background(), "old-id", "x:2",
		ApplyOptions{PostUpdateHook: "/hooks/post.sh"}); res.Err != nil {
		t.Fatalf("Apply: %v", res.Err)
	}
	var found bool
	for _, c := range hr.Calls() {
		if c.Path == "/hooks/post.sh" && c.Ctx.Action == hooks.ActionPostUpdate {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("post-update hook not invoked: %+v", hr.Calls())
	}
}

func TestApplyWithOptions_PostUpdateFailureNonFatal(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "x:1"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	hr := hooks.NewFakeRunner()
	hr.On("/hooks/post.sh", []byte("oops"), errors.New("exit 1"))
	u := &Updater{
		Docker:         fd,
		Hooks:          hr,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "x:2",
		ApplyOptions{PostUpdateHook: "/hooks/post.sh"})
	if res.Err != nil {
		t.Errorf("post-update hook failure should not fail Apply: %v", res.Err)
	}
}

func TestApplyWithOptions_RollbackHookFiresOnRollback(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": sampleInspect("old-id", "sonarr", "x:1"),
		},
	}
	fd.healthTimeline = func(i int) docker.HealthStatus {
		if i == 0 {
			return docker.HealthNone
		}
		return docker.HealthUnhealthy
	}
	hr := hooks.NewFakeRunner()
	hr.On("/hooks/rb.sh", nil, nil)
	u := &Updater{
		Docker:         fd,
		Hooks:          hr,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "x:2",
		ApplyOptions{RollbackHook: "/hooks/rb.sh"})
	if !res.RolledBack {
		t.Fatal("expected rollback")
	}
	var found bool
	for _, c := range hr.Calls() {
		if c.Path == "/hooks/rb.sh" && c.Ctx.Action == hooks.ActionRollback {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("rollback hook not invoked: %+v", hr.Calls())
	}
}

// --- waitForHealthy in isolation -------------------------------------------

func TestWaitForHealthy_TimesOutWhenStuckStarting(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"x": {ID: "x", Health: docker.HealthStarting, Running: true},
		},
		healthTimeline: func(_ int) docker.HealthStatus { return docker.HealthStarting },
	}
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  20 * time.Millisecond,
	}
	healthy, status, err := u.waitForHealthy(context.Background(), "x", 0)
	if healthy {
		t.Error("should not be healthy")
	}
	if status != docker.HealthStarting {
		t.Errorf("status = %v, want Starting", status)
	}
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want timeout", err)
	}
}

// TestWaitForHealthy_StartPeriodOverrideExtendsTimeout verifies the
// Phase-15a contract: a per-container HEALTHCHECK start_period that
// exceeds the daemon's HealthTimeout pushes the timeout out enough to
// cover it. Without this, services with long startup probes (databases,
// app servers warming caches) would always be rolled back.
func TestWaitForHealthy_StartPeriodOverrideExtendsTimeout(t *testing.T) {
	calls := 0
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"x": {ID: "x", Running: true},
		},
		healthTimeline: func(_ int) docker.HealthStatus {
			calls++
			// First few inspections: Starting. Then Healthy.
			if calls < 4 {
				return docker.HealthStarting
			}
			return docker.HealthHealthy
		},
	}
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  3 * time.Millisecond, // less than 4 polls × 1ms
	}
	// Override of 50ms = much longer than the configured timeout. The
	// new behaviour stretches the timeout; the container becomes
	// healthy on poll 4 (~4ms elapsed), so we should succeed.
	healthy, status, err := u.waitForHealthy(context.Background(), "x", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !healthy {
		t.Errorf("expected healthy after override-extended timeout; status=%v", status)
	}
}

func TestWaitForHealthy_RespectsContextCancel(t *testing.T) {
	fd := &fakeDocker{
		containers: map[string]*docker.ContainerInspect{
			"x": {ID: "x", Health: docker.HealthStarting, Running: true},
		},
		healthTimeline: func(_ int) docker.HealthStatus { return docker.HealthStarting },
	}
	u := &Updater{
		Docker:         fd,
		HealthInterval: 50 * time.Millisecond,
		HealthTimeout:  10 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, _, err := u.waitForHealthy(ctx, "x", 0)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// --- helpers ---------------------------------------------------------------

func opsAt(ops []string, i int) string {
	if i < len(ops) {
		return ops[i]
	}
	return "<missing>"
}

func containsOp(ops []string, want string) bool {
	for _, op := range ops {
		if op == want {
			return true
		}
	}
	return false
}
