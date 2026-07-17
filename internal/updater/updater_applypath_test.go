package updater

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
)

func hasOp(ops []string, want string) bool {
	for _, o := range ops {
		if o == want {
			return true
		}
	}
	return false
}

// An unhealthy new container must fail CLOSED: the update rolls back fully —
// the new container is stopped and removed, and the OLD container is renamed
// back to its original name and restarted — and the error names the failure.
// Pins the health-decision + rollback conditionals (updater.go ~373-412) that
// mutation testing found under-asserted.
func TestApply_HealthUnhealthy_FailsClosedWithFullRollback(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0"),
	}}
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
	res := u.ApplyWithOptions(context.Background(), "old-id", "ghcr.io/owner/app:2.0", ApplyOptions{})

	if res.Err == nil || !strings.Contains(res.Err.Error(), "health check failed: status=unhealthy") {
		t.Fatalf("an unhealthy container must fail closed with the status in the error, got err=%v", res.Err)
	}
	if !res.RolledBack {
		t.Fatal("an unhealthy container must be rolled back")
	}
	if !hasOp(fd.ops, "stop:new-app") || !hasOp(fd.ops, "remove:new-app") {
		t.Fatalf("rollback must stop AND remove the new container; ops=%v", fd.ops)
	}
	if !hasOp(fd.ops, "rename:old-id->app") {
		t.Fatalf("rollback must rename the old container back to its original name; ops=%v", fd.ops)
	}
	if !hasOp(fd.ops, "start:old-id") {
		t.Fatalf("rollback must restart the old container; ops=%v", fd.ops)
	}
}

// A container that declares a HEALTHCHECK start_period LONGER than the updater's
// default HealthTimeout must NOT be rolled back before that start_period elapses
// — the per-container start_period stretches the timeout. Pins the grace-override
// and timeout-stretch boundary logic (updater.go ~482-525): a mutant dropping the
// stretch would time out and roll back a still-starting container.
func TestApply_LongStartPeriod_NotRolledBackPrematurely(t *testing.T) {
	old := sampleInspect("old-id", "app", "ghcr.io/owner/app:1.0")
	// 40ms start_period (in ns) — longer than the 5ms HealthTimeout below.
	old.Config = json.RawMessage(`{"Image":"ghcr.io/owner/app:1.0","Healthcheck":{"StartPeriod":40000000}}`)
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{"old-id": old}}
	// No HEALTHCHECK status reported: acceptance is Running-through-grace.
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  5 * time.Millisecond, // < start_period; must be stretched
	}
	res := u.ApplyWithOptions(context.Background(), "old-id", "ghcr.io/owner/app:2.0", ApplyOptions{})

	if res.Err != nil {
		t.Fatalf("a container within its declared start_period must not be failed/rolled back, got err=%v", res.Err)
	}
	if res.RolledBack {
		t.Fatal("must not roll back a container that is still within its start_period")
	}
	if !hasOp(fd.ops, "remove:old-id") {
		t.Fatalf("a successful update should clean up the old container; ops=%v", fd.ops)
	}
}
