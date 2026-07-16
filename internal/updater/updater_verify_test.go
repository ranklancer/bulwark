package updater

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/verify"
)

// fakeVerifier returns a preset verdict; satisfies updater.Verifier.
type fakeVerifier struct{ decision verify.Decision }

func (f fakeVerifier) Evaluate(_ context.Context, _ verify.Input) verify.Verdict {
	return verify.Verdict{Decision: f.decision, Reasons: []string{"fake:" + string(f.decision)}}
}

var pinnedTarget = "lscr.io/linuxserver/sonarr@sha256:" + strings.Repeat("a", 64)

func pulled(ops []string) bool {
	for _, o := range ops {
		if strings.HasPrefix(o, "pull:") {
			return true
		}
	}
	return false
}

func TestVerifyBeforePull_BlockAbortsPull(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
	}}
	u := &Updater{Docker: fd, Verify: fakeVerifier{decision: verify.DecisionBlock}}
	res := u.Apply(context.Background(), "old-id", pinnedTarget)
	if !res.VerifyBlocked || res.Err == nil {
		t.Fatalf("block verdict must abort the update: VerifyBlocked=%v err=%v", res.VerifyBlocked, res.Err)
	}
	if pulled(fd.ops) {
		t.Fatalf("verify-before-pull BLOCK must not pull; ops=%v", fd.ops)
	}
	if res.VerifyDecision != verify.DecisionBlock {
		t.Fatalf("VerifyDecision=%q, want block", res.VerifyDecision)
	}
}

func TestVerifyBeforePull_UnpinnedFailsClosed(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
	}}
	// A configured verifier + a mutable-tag target => fail closed (no pull),
	// regardless of what the verifier would say — we cannot attest an unpinned ref.
	u := &Updater{Docker: fd, Verify: fakeVerifier{decision: verify.DecisionAllow}}
	res := u.Apply(context.Background(), "old-id", "lscr.io/linuxserver/sonarr:4.0.11-ls47")
	if !res.VerifyBlocked || res.Err == nil {
		t.Fatalf("unpinned target with a verifier must fail closed: %+v", res)
	}
	if pulled(fd.ops) {
		t.Fatalf("unpinned fail-closed must not pull; ops=%v", fd.ops)
	}
}

func TestVerifyBeforePull_AllowProceeds(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
	}}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
		Verify:         fakeVerifier{decision: verify.DecisionAllow},
	}
	res := u.Apply(context.Background(), "old-id", pinnedTarget)
	if res.Err != nil {
		t.Fatalf("allow verdict must proceed to pull: %v\nops=%v", res.Err, fd.ops)
	}
	if res.VerifyDecision != verify.DecisionAllow {
		t.Fatalf("VerifyDecision=%q, want allow", res.VerifyDecision)
	}
	if !pulled(fd.ops) {
		t.Fatalf("allow must pull; ops=%v", fd.ops)
	}
}
