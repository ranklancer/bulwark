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
	res := u.ApplyWithOptions(context.Background(), "old-id", pinnedTarget, ApplyOptions{})
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
	res := u.ApplyWithOptions(context.Background(), "old-id", "lscr.io/linuxserver/sonarr:4.0.11-ls47", ApplyOptions{})
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
	res := u.ApplyWithOptions(context.Background(), "old-id", pinnedTarget, ApplyOptions{})
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

// recordingVerifier captures the Input it was called with and returns a preset
// verdict, so a test can assert that container labels reach the trust gate.
type recordingVerifier struct {
	verdict   verify.Verdict
	lastInput verify.Input
}

func (r *recordingVerifier) Evaluate(_ context.Context, in verify.Input) verify.Verdict {
	r.lastInput = in
	return r.verdict
}

func TestVerifyBeforePull_BreakGlassProceedsAndForwardsLabels(t *testing.T) {
	// #65: a label-driven break-glass override must be REACHABLE at the
	// verify-before-pull step (labels forwarded) and AUDITED (VerifyBreakGlass),
	// and the update must proceed to pull rather than be re-blocked.
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
	}}
	fd.healthTimeline = func(i int) docker.HealthStatus { return docker.HealthNone }
	rv := &recordingVerifier{verdict: verify.Verdict{
		Decision:   verify.DecisionBreakGlass,
		BreakGlass: &verify.BreakGlass{Reason: "operator override"},
		Reasons:    []string{"break-glass"},
	}}
	u := &Updater{
		Docker:         fd,
		StartupGrace:   1 * time.Millisecond,
		HealthInterval: 1 * time.Millisecond,
		HealthTimeout:  100 * time.Millisecond,
		Verify:         rv,
	}
	labels := map[string]string{"bulwark.verify.break-glass": "operator override"}
	res := u.ApplyWithOptions(context.Background(), "old-id", pinnedTarget, ApplyOptions{Labels: labels})
	if res.Err != nil {
		t.Fatalf("break-glass must proceed to pull, got err=%v ops=%v", res.Err, fd.ops)
	}
	if !res.VerifyBreakGlass {
		t.Fatalf("VerifyBreakGlass must be true on a break-glass verdict")
	}
	if res.VerifyBlocked {
		t.Fatalf("break-glass must not block")
	}
	if !pulled(fd.ops) {
		t.Fatalf("break-glass must proceed to pull; ops=%v", fd.ops)
	}
	if rv.lastInput.Labels["bulwark.verify.break-glass"] != "operator override" {
		t.Fatalf("labels not forwarded to the verify gate: %+v", rv.lastInput.Labels)
	}
}
