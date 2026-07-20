package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/scanner"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/updater"
	"github.com/ranklancer/bulwark/internal/verify"
	"github.com/ranklancer/bulwark/pkg/types"
)

// PR #83 finding: apply.go verified pinnedRef(r) (digest-pinned) at the
// deploy-time gate but then invoked ApplyWithOptions with the UNPINNED
// r.Reference.String(). The real scanner never digest-pins Reference -- it
// parses the running container's repo:tag into Reference and stores the
// registry digest separately in RegistryDigest (internal/scanner/scanner.go)
// -- so every real update hit the updater's own verify-before-pull
// "not digest-pinned; refusing to pull an unverifiable image" refusal
// (internal/updater/updater.go) the moment verify was enabled. Net effect:
// verify+auto-apply was fail-closed shut for every real update, not just
// unsafe ones.
//
// The tests below exercise the fix end-to-end through the same CLI path
// (`bulwark scan --apply`) the daemon and the operator use, with a
// scanner-shaped result built the same way scanOne does: Reference is a bare
// repo:tag, RegistryDigest is populated separately.

// permissiveGate is a verify.Gate that is Enabled (so u.Verify != nil,
// triggering the updater's own isDigestPinned refusal) but has every axis
// off, so any digest-pinned ref is unconditionally allowed. This isolates
// these tests from axis-evaluation logic that's already covered elsewhere
// (verify_gate_test.go) and keeps focus on the pinning bug itself.
func permissiveGate() *verify.Gate {
	return &verify.Gate{Policy: verify.Policy{Enabled: true}}
}

// recordingVerifier wraps a Verifier and remembers the PinnedRef it was last
// asked to evaluate, so a test can assert the ref that was VERIFIED is the
// exact same ref that was PULLED (no verify-one/pull-another window).
type recordingVerifier struct {
	inner updater.Verifier

	mu      sync.Mutex
	evalRef string
}

func (r *recordingVerifier) Evaluate(ctx context.Context, in verify.Input) verify.Verdict {
	r.mu.Lock()
	r.evalRef = in.PinnedRef
	r.mu.Unlock()
	return r.inner.Evaluate(ctx, in)
}

func (r *recordingVerifier) lastEvaluated() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evalRef
}

// TestScanApply_VerifyEnabled_UsesDigestPinnedRef is the regression test for
// the finding: with verify ENABLED and a scanner-shaped ScanResult (unpinned
// Reference + populated RegistryDigest), an eligible SAFE update must now
// PROCEED (not be spuriously refused), and the ref pulled must be the
// digest-pinned ref (pinnedRef(r)) -- the exact same ref the verifier
// evaluated.
func TestScanApply_VerifyEnabled_UsesDigestPinnedRef(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	digest := "sha256:" + strings.Repeat("a", 64)
	const image = "lscr.io/linuxserver/sonarr:4.0.10-ls45"

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "sonarr",
			Image:   image,
			ImageID: "sha256:l1",
			Labels:  map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{image: digest}}

	stubDoc := &stubUpdaterDocker{
		startupHealth: docker.HealthHealthy,
		containers: map[string]*docker.ContainerInspect{
			"old-id": {
				ID:              "old-id",
				Name:            "/sonarr",
				ImageRef:        image,
				Running:         true,
				Health:          docker.HealthNone,
				Config:          json.RawMessage(`{"Image":"` + image + `","Env":["TZ=UTC"]}`),
				HostConfig:      json.RawMessage(`{"Binds":["/data:/data"]}`),
				NetworkSettings: json.RawMessage(`{"Networks":{"media":{}}}`),
			},
		},
	}

	recVerify := &recordingVerifier{inner: permissiveGate()}
	upd := &updater.Updater{
		Docker:         stubDoc,
		Verify:         recVerify,
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

	wantRef := image + "@" + digest

	// The regression: verify+auto-apply must not spuriously refuse this
	// eligible update.
	if got := atomic.LoadInt32(&stubDoc.pulls); got != 1 {
		t.Fatalf("pulls = %d, want 1 (verify+auto-apply must not spuriously refuse an eligible update); stdout=%s stderr=%s",
			got, stdout.String(), stderr.String())
	}

	stubDoc.pullMu.Lock()
	pulled := append([]string(nil), stubDoc.pullOrder...)
	stubDoc.pullMu.Unlock()
	if len(pulled) != 1 {
		t.Fatalf("pullOrder = %v, want exactly one entry", pulled)
	}

	// The ref pulled must be digest-pinned and equal pinnedRef(r).
	if pulled[0] != wantRef {
		t.Fatalf("pulled ref = %q, want %q (must be digest-pinned, matching what the trust gate verified)", pulled[0], wantRef)
	}
	if !strings.Contains(pulled[0], "@sha256:") {
		t.Fatalf("pulled ref %q is not digest-pinned", pulled[0])
	}

	// Verified == pulled: the ref the verifier evaluated must be the exact
	// ref that was pulled -- no verify-one/pull-another window.
	if evaluated := recVerify.lastEvaluated(); evaluated != pulled[0] {
		t.Fatalf("verified ref %q != pulled ref %q", evaluated, pulled[0])
	}

	if len(rec.got) != 1 {
		t.Fatalf("dispatched events = %d, want 1; output: %s", len(rec.got), stdout.String())
	}
	if rec.got[0].Action != types.ActionAutoUpdated {
		t.Errorf("event action = %v, want AutoUpdated (proves the apply succeeded, not blocked)", rec.got[0].Action)
	}
}

// TestPinnedRef_EmptyRegistryDigest_DoesNotFabricatePin proves pinnedRef
// itself -- the single source of truth used at both the deploy-time gate
// (~line 115) and the ApplyWithOptions call this PR fixes (~line 172) --
// never invents a digest pin it doesn't have. This is the fail-closed
// invariant the fix must not weaken: when RegistryDigest is empty, pinnedRef
// falls back to the same plain (unpinned) ref it always did.
func TestPinnedRef_EmptyRegistryDigest_DoesNotFabricatePin(t *testing.T) {
	ref, err := registry.Parse("lscr.io/linuxserver/sonarr:4.0.10-ls45")
	if err != nil {
		t.Fatalf("registry.Parse: %v", err)
	}
	r := scanner.Result{Reference: ref, RegistryDigest: ""}

	got := pinnedRef(r)
	want := ref.String()
	if got != want {
		t.Fatalf("pinnedRef with empty RegistryDigest = %q, want %q (must not fabricate a digest pin)", got, want)
	}
	if strings.Contains(got, "@") {
		t.Fatalf("pinnedRef with empty RegistryDigest must not be digest-pinned, got %q", got)
	}
}

// TestApplyPinnedRef_EmptyRegistryDigest_UpdaterRefusesFailClosed exercises
// the exact call this PR changes (pinnedRef(r) fed into ApplyWithOptions)
// with a RegistryDigest-less result -- the scenario a caller must never be
// able to turn into a pull of an unverifiable, mutable tag. pinnedRef falls
// back to the unpinned ref (proven above), and the updater's own
// verify-before-pull digest check must still refuse it: no pull happens, an
// error is surfaced. This is unchanged updater behaviour -- the fix in
// apply.go does not touch it -- but it's the guarantee that makes passing
// pinnedRef(r) at the call site safe rather than more permissive.
func TestApplyPinnedRef_EmptyRegistryDigest_UpdaterRefusesFailClosed(t *testing.T) {
	ref, err := registry.Parse("lscr.io/linuxserver/sonarr:4.0.10-ls45")
	if err != nil {
		t.Fatalf("registry.Parse: %v", err)
	}
	r := scanner.Result{
		Container: docker.Container{ID: "old-id", Name: "sonarr"},
		Reference: ref,
		// RegistryDigest deliberately empty.
	}
	target := pinnedRef(r)
	if strings.Contains(target, "@") {
		t.Fatalf("pinnedRef fabricated a pin from an empty RegistryDigest: %q", target)
	}

	stubDoc := &stubUpdaterDocker{
		containers: map[string]*docker.ContainerInspect{
			"old-id": {ID: "old-id", Name: "/sonarr", ImageRef: ref.String(), Running: true},
		},
	}
	upd := &updater.Updater{Docker: stubDoc, Verify: permissiveGate()}

	res := upd.ApplyWithOptions(context.Background(), r.Container.ID, target, updater.ApplyOptions{})

	if res.Err == nil {
		t.Fatal("expected the updater to refuse an unpinned target when RegistryDigest is empty; got nil error")
	}
	if !strings.Contains(res.Err.Error(), "not digest-pinned") {
		t.Fatalf("expected a not-digest-pinned refusal, got: %v", res.Err)
	}
	if got := atomic.LoadInt32(&stubDoc.pulls); got != 0 {
		t.Fatalf("pulls = %d, want 0 -- an empty RegistryDigest must never reach an unverifiable pull (fail-closed)", got)
	}
}

// ---------------------------------------------------------------------------
// Self-pinning feedback loop regression (found by adversarial review of
// PR #85's original fix). See the pinnedRef doc comment in apply.go for
// the full mechanism. Summary: applying an update rewrites the running
// container's Config.Image to a digest-pinned value; on the NEXT scan,
// registry.Parse folds that (now-stale) digest back into Reference while
// RegistryDigest carries a freshly resolved digest. If pinnedRef bails
// out just because the incoming ref already contains "@", it keeps
// re-verifying and re-pulling the STALE digest forever -- the container
// silently stops receiving updates while the audit trail and
// notifications keep claiming it was patched.
// ---------------------------------------------------------------------------

// TestPinnedRef_Idempotent_UsesFreshDigestNotStaleReferenceDigest is the
// core regression test. Reference already carries a STALE digest (as it
// would after registry.Parse folds a previously-applied Config.Image back
// in) while RegistryDigest carries a freshly resolved NEWER digest.
// pinnedRef(r) must pin to NEW, not OLD.
//
// This test MUST FAIL against the pre-fix pinnedRef (which returned
// r.Reference.String() unchanged whenever it already contained "@") --
// verified manually by temporarily reverting the helper: it failed with
// `pinnedRef = ".../sonarr:4.0.10-ls45@sha256:1111...1111", want
// ".../sonarr:4.0.10-ls45@sha256:2222...2222"` (i.e. it returned the
// STALE digest), then passed again once the helper was restored.
func TestPinnedRef_Idempotent_UsesFreshDigestNotStaleReferenceDigest(t *testing.T) {
	oldDigest := "sha256:" + strings.Repeat("1", 64)
	newDigest := "sha256:" + strings.Repeat("2", 64)

	// Simulates the SECOND scan after an apply: the scanner parsed the
	// container's current (already digest-pinned, now-stale) Config.Image
	// into Reference, and resolved a fresh RegistryDigest from the
	// registry separately -- exactly as internal/scanner/scanner.go does.
	ref, err := registry.Parse("lscr.io/linuxserver/sonarr:4.0.10-ls45@" + oldDigest)
	if err != nil {
		t.Fatalf("registry.Parse: %v", err)
	}
	r := scanner.Result{Reference: ref, RegistryDigest: newDigest}

	got := pinnedRef(r)
	want := "lscr.io/linuxserver/sonarr:4.0.10-ls45@" + newDigest
	if got != want {
		t.Fatalf("pinnedRef = %q, want %q -- must pin to the freshly resolved RegistryDigest, not whatever stale digest already happens to be on Reference (self-pinning feedback loop)", got, want)
	}
	if strings.Contains(got, oldDigest) {
		t.Fatalf("pinnedRef returned the STALE digest %q instead of the fresh RegistryDigest %q -- self-pinning loop reproduced", oldDigest, newDigest)
	}
}

// TestPinnedRef_Idempotent_SecondApplyDoesNotFreeze proves the fix holds
// across repeated apply cycles, not just once: as RegistryDigest keeps
// advancing across scans, pinnedRef keeps tracking it even though
// Reference always shows up carrying whatever digest the PREVIOUS apply
// pinned. Without the fix, the very first apply that bakes a digest into
// Config.Image permanently freezes every subsequent apply on that one
// digest -- this is the "second apply doesn't freeze" guarantee.
func TestPinnedRef_Idempotent_SecondApplyDoesNotFreeze(t *testing.T) {
	const repoTag = "lscr.io/linuxserver/sonarr:4.0.10-ls45"
	d1 := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	d3 := "sha256:" + strings.Repeat("3", 64)

	// Cycle 1: bare tag, nothing applied yet. RegistryDigest = d1.
	ref0, err := registry.Parse(repoTag)
	if err != nil {
		t.Fatalf("registry.Parse: %v", err)
	}
	r1 := scanner.Result{Reference: ref0, RegistryDigest: d1}
	if got, want := pinnedRef(r1), repoTag+"@"+d1; got != want {
		t.Fatalf("cycle 1: pinnedRef = %q, want %q", got, want)
	}

	// Cycle 2: the apply from cycle 1 rewrote Config.Image to repoTag@d1;
	// the next scan's registry.Parse folds d1 back into Reference. The
	// registry has since advanced to d2.
	ref1, err := registry.Parse(repoTag + "@" + d1)
	if err != nil {
		t.Fatalf("registry.Parse: %v", err)
	}
	r2 := scanner.Result{Reference: ref1, RegistryDigest: d2}
	if got, want := pinnedRef(r2), repoTag+"@"+d2; got != want {
		t.Fatalf("cycle 2 (second apply): pinnedRef = %q, want %q -- must not freeze on d1", got, want)
	}

	// Cycle 3: same story again -- the fix must keep working indefinitely,
	// not just for one extra cycle.
	ref2, err := registry.Parse(repoTag + "@" + d2)
	if err != nil {
		t.Fatalf("registry.Parse: %v", err)
	}
	r3 := scanner.Result{Reference: ref2, RegistryDigest: d3}
	if got, want := pinnedRef(r3), repoTag+"@"+d3; got != want {
		t.Fatalf("cycle 3 (third apply): pinnedRef = %q, want %q -- must not freeze", got, want)
	}
}

// TestScanApply_SelfPinningLoop_SecondCycleTargetsFreshDigest is the
// end-to-end regression test. It drives the same CLI path
// (`bulwark scan --apply`) as TestScanApply_VerifyEnabled_UsesDigestPinnedRef,
// but starts from a container whose LIVE image is already digest-pinned to
// a stale digest -- exactly what a prior apply's write.go would have set
// Config.Image to. It proves the ref handed to PullImage is the freshly
// resolved RegistryDigest, not the stale digest already baked into the
// container's current image.
func TestScanApply_SelfPinningLoop_SecondCycleTargetsFreshDigest(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}

	oldDigest := "sha256:" + strings.Repeat("1", 64)
	newDigest := "sha256:" + strings.Repeat("2", 64)
	const repoTag = "lscr.io/linuxserver/sonarr:4.0.10-ls45"
	const repoNoTag = "lscr.io/linuxserver/sonarr"
	// The container's CURRENT live image is already digest-pinned to a
	// STALE digest -- exactly what a prior apply would have set
	// Config.Image to.
	liveImage := repoTag + "@" + oldDigest

	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "old-id", Name: "sonarr",
			Image:   liveImage,
			ImageID: "sha256:l1",
			Labels:  map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{repoNoTag + "@" + oldDigest}},
		},
	}
	// The registry resolves the CURRENT (already stale-pinned) ref -- the
	// scanner always resolves whatever registry.Parse(c.Image) produced;
	// the key must match ref.String() exactly.
	fr := &fakeRegistry{digests: map[string]string{liveImage: newDigest}}

	stubDoc := &stubUpdaterDocker{
		startupHealth: docker.HealthHealthy,
		containers: map[string]*docker.ContainerInspect{
			"old-id": {
				ID:              "old-id",
				Name:            "/sonarr",
				ImageRef:        liveImage,
				Running:         true,
				Health:          docker.HealthNone,
				Config:          json.RawMessage(`{"Image":"` + liveImage + `","Env":["TZ=UTC"]}`),
				HostConfig:      json.RawMessage(`{"Binds":["/data:/data"]}`),
				NetworkSettings: json.RawMessage(`{"Networks":{"media":{}}}`),
			},
		},
	}

	recVerify := &recordingVerifier{inner: permissiveGate()}
	upd := &updater.Updater{
		Docker:         stubDoc,
		Verify:         recVerify,
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

	wantRef := repoTag + "@" + newDigest

	if got := atomic.LoadInt32(&stubDoc.pulls); got != 1 {
		t.Fatalf("pulls = %d, want 1 (second-cycle apply must not spuriously refuse or silently no-op); stdout=%s stderr=%s",
			got, stdout.String(), stderr.String())
	}

	stubDoc.pullMu.Lock()
	pulled := append([]string(nil), stubDoc.pullOrder...)
	stubDoc.pullMu.Unlock()
	if len(pulled) != 1 {
		t.Fatalf("pullOrder = %v, want exactly one entry", pulled)
	}

	// This is the crux of the self-pinning regression: the ref pulled
	// must be the FRESHLY resolved digest, not the stale one already
	// baked into the container's live image.
	if pulled[0] != wantRef {
		t.Fatalf("pulled ref = %q, want %q -- must target the freshly resolved digest, not the stale already-running one (self-pinning feedback loop)", pulled[0], wantRef)
	}
	if strings.Contains(pulled[0], oldDigest) {
		t.Fatalf("pulled ref %q still carries the STALE digest %q -- update freeze reproduced", pulled[0], oldDigest)
	}

	if evaluated := recVerify.lastEvaluated(); evaluated != pulled[0] {
		t.Fatalf("verified ref %q != pulled ref %q", evaluated, pulled[0])
	}

	if len(rec.got) != 1 {
		t.Fatalf("dispatched events = %d, want 1; output: %s", len(rec.got), stdout.String())
	}
	if rec.got[0].Action != types.ActionAutoUpdated {
		t.Errorf("event action = %v, want AutoUpdated (proves the second-cycle apply succeeded, not silently frozen)", rec.got[0].Action)
	}
}
