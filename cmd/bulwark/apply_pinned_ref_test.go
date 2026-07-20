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
