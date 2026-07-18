package main

// a hardening tier: scan --apply fault injection (bulwark pre-public hardening backlog
// an internal audit).
//
// PR #65 (the verify-before-pull design) wired verify-before-pull onto the Updater the CLI's
// `bulwark scan --apply` path uses (cmd/bulwark/scan.go's attachVerifyGate
// sets Updater.Verify = gate; internal/updater/updater.go's
// ApplyWithOptions then calls gate.Evaluate BEFORE any pull, per container,
// inside cmd/bulwark/apply.go's applyEligibleUpdates loop). This test proves
// that property end to end at the scan-apply orchestration layer -- across a
// scan with more than one eligible image -- for a fault class distinct from
// "verified=false": the vulnerability *source* itself (cve.Source, the
// pluggable Trivy/Grype-style backend the vulnerability axis calls through
// verify.Gate.Vulns) returning an error mid-scan, e.g. because the scanner
// backend timed out or crashed on one image.
//
// applyEligibleUpdates iterates scanner.Result per-container; unlike the
// deploy-time trust gate's own early-exit-on-block logic, nothing in that
// loop treats one container's failure as a reason to stop processing the
// rest of the batch. This test asserts that behaviour is correct AND
// intentional: a verify-source error is scoped to the ONE image whose gate
// evaluation hit it (fail closed: no pull, no container mutation, an
// apply.failed audit record with the source error in the Detail) while a
// clean image later in the very same scan still applies normally. A mutant
// that (a) let a source error pass verification (fail-open) or (b) aborted
// the whole batch on the first error would fail this test: (a) via the
// pull/create counters and audit action on the faulty image, (b) via the
// clean image's pull/create counters and Success outcome.
//
// scanner.Result.Reference is hand-constructed here (digest-pinned) rather
// than produced by internal/scanner.Scan, matching the precedent set by
// cmd/bulwark/verify_gate_test.go: applyEligibleUpdates is exercised
// directly with fixture results so the vulnerability-source-error property
// under test isn't confounded by unrelated preconditions (verify-before-pull
// separately refuses any target that isn't digest-pinned; that's covered by
// internal/updater's own fault-injection suite, not this one).

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/api"
	"github.com/ranklancer/bulwark/internal/cve"
	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/scanner"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/updater"
	"github.com/ranklancer/bulwark/internal/verify"
	"github.com/ranklancer/bulwark/pkg/types"
)

// faultyVulnSource is a cve.Source fake that returns an injected error for
// any ref present in errFor and a clean (no findings) result for everything
// else. It also records every ref it was asked about, so the test can
// confirm the vulnerability axis was actually consulted for both images
// rather than short-circuited.
type faultyVulnSource struct {
	errFor map[string]error
	calls  []string
}

func (f *faultyVulnSource) Vulns(_ context.Context, ref string) ([]cve.Vuln, error) {
	f.calls = append(f.calls, ref)
	if err, ok := f.errFor[ref]; ok {
		return nil, err
	}
	return nil, nil
}

// TestScanApply_MidScanVerifySourceError_FailsClosedPerImage is the a hardening tier
// pin: a scan over two SAFE, auto-apply-eligible images where the
// vulnerability source errors for the SECOND image processed. The FIRST
// image (clean source) must still apply; the second must not, and the
// failure must be recorded, not silently swallowed.
func TestScanApply_MidScanVerifySourceError_FailsClosedPerImage(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	cleanDigest := "sha256:" + strings.Repeat("a", 64)
	faultyDigest := "sha256:" + strings.Repeat("b", 64)

	// sonarr: clean image, no vulnerability findings, must apply.
	sonarrRef := registry.Reference{
		Registry:   "lscr.io",
		Repository: "linuxserver/sonarr",
		Tag:        "4.0.10-ls45",
		Digest:     cleanDigest,
	}
	// radarr: the vulnerability SOURCE errors for this image's pinned ref
	// mid-scan (distinct from "verified=false" -- the source could not
	// answer at all, e.g. the scanner backend timed out).
	radarrRef := registry.Reference{
		Registry:   "lscr.io",
		Repository: "linuxserver/radarr",
		Tag:        "5.0.0",
		Digest:     faultyDigest,
	}

	sourceErr := errors.New("cve source: scanner backend timed out")
	fakeVulns := &faultyVulnSource{
		errFor: map[string]error{
			radarrRef.String(): sourceErr,
		},
	}

	gate := verify.Gate{
		Policy: verify.Policy{
			Enabled: true,
			Vuln: verify.VulnPolicy{
				Mode:           verify.ModeBlock,
				BlockThreshold: cve.SeverityHigh,
			},
		},
		Vulns: fakeVulns,
	}

	results := []scanner.Result{
		{
			Container: docker.Container{
				ID:      "sonarr-id",
				Name:    "sonarr",
				Image:   "lscr.io/linuxserver/sonarr:4.0.10-ls45",
				ImageID: "sha256:sonarr-local",
				Labels:  map[string]string{},
			},
			Reference:      sonarrRef,
			LocalDigest:    "sha256:" + strings.Repeat("0", 64),
			RegistryDigest: cleanDigest,
			Assessment:     &types.RiskAssessment{Level: types.RiskSafe},
		},
		{
			Container: docker.Container{
				ID:      "radarr-id",
				Name:    "radarr",
				Image:   "lscr.io/linuxserver/radarr:5.0.0",
				ImageID: "sha256:radarr-local",
				Labels:  map[string]string{},
			},
			Reference:      radarrRef,
			LocalDigest:    "sha256:" + strings.Repeat("1", 64),
			RegistryDigest: faultyDigest,
			Assessment:     &types.RiskAssessment{Level: types.RiskSafe},
		},
	}

	stubDoc := &stubUpdaterDocker{
		startupHealth: docker.HealthHealthy,
		containers: map[string]*docker.ContainerInspect{
			"sonarr-id": sampleUpdaterInspect("sonarr-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
			"radarr-id": sampleUpdaterInspect("radarr-id", "radarr", "lscr.io/linuxserver/radarr:5.0.0"),
		},
	}
	upd := &updater.Updater{
		Docker: stubDoc,
		Verify: gate,
		Logger: slog.Default(),
	}
	metrics := api.NewMetrics()

	// The deploy-time trust gate param (arg 7) is intentionally nil here:
	// cmd/bulwark/scan.go's `bulwark scan --apply` CLI path never wires
	// applyEligibleUpdates' own `gate` argument (that one is daemon-only,
	// see cmd/bulwark/cycle.go's cfg.Gate). scan --apply's ONLY trust
	// enforcement is the verify-before-pull gate wired onto the Updater by
	// attachVerifyGate, which is exactly what upd.Verify exercises here.
	out := applyEligibleUpdates(context.Background(), results, upd, st, nil, slog.Default(), nil, metrics, nil)

	// --- the faulty image: fail closed, no pull, no mutation ---
	radarrOC, ok := out["radarr"]
	if !ok {
		t.Fatalf("expected an outcome recorded for radarr, got %+v", out)
	}
	if radarrOC.Success {
		t.Fatalf("a verify-source error must NOT let the apply succeed: %+v", radarrOC)
	}
	if radarrOC.Err == nil {
		t.Fatalf("expected radarr's outcome to carry an error, got %+v", radarrOC)
	}
	if !strings.Contains(radarrOC.Err.Error(), sourceErr.Error()) {
		t.Fatalf("radarr's error should surface the injected verify-source error, got %q", radarrOC.Err.Error())
	}
	if _, created := stubDoc.containers["new-radarr"]; created {
		t.Fatalf("verify-source error must fail closed: NO replacement container may be created for radarr")
	}
	for _, ref := range stubDoc.pullOrder {
		if strings.Contains(ref, "radarr") {
			t.Fatalf("verify-source error must fail closed: radarr must never be pulled; pullOrder=%v", stubDoc.pullOrder)
		}
	}

	// --- the clean image in the SAME scan: must still apply normally ---
	// This is the scoping assertion: a mid-scan verify-source error on one
	// image must not silently abort the rest of the batch. If the gate (or
	// a regression) turned this into a whole-scan abort, sonarr's outcome
	// would be missing/failed too.
	sonarrOC, ok := out["sonarr"]
	if !ok {
		t.Fatalf("expected an outcome recorded for sonarr, got %+v", out)
	}
	if !sonarrOC.Success {
		t.Fatalf("a clean image elsewhere in the same scan must still apply; got %+v", sonarrOC)
	}
	if _, created := stubDoc.containers["new-sonarr"]; !created {
		t.Fatalf("expected a replacement container to have been created for sonarr")
	}
	sonarrPulled := false
	for _, ref := range stubDoc.pullOrder {
		if strings.Contains(ref, "sonarr") {
			sonarrPulled = true
		}
	}
	if !sonarrPulled {
		t.Fatalf("expected sonarr to have been pulled; pullOrder=%v", stubDoc.pullOrder)
	}

	// --- the source was actually consulted for both images ---
	if len(fakeVulns.calls) != 2 {
		t.Fatalf("expected the vulnerability source to be consulted for both images, got calls=%v", fakeVulns.calls)
	}

	// --- the scan surfaces the failure: an audit record, not silence ---
	events, err := st.ReadAudit(10)
	if err != nil {
		t.Fatalf("ReadAudit: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Container == "radarr" && e.Action == store.ActionAppliedFailed && strings.Contains(e.Detail, sourceErr.Error()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an %q audit event for radarr carrying the verify-source error, got %+v", store.ActionAppliedFailed, events)
	}
}

// sampleUpdaterInspect builds the minimal *docker.ContainerInspect the
// stubUpdaterDocker fake (defined in scan_apply_test.go) needs to drive a
// full recreate dance: enough Config/HostConfig/NetworkSettings JSON for the
// updater to round-trip a CreateContainerConfig.
func sampleUpdaterInspect(id, name, imageRef string) *docker.ContainerInspect {
	return &docker.ContainerInspect{
		ID:              id,
		Name:            "/" + name,
		ImageRef:        imageRef,
		Running:         true,
		Health:          docker.HealthNone,
		Config:          []byte(`{"Image":"` + imageRef + `","Env":["TZ=UTC"]}`),
		HostConfig:      []byte(`{"Binds":["/data:/data"]}`),
		NetworkSettings: []byte(`{"Networks":{"media":{}}}`),
	}
}
