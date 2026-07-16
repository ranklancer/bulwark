package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/api"
	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/scanner"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/updater"
	"github.com/ranklancer/bulwark/internal/verify"
	"github.com/ranklancer/bulwark/pkg/types"
)

// TestApplyEligibleUpdates_TrustGateBlocksUnsigned proves the reconcile-time
// interception: a SAFE (auto-apply-eligible) update whose image fails the
// signature axis is held before the updater is ever invoked, and the block is
// stamped into the append-only audit log.
func TestApplyEligibleUpdates_TrustGateBlocksUnsigned(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	results := []scanner.Result{{
		Container: docker.Container{
			ID:     "c1",
			Name:   "sonarr",
			Image:  "lscr.io/linuxserver/sonarr:1",
			Labels: map[string]string{},
		},
		LocalDigest:    "sha256:old",
		RegistryDigest: "sha256:new",
		Assessment:     &types.RiskAssessment{Level: types.RiskSafe},
	}}

	gate := &verify.Gate{
		Policy: verify.Policy{
			Enabled: true,
			Signature: verify.SignaturePolicy{
				Mode:       verify.ModeBlock,
				Identities: []verify.Identity{{SANRegexp: ".*"}},
			},
		},
		Signature: &verify.FakeSignatureVerifier{Result: verify.SignatureResult{Verified: false}},
	}

	// A non-nil updater with a nil Docker client: if the gate failed to block,
	// the apply path would dereference it and the test would blow up. Reaching
	// a clean Blocked outcome proves the gate intercepted before apply.
	upd := &updater.Updater{}
	metrics := api.NewMetrics()

	out := applyEligibleUpdates(context.Background(), results, upd, st, nil, slog.Default(), gate, metrics, nil)

	oc, ok := out["sonarr"]
	if !ok || !oc.Blocked {
		t.Fatalf("expected sonarr Blocked by trust gate, got %+v (present=%v)", oc, ok)
	}

	events, _ := st.ReadAudit(10)
	found := false
	for _, e := range events {
		if e.Action == store.ActionApplyBlocked && e.Container == "sonarr" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an %q audit event for sonarr, got %+v", store.ActionApplyBlocked, events)
	}
}

// TestApplyEligibleUpdates_TrustGateWarnProceedsAndAudits proves the design notes
// warn/observe path: a SAFE update whose image fails the signature axis in warn
// mode is NOT held — the apply proceeds — but the would-block verdict is stamped
// into the append-only audit log (previously warn was silent apart from the
// metric counter).
func TestApplyEligibleUpdates_TrustGateWarnProceedsAndAudits(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	results := []scanner.Result{{
		Container: docker.Container{
			ID:     "c1",
			Name:   "sonarr",
			Image:  "lscr.io/linuxserver/sonarr:1",
			Labels: map[string]string{},
		},
		LocalDigest:    "sha256:old",
		RegistryDigest: "sha256:new",
		Assessment:     &types.RiskAssessment{Level: types.RiskSafe},
	}}

	gate := &verify.Gate{
		Policy: verify.Policy{
			Enabled: true,
			Signature: verify.SignaturePolicy{
				Mode:       verify.ModeWarn,
				Identities: []verify.Identity{{SANRegexp: ".*"}},
			},
		},
		Signature: &verify.FakeSignatureVerifier{Result: verify.SignatureResult{Verified: false}},
	}

	// A stub Docker client lets the apply proceed (warn never holds) without a
	// real daemon; we assert only that the would-block telemetry was recorded.
	upd := &updater.Updater{Docker: &stubUpdaterDocker{}}
	metrics := api.NewMetrics()

	out := applyEligibleUpdates(context.Background(), results, upd, st, nil, slog.Default(), gate, metrics, nil)

	oc, ok := out["sonarr"]
	if !ok {
		t.Fatalf("expected an outcome for sonarr, got %+v", out)
	}
	if oc.Blocked {
		t.Fatalf("warn mode must not block the apply; got Blocked outcome %+v", oc)
	}

	events, _ := st.ReadAudit(10)
	found := false
	for _, e := range events {
		if e.Action == store.ActionApplyWouldBlock && e.Container == "sonarr" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an %q audit event for sonarr, got %+v", store.ActionApplyWouldBlock, events)
	}
	// The would-block telemetry is remediation-aware: an unsigned image in warn
	// mode carries the "signature_untrusted" code in its detail.
	remediationSeen := false
	for _, e := range events {
		if e.Action == store.ActionApplyWouldBlock && strings.Contains(e.Detail, "signature_untrusted") {
			remediationSeen = true
		}
	}
	if !remediationSeen {
		t.Errorf("would-block audit detail should carry the remediation code; got %+v", events)
	}
}
