package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/api"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/updater"
	"github.com/bulwark-docker/bulwark/internal/verify"
	"github.com/bulwark-docker/bulwark/pkg/types"
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
