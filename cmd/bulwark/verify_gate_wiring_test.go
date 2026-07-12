package main

import (
	"testing"

	"github.com/bulwark-docker/bulwark/internal/config"
)

// TestBuildVerifyGate_WiresProvenance guards against the provenance verifier
// being defined and configured but never wired into the gate the CLI/daemon use
// (the trust engine Phase 1). With provenance enabled the gate must carry a non-nil verifier.
func TestBuildVerifyGate_WiresProvenance(t *testing.T) {
	cfg := &config.Config{}
	cfg.Verify.Enabled = true
	cfg.Verify.Signature.Mode = "off"
	cfg.Verify.Provenance.Mode = "warn"
	cfg.Verify.Provenance.BuilderID = "^https://github.com/acme/.+$"

	g, err := buildVerifyGate(cfg)
	if err != nil {
		t.Fatalf("buildVerifyGate: %v", err)
	}
	if g.Provenance == nil {
		t.Fatal("buildVerifyGate did not wire the provenance verifier")
	}
}
