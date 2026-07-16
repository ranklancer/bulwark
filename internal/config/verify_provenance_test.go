package config

import (
	"testing"

	"github.com/ranklancer/bulwark/internal/verify"
)

func cfgWithProvenance(pv VerifyProvenanceConfig) *Config {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Provenance = pv
	return c
}

func TestProvenance_OptInOffWhenUnconfigured(t *testing.T) {
	c := cfgWithProvenance(VerifyProvenanceConfig{})
	if got := c.provenanceMode(); got != verify.ModeOff {
		t.Fatalf("unconfigured provenance mode = %v, want off", got)
	}
	if m := c.VerifyPolicy().Provenance.Mode; m != verify.ModeOff {
		t.Fatalf("policy provenance mode = %v, want off", m)
	}
}

func TestProvenance_BuilderSetUnsetModeDefaultsWarn(t *testing.T) {
	c := cfgWithProvenance(VerifyProvenanceConfig{BuilderID: "^gha$"})
	if got := c.provenanceMode(); got != verify.ModeWarn {
		t.Fatalf("mode = %v, want warn (the design notes fresh opt-in)", got)
	}
	pol := c.VerifyPolicy().Provenance
	if pol.Mode != verify.ModeWarn || pol.BuilderIDRegexp != "^gha$" {
		t.Fatalf("policy = %+v, want warn/^gha$", pol)
	}
}

func TestProvenance_BlockWithEmptyBuilderDegradesToWarn(t *testing.T) {
	c := cfgWithProvenance(VerifyProvenanceConfig{Mode: "block"})
	if got := c.provenanceMode(); got != verify.ModeBlock {
		t.Fatalf("raw mode = %v, want block", got)
	}
	// an internal note: with no builder, the policy must degrade to warn (never auto-trust).
	if pol := c.VerifyPolicy().Provenance; pol.Mode != verify.ModeWarn {
		t.Fatalf("effective policy mode = %v, want warn (empty builder degrade)", pol.Mode)
	}
}

func TestProvenance_OnlyAxisActiveIsValid(t *testing.T) {
	c := cfgWithProvenance(VerifyProvenanceConfig{Mode: "warn", BuilderID: "^gha$"})
	c.Verify.Signature.Mode = "off"
	if err := c.validateVerify(); err != nil {
		t.Fatalf("provenance-only verify config should validate, got: %v", err)
	}
}

func TestProvenance_SBOMWarnOnlyMappedThrough(t *testing.T) {
	c := cfgWithProvenance(VerifyProvenanceConfig{Mode: "warn", BuilderID: "^gha$", RequireSBOM: true})
	if !c.VerifyPolicy().Provenance.RequireSBOM {
		t.Fatal("RequireSBOM did not map into the policy")
	}
}
