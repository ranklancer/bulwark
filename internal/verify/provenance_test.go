package verify

import (
	"context"
	"testing"
)

func provGate(mode Mode, pol ProvenancePolicy, v ProvenanceVerifier) Gate {
	pol.Mode = mode
	return Gate{
		Policy:     Policy{Enabled: true, Provenance: pol},
		Provenance: v,
	}
}

func TestProvenanceAxis_WarnVerified_Allows(t *testing.T) {
	f := &FakeProvenanceVerifier{Result: ProvenanceResult{Verified: true, Builder: "gha"}}
	g := provGate(ModeWarn, ProvenancePolicy{BuilderIDRegexp: "gha"}, f)
	v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:abc"})
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %s, want allow; reasons=%v", v.Decision, v.Reasons)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("verifier calls = %d, want 1", len(f.Calls))
	}
}

func TestProvenanceAxis_WarnUntrusted_WarnsWithRemediation(t *testing.T) {
	f := &FakeProvenanceVerifier{Result: ProvenanceResult{Verified: false}}
	g := provGate(ModeWarn, ProvenancePolicy{BuilderIDRegexp: "gha"}, f)
	v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:abc"})
	if v.Decision != DecisionWarn {
		t.Fatalf("decision = %s, want warn", v.Decision)
	}
	if got := v.Remediation(); got != RemediationProvenanceUntrusted {
		t.Fatalf("remediation = %q, want provenance_untrusted", got)
	}
}

func TestProvenanceAxis_BlockUntrusted_Blocks(t *testing.T) {
	f := &FakeProvenanceVerifier{Result: ProvenanceResult{Verified: false}}
	g := provGate(ModeBlock, ProvenancePolicy{BuilderIDRegexp: "gha"}, f)
	v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", v.Decision)
	}
}

func TestProvenanceAxis_BlockError_FailsClosed(t *testing.T) {
	f := &FakeProvenanceVerifier{Result: ProvenanceResult{Err: context.DeadlineExceeded}}
	g := provGate(ModeBlock, ProvenancePolicy{BuilderIDRegexp: "gha"}, f)
	v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block (fail-closed on error)", v.Decision)
	}
	if got := v.Remediation(); got != RemediationVerifierUnavailable {
		t.Fatalf("remediation = %q, want verifier_unavailable", got)
	}
}

func TestProvenanceAxis_NilVerifier_BlocksInBlockMode(t *testing.T) {
	g := provGate(ModeBlock, ProvenancePolicy{BuilderIDRegexp: "gha"}, nil)
	v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block (no verifier configured)", v.Decision)
	}
}

func TestProvenanceAxis_SBOMMissingIsWarnOnly(t *testing.T) {
	// Verified provenance, but a required SBOM is absent. Even in block mode the
	// missing SBOM only warns (an internal note) and never blocks.
	f := &FakeProvenanceVerifier{Result: ProvenanceResult{Verified: true, SBOMChecked: true, HasSBOM: false}}
	g := provGate(ModeBlock, ProvenancePolicy{BuilderIDRegexp: "gha", RequireSBOM: true}, f)
	v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:abc"})
	if v.Decision != DecisionWarn {
		t.Fatalf("decision = %s, want warn (SBOM missing is warn-only); reasons=%v", v.Decision, v.Reasons)
	}
}

func TestCosignProvenanceVerifier_NilCosign_Errs(t *testing.T) {
	c := &CosignProvenanceVerifier{}
	r := c.VerifyProvenance(context.Background(), "img@sha256:abc", ProvenancePolicy{BuilderIDRegexp: "gha"})
	if r.Err == nil {
		t.Fatal("expected an error when the cosign verifier is not configured")
	}
}

func TestCosignProvenanceVerifier_EmptyBuilder_NotTrusted(t *testing.T) {
	// A configured but pin-disabled cosign (no version/digest) skips the
	// integrity gate; an empty builder must still refuse to trust.
	c := &CosignProvenanceVerifier{Cosign: &CosignVerifier{}}
	r := c.VerifyProvenance(context.Background(), "img@sha256:abc", ProvenancePolicy{BuilderIDRegexp: ""})
	if r.Verified {
		t.Fatal("empty builder identity must never be auto-trusted")
	}
	if r.Err != nil {
		t.Fatalf("empty builder should be a clean not-verified, got err: %v", r.Err)
	}
}
