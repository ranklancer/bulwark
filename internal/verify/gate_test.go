package verify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/cve"
)

type fakeSource struct {
	vulns []cve.Vuln
	err   error
}

func (f fakeSource) Vulns(_ context.Context, _ string) ([]cve.Vuln, error) {
	return f.vulns, f.err
}

func sigBlockPolicy() SignaturePolicy {
	return SignaturePolicy{
		Mode:       ModeBlock,
		Identities: []Identity{{SANRegexp: "^https://github.com/ranklancer/.+$", Issuer: "https://token.actions.githubusercontent.com"}},
	}
}

func trustedVerifier() *FakeSignatureVerifier {
	return &FakeSignatureVerifier{Result: SignatureResult{Verified: true, Identity: "ranklancer"}}
}

func untrustedVerifier() *FakeSignatureVerifier {
	return &FakeSignatureVerifier{Result: SignatureResult{Verified: false, Detail: "no trusted signature found"}}
}

func TestEvaluate_DisabledAlwaysAllows(t *testing.T) {
	g := Gate{Policy: Policy{Enabled: false}, Signature: untrustedVerifier()}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if !v.Allowed() || v.Decision != DecisionAllow {
		t.Fatalf("disabled gate must allow, got %s", v.Decision)
	}
}

func TestEvaluate_HappyPath_SignedAndClean_Allows(t *testing.T) {
	// North star: verified identity + no blocking vulns => automation proceeds.
	g := Gate{
		Policy: Policy{
			Enabled:   true,
			Signature: sigBlockPolicy(),
			Vuln:      VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityCritical},
		},
		Signature: trustedVerifier(),
		Vulns:     fakeSource{vulns: []cve.Vuln{{ID: "CVE-2020-1", Severity: cve.SeverityMedium}}},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionAllow {
		t.Fatalf("signed+clean must allow, got %s (%s)", v.Decision, v.Summary())
	}
}

func TestEvaluate_UntrustedSignature_Blocks(t *testing.T) {
	g := Gate{
		Policy:    Policy{Enabled: true, Signature: sigBlockPolicy()},
		Signature: untrustedVerifier(),
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock || v.Allowed() {
		t.Fatalf("untrusted signature in block mode must block, got %s", v.Decision)
	}
}

func TestEvaluate_UntrustedSignature_WarnModeAllows(t *testing.T) {
	pol := sigBlockPolicy()
	pol.Mode = ModeWarn
	g := Gate{Policy: Policy{Enabled: true, Signature: pol}, Signature: untrustedVerifier()}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionWarn || !v.Allowed() {
		t.Fatalf("warn mode must warn+allow, got %s", v.Decision)
	}
}

func TestEvaluate_NilVerifier_FailsClosed(t *testing.T) {
	g := Gate{Policy: Policy{Enabled: true, Signature: sigBlockPolicy()}, Signature: nil}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("nil verifier in block mode must fail closed, got %s", v.Decision)
	}
}

func TestEvaluate_VulnAtThreshold_Blocks(t *testing.T) {
	g := Gate{
		Policy: Policy{
			Enabled: true,
			Vuln:    VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityHigh},
		},
		Vulns: fakeSource{vulns: []cve.Vuln{
			{ID: "CVE-2024-9", Severity: cve.SeverityCritical},
			{ID: "CVE-2024-1", Severity: cve.SeverityLow},
		}},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("critical vuln at/above HIGH must block, got %s", v.Decision)
	}
	if v.Vuln.Highest != cve.SeverityCritical || len(v.Vuln.Blocking) != 1 {
		t.Fatalf("expected 1 blocking crit, got %d highest=%s", len(v.Vuln.Blocking), v.Vuln.Highest)
	}
}

func TestEvaluate_VulnBelowThreshold_Allows(t *testing.T) {
	g := Gate{
		Policy: Policy{Enabled: true, Vuln: VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityCritical}},
		Vulns:  fakeSource{vulns: []cve.Vuln{{ID: "CVE-2024-1", Severity: cve.SeverityHigh}}},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionAllow {
		t.Fatalf("high vuln below CRITICAL threshold must allow, got %s", v.Decision)
	}
}

func TestEvaluate_VulnSourceError_FailsClosed(t *testing.T) {
	g := Gate{
		Policy: Policy{Enabled: true, Vuln: VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityHigh}},
		Vulns:  fakeSource{err: errors.New("trivy report missing")},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("unknown vuln state in block mode must fail closed, got %s", v.Decision)
	}
}

func TestEvaluate_BreakGlass_ConvertsBlockToOverride(t *testing.T) {
	g := Gate{Policy: Policy{Enabled: true, Signature: sigBlockPolicy()}, Signature: untrustedVerifier()}
	in := Input{
		PinnedRef: "repo@sha256:abc",
		Labels:    map[string]string{LabelBreakGlass: "hotfix: vendor image not yet signed"},
	}
	v := g.Evaluate(context.Background(), in)
	if v.Decision != DecisionBreakGlass || !v.Allowed() {
		t.Fatalf("valid break-glass must override to proceed, got %s", v.Decision)
	}
	if v.BreakGlass == nil || v.BreakGlass.Reason == "" {
		t.Fatalf("break-glass metadata must be attached")
	}
}

func TestEvaluate_BreakGlassExpired_StaysBlocked(t *testing.T) {
	g := Gate{
		Policy:    Policy{Enabled: true, Signature: sigBlockPolicy()},
		Signature: untrustedVerifier(),
		Now:       func() time.Time { return time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC) },
	}
	in := Input{
		PinnedRef: "repo@sha256:abc",
		Labels: map[string]string{
			LabelBreakGlass:        "expired window",
			LabelBreakGlassExpires: "2026-07-01T00:00:00Z",
		},
	}
	v := g.Evaluate(context.Background(), in)
	if v.Decision != DecisionBlock {
		t.Fatalf("expired break-glass must stay blocked, got %s", v.Decision)
	}
}

// TestGate_EnforcementModes_SignedVsUnsigned is the end-to-end enforcement
// matrix: for each mode (off/warn/block) crossed with a signed vs unsigned
// image (modelled by FakeSignatureVerifier), the gate returns the right
// Decision. off never evaluates; warn observes (never holds); block is
// fail-closed on an untrusted image.
func TestGate_EnforcementModes_SignedVsUnsigned(t *testing.T) {
	mk := func(mode Mode, verified bool) Gate {
		return Gate{
			Policy: Policy{Enabled: true, Signature: SignaturePolicy{
				Mode:       mode,
				Identities: []Identity{{SANRegexp: ".*"}},
			}},
			Signature: &FakeSignatureVerifier{Result: SignatureResult{Verified: verified}},
		}
	}
	cases := []struct {
		name     string
		mode     Mode
		verified bool
		want     Decision
	}{
		{"off/unsigned proceeds", ModeOff, false, DecisionAllow},
		{"off/signed proceeds", ModeOff, true, DecisionAllow},
		{"warn/signed allows", ModeWarn, true, DecisionAllow},
		{"warn/unsigned warns", ModeWarn, false, DecisionWarn},
		{"block/signed allows", ModeBlock, true, DecisionAllow},
		{"block/unsigned blocks", ModeBlock, false, DecisionBlock},
	}
	for _, tc := range cases {
		g := mk(tc.mode, tc.verified)
		v := g.Evaluate(context.Background(), Input{PinnedRef: "img@sha256:deadbeef"})
		if v.Decision != tc.want {
			t.Errorf("%s: Decision = %q, want %q (reasons: %v)", tc.name, v.Decision, tc.want, v.Reasons)
		}
	}
}

func TestEvaluate_UnknownSeverityVuln_FailsClosed(t *testing.T) {
	// A KNOWN vulnerability whose severity could not be graded (SeverityUnknown,
	// e.g. an OSV advisory carrying only a CVSS vector) must BLOCK under block
	// mode — the image is affected; we must not pass it because it is ungradable.
	g := Gate{
		Policy: Policy{Enabled: true, Vuln: VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityHigh}},
		Vulns:  fakeSource{vulns: []cve.Vuln{{ID: "OSV-2024-1", Severity: cve.SeverityUnknown}}},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("ungradable (Unknown) known vuln must fail closed, got %s", v.Decision)
	}
}
