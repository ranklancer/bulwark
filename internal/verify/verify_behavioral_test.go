package verify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/cve"
)

func hasReasonContaining(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// An expired break-glass must not only stay blocked but SAY so. This pins the
// reason-emitting branch (`if bg.Reason != "" && bg.Expired`): a negated
// conditional would silently drop the explanation while the decision stays
// Block — a shallow-test gap surfaced by mutation testing.
func TestEvaluate_BreakGlassExpired_ReportsExpiredReason(t *testing.T) {
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
	if !hasReasonContaining(v.Reasons, "break-glass present but expired") {
		t.Fatalf("expired break-glass must surface an explanatory blocking reason, got %v", v.Reasons)
	}
}

// A finding whose severity EQUALS the block threshold must block. This pins the
// `vu.Severity >= BlockThreshold` boundary: a `>` mutant would let the
// exactly-at-threshold finding slip through — a fail-open the tests missed.
func TestEvaluate_VulnExactlyAtThreshold_Blocks(t *testing.T) {
	g := Gate{
		Policy: Policy{Enabled: true, Vuln: VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityHigh}},
		Vulns:  fakeSource{vulns: []cve.Vuln{{ID: "CVE-AT", Severity: cve.SeverityHigh}}},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock {
		t.Fatalf("a finding exactly at the block threshold must block, got %s", v.Decision)
	}
	if len(v.Vuln.Blocking) != 1 {
		t.Fatalf("the at-threshold finding must be recorded as blocking, got %d", len(v.Vuln.Blocking))
	}
}

// The vuln axis being *evaluated* with ZERO blocking findings must NOT read as
// vulnerable. This pins the `len(v.Vuln.Blocking) > 0` boundary in
// Verdict.Remediation: a `>= 0` mutant would report every evaluated-but-clean
// verdict as RemediationVulnerable.
func TestVerdictRemediation_EvaluatedNoBlocking_IsNone(t *testing.T) {
	clean := Verdict{
		Signature: SignatureResult{Evaluated: true, Verified: true},
		Vuln:      VulnResult{Evaluated: true, Blocking: nil},
	}
	if got := clean.Remediation(); got != RemediationNone {
		t.Fatalf("evaluated vuln axis with no blocking findings must be RemediationNone, got %q", got)
	}
	oneBlocking := Verdict{
		Signature: SignatureResult{Evaluated: true, Verified: true},
		Vuln:      VulnResult{Evaluated: true, Blocking: []cve.Vuln{{ID: "CVE-X"}}},
	}
	if got := oneBlocking.Remediation(); got != RemediationVulnerable {
		t.Fatalf("one blocking finding must be RemediationVulnerable, got %q", got)
	}
}

// firstLine bounds the human-readable signature detail. Cover its branches
// (empty, single line, newline-truncated, and length-capped) — this also kills
// the CONDITIONALS_BOUNDARY mutants mutation testing found surviving at the
// newline-index and 200-char-cap checks.
func TestFirstLine_Bounds(t *testing.T) {
	if got := firstLine(nil); got != "" {
		t.Fatalf("empty input -> empty, got %q", got)
	}
	if got := firstLine([]byte("  only line  ")); got != "only line" {
		t.Fatalf("single line trimmed, got %q", got)
	}
	if got := firstLine([]byte("first\nsecond\nthird")); got != "first" {
		t.Fatalf("multi-line -> first line, got %q", got)
	}
	long := make([]byte, 0, 260)
	for i := 0; i < 260; i++ {
		long = append(long, 'x')
	}
	got := firstLine(long)
	if len(got) <= 200 || got[len(got)-3:] != "..." {
		t.Fatalf("over-long input must be truncated with an ellipsis, got len=%d tail=%q", len(got), got[max(0, len(got)-3):])
	}
}
