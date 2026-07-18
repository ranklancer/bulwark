package admit

import (
	"context"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/cve"
	"github.com/ranklancer/bulwark/internal/verify"
)

// This file targets the 2 Gremlins mutation-testing survivors on the
// pin-state decision in admit.go:
//
//   - admit.go:55  worse() -- a CONDITIONAL_BOUNDARY mutant on `rank(b) > rank(a)`
//     (flips to `>=`). TestWorse_TieBreaksToFirstArgOnEqualRank kills it.
//   - admit.go:175 Admit() -- a NEGATION mutant on
//     `rc != verify.RemediationNone` (flips to `==`).
//     TestAdmit_RemediationSuffixOnlyWhenPresent kills it.
//
// Neither existing test (TestWorseOrdering, TestAdmit_*) exercises the exact
// input that distinguishes original from mutant in either case:
// TestWorseOrdering only feeds worse() pairs with strictly different rank,
// never a tie; no existing test inspects ImageResult.Reasons for the
// remediation-code suffix.

// TestWorse_TieBreaksToFirstArgOnEqualRank kills the admit.go:55 boundary
// mutant. rank() only classifies Block/BreakGlass/Warn explicitly; every
// other Decision value (Allow, and any value the engine cannot classify)
// falls through to the default case and ranks 0. On such a tie, worse(a, b)
// must return `a` (the first argument) because the guard is `rank(b) >
// rank(a)`, which is false when they're equal. A CONDITIONAL_BOUNDARY mutant
// that widens the comparison to `>=` makes the guard true on a tie and
// returns `b` instead -- silently overriding a rank-0 decision with a
// different rank-0 decision it was never supposed to prefer.
func TestWorse_TieBreaksToFirstArgOnEqualRank(t *testing.T) {
	a := DecisionAllow                 // rank 0 (default case)
	b := Decision("unranked-sentinel") // also rank 0 (default case), but a distinct value from a

	if got := worse(a, b); got != a {
		t.Fatalf("worse(%q, %q): equal-rank tie must keep the first argument: got %q, want %q", a, b, got, a)
	}
	// Symmetric check: swap the arguments, the tie-break must still favor
	// whichever value is passed first -- this is what distinguishes `>` from
	// `>=` regardless of which side the mutant widens.
	if got := worse(b, a); got != b {
		t.Fatalf("worse(%q, %q): equal-rank tie must keep the first argument: got %q, want %q", b, a, got, b)
	}
}

// remediationGate is a minimal admit.TrustGate whose Evaluate always returns
// a fixed verify.Verdict, letting the test control exactly what
// Verdict.Remediation() reports without needing a real cosign/trivy backend.
type remediationGate struct{ v verify.Verdict }

func (g remediationGate) Evaluate(_ context.Context, _ verify.Input) verify.Verdict { return g.v }

// TestAdmit_RemediationSuffixOnlyWhenPresent kills the admit.go:175 negation
// mutant on `rc != verify.RemediationNone`. It asserts BOTH directions of the
// condition so the test fails regardless of which way a negation mutant
// flips the comparison:
//
//   - clean verdict (Remediation() == RemediationNone): the reason string
//     must NOT carry a trailing "(...)" remediation suffix.
//   - a verdict with a concrete remediation code (RemediationVulnerable): the
//     reason string MUST carry that code in the suffix.
//
// A mutant that flips `!=` to `==` inverts both: it would append "()" to the
// clean case and drop the code from the failing case.
func TestAdmit_RemediationSuffixOnlyWhenPresent(t *testing.T) {
	t.Run("no remediation code => no suffix", func(t *testing.T) {
		// Every axis left unevaluated (zero value) => Verdict.Remediation()
		// returns RemediationNone.
		g := remediationGate{v: verify.Verdict{Decision: verify.DecisionWarn}}
		e := Engine{Policy: Policy{Pin: verify.ModeWarn}, Gate: g}
		v := e.Admit(context.Background(), []Image{pinned("app", "app@sha256:"+strings.Repeat("a", 64))})

		if len(v.Images) != 1 || len(v.Images[0].Reasons) == 0 {
			t.Fatalf("expected a trust reason to be recorded: %+v", v)
		}
		reason := v.Images[0].Reasons[len(v.Images[0].Reasons)-1]
		if reason != "trust: warn" {
			t.Fatalf("clean verdict must not carry a remediation suffix: got %q, want %q", reason, "trust: warn")
		}
	})

	t.Run("remediation code present => suffix carries it", func(t *testing.T) {
		g := remediationGate{v: verify.Verdict{
			Decision: verify.DecisionBlock,
			Vuln: verify.VulnResult{
				Evaluated: true,
				Blocking:  []cve.Vuln{{ID: "CVE-2099-0001", Severity: cve.SeverityCritical}},
			},
		}}
		e := Engine{Policy: Policy{Pin: verify.ModeWarn}, Gate: g}
		v := e.Admit(context.Background(), []Image{pinned("app", "app@sha256:"+strings.Repeat("b", 64))})

		if len(v.Images) != 1 || len(v.Images[0].Reasons) == 0 {
			t.Fatalf("expected a trust reason to be recorded: %+v", v)
		}
		reason := v.Images[0].Reasons[len(v.Images[0].Reasons)-1]
		want := "trust: block (vulnerable)"
		if reason != want {
			t.Fatalf("blocking verdict must carry the remediation code in the suffix: got %q, want %q", reason, want)
		}
	})
}
