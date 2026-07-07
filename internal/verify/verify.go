// Package verify is Bulwark's deploy-time trust engine. Before an image is
// applied it answers one question: "is this image trusted enough to let
// automation proceed?" A passing Verdict lets Bulwark's existing auto-apply
// path flow with confidence; only a failing Verdict blocks or queues. The gate
// is a trust enabler, not a friction wall: the happy path (signed by a trusted
// identity AND no vulnerability at or above the configured threshold) is
// allowed cleanly, and block/queue is the exception for genuinely untrusted or
// vulnerable images.
//
// Trust is evaluated on two axes, both fail-closed:
//
//   - signature: the image digest must carry a cosign signature from a trusted
//     keyless identity (OIDC SAN + issuer) or a trusted key.
//   - vulnerability: the image must carry no vulnerability at or above a
//     configured block threshold (reusing the internal/cve Source seam from #8).
//
// The engine never reinvents crypto. Signature checking shells out to the
// cosign binary behind the SignatureVerifier seam; vulnerability data comes
// from the pluggable cve.Source (Trivy first). Bulwark owns only the
// reconcile-time interception, the policy, and the allow/block/break-glass
// verdict.
package verify

import (
	"fmt"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/cve"
)

// Mode is the enforcement strength of a single trust axis.
type Mode int

const (
	// ModeOff disables an axis: it is not evaluated at all.
	ModeOff Mode = iota
	// ModeWarn evaluates an axis and surfaces failures, but never blocks apply.
	ModeWarn
	// ModeBlock evaluates an axis and blocks apply on failure (subject to an
	// audited break-glass override).
	ModeBlock
)

// String renders the mode as its config token.
func (m Mode) String() string {
	switch m {
	case ModeWarn:
		return "warn"
	case ModeBlock:
		return "block"
	default:
		return "off"
	}
}

// ParseMode parses an "off" | "warn" | "block" token (case-insensitive). An
// empty string is treated as "off" so an unset field is inert.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return ModeOff, nil
	case "warn":
		return ModeWarn, nil
	case "block":
		return ModeBlock, nil
	default:
		return ModeOff, fmt.Errorf("verify: invalid mode %q (want off|warn|block)", s)
	}
}

// Decision is the terminal outcome of a Verdict.
type Decision string

const (
	// DecisionAllow means every enabled axis passed.
	DecisionAllow Decision = "allow"
	// DecisionWarn means an axis failed only in warn mode; apply still proceeds.
	DecisionWarn Decision = "warn"
	// DecisionBlock means a block-mode axis failed and no break-glass applied.
	DecisionBlock Decision = "block"
	// DecisionBreakGlass means a block-mode axis failed but a valid, audited
	// break-glass override let the apply proceed anyway.
	DecisionBreakGlass Decision = "break_glass"
)

// Identity is one allowed keyless signer: a regexp matched against the
// certificate SAN, optionally pinned to an OIDC issuer.
type Identity struct {
	SANRegexp string
	Issuer    string
}

// SignaturePolicy configures the signature axis.
type SignaturePolicy struct {
	Mode       Mode
	Identities []Identity // allowed keyless identities (any match trusts)
	Key        string     // path/ref to a public key for keyed verification
}

// VulnPolicy configures the vulnerability axis.
type VulnPolicy struct {
	Mode           Mode
	BlockThreshold cve.Severity // lowest severity that fails the axis
}

// enabled reports whether the vuln axis should be evaluated.
func (p VulnPolicy) enabled() bool {
	return p.Mode != ModeOff && p.BlockThreshold != cve.SeverityUnknown
}

// Policy is the full deploy-time trust policy.
type Policy struct {
	Enabled   bool
	Signature SignaturePolicy
	Vuln      VulnPolicy
}

// VulnResult is the outcome of the vulnerability axis for one image.
type VulnResult struct {
	Evaluated bool
	Err       error        // non-nil => source could not answer (unknown)
	Blocking  []cve.Vuln   // vulns at or above the block threshold
	Highest   cve.Severity // highest severity among Blocking
}

// Verdict is the trust engine's answer for one candidate image.
type Verdict struct {
	Decision   Decision
	Signature  SignatureResult
	Vuln       VulnResult
	BreakGlass *BreakGlass // non-nil when a break-glass override was applied
	Reasons    []string    // ordered, human-readable rationale
}

// Allowed reports whether apply may proceed. Allow, Warn and BreakGlass all
// proceed; only Block stops.
func (v Verdict) Allowed() bool { return v.Decision != DecisionBlock }

// Blocked is the inverse of Allowed.
func (v Verdict) Blocked() bool { return v.Decision == DecisionBlock }

// Summary is a compact one-line rationale for the audit log and notifiers.
func (v Verdict) Summary() string { return strings.Join(v.Reasons, "; ") }
