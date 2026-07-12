package verify

import (
	"context"
	"fmt"
)

// ProvenancePolicy configures the provenance/SBOM axis (the trust engine). It verifies that a
// digest-pinned image carries a SLSA provenance attestation from a trusted
// builder. Per the internal note decisions:
//   - warn-default on a fresh enable (the design notes progressive enforcement);
//   - an empty BuilderIDRegexp is NEVER auto-trusted (an internal note) — the axis cannot
//     pass, and block mode is degraded to warn so it does not halt the fleet on
//     an unpopulated trust set;
//   - a missing SBOM is warn-only (an internal note) — it never blocks.
type ProvenancePolicy struct {
	Mode             Mode
	BuilderIDRegexp  string   // trusted builder identity (certificate SAN regexp)
	Issuer           string   // optional OIDC issuer pin for the builder cert
	SourceRepoRegexp string   // optional: reserved for source-repo pinning
	RequireSBOM      bool     // also look for an SBOM attestation (warn-only if missing)
	PredicateTypes   []string // provenance predicate types (default: slsaprovenance)
}

// enabled reports whether the provenance axis should be evaluated.
func (p ProvenancePolicy) enabled() bool { return p.Mode != ModeOff }

// predicateTypesOrDefault returns the configured provenance predicate types,
// defaulting to SLSA provenance when unset.
func (p ProvenancePolicy) predicateTypesOrDefault() []string {
	if len(p.PredicateTypes) == 0 {
		return []string{"slsaprovenance"}
	}
	return p.PredicateTypes
}

// ProvenanceResult is the outcome of the provenance axis for one image.
type ProvenanceResult struct {
	Evaluated   bool
	Verified    bool   // a trusted provenance attestation was found
	Builder     string // matched builder identity, when verified
	SBOMChecked bool   // whether an SBOM attestation was looked for
	HasSBOM     bool   // whether a valid SBOM attestation was found
	Err         error  // non-nil => axis could not be completed (unknown)
	Detail      string // short human-readable detail (never secrets)
}

// ProvenanceVerifier checks that a digest-pinned image carries a trusted SLSA
// provenance attestation (and optionally an SBOM attestation).
type ProvenanceVerifier interface {
	VerifyProvenance(ctx context.Context, pinnedRef string, pol ProvenancePolicy) ProvenanceResult
}

// CosignProvenanceVerifier verifies attestations via a pinned cosign binary. It
// reuses CosignVerifier so the same integrity-pinned executable and exec path
// serve both the signature and provenance axes.
type CosignProvenanceVerifier struct {
	Cosign *CosignVerifier
}

// VerifyProvenance runs `cosign verify-attestation` for the configured predicate
// types against the trusted builder identity. Fail-closed: any inability to
// complete the check returns an unknown result (Err set) that the gate blocks on
// in block mode. A missing SBOM never sets Err — it is reported via HasSBOM.
func (c *CosignProvenanceVerifier) VerifyProvenance(ctx context.Context, pinnedRef string, pol ProvenancePolicy) ProvenanceResult {
	res := ProvenanceResult{Evaluated: true}
	if c == nil || c.Cosign == nil {
		res.Err = fmt.Errorf("no cosign provenance verifier configured")
		return res
	}
	// Integrity gate: never trust ambient tooling (mirrors the signature axis).
	if err := c.Cosign.ensureIntegrity(ctx); err != nil {
		res.Err = fmt.Errorf("cosign integrity check failed: %w", err)
		res.Detail = "pinned cosign binary failed integrity verification"
		return res
	}
	if pol.BuilderIDRegexp == "" {
		// an internal note: an empty trusted-builder set is never auto-trusted.
		res.Detail = "no trusted builder identity configured"
		return res
	}
	for _, pt := range pol.predicateTypesOrDefault() {
		args := []string{"verify-attestation", "--type", pt, "--certificate-identity-regexp", pol.BuilderIDRegexp}
		if pol.Issuer != "" {
			args = append(args, "--certificate-oidc-issuer", pol.Issuer)
		}
		args = append(args, "--output", "json", pinnedRef)
		out, err := c.Cosign.exec(ctx, args...)
		if err == nil {
			res.Verified = true
			res.Builder = pol.BuilderIDRegexp
			res.Detail = "verified provenance predicate " + pt
			break
		}
		if isExecUnavailable(err) {
			res.Err = fmt.Errorf("cosign unavailable: %w", err)
			return res
		}
		res.Detail = firstLine(out)
	}
	// SBOM is advisory (an internal note): its absence is warn-only and never sets Err.
	if pol.RequireSBOM {
		res.SBOMChecked = true
		for _, st := range []string{"cyclonedx", "spdxjson", "spdx"} {
			args := []string{"verify-attestation", "--type", st, "--certificate-identity-regexp", pol.BuilderIDRegexp}
			if pol.Issuer != "" {
				args = append(args, "--certificate-oidc-issuer", pol.Issuer)
			}
			args = append(args, "--output", "json", pinnedRef)
			if _, err := c.Cosign.exec(ctx, args...); err == nil {
				res.HasSBOM = true
				break
			} else if isExecUnavailable(err) {
				break
			}
		}
	}
	return res
}

// FakeProvenanceVerifier is a test double: it returns a programmed result and
// records the pinned refs it was asked to verify.
type FakeProvenanceVerifier struct {
	Result ProvenanceResult
	Calls  []string
}

// VerifyProvenance records the call and returns the programmed result.
func (f *FakeProvenanceVerifier) VerifyProvenance(_ context.Context, pinnedRef string, _ ProvenancePolicy) ProvenanceResult {
	f.Calls = append(f.Calls, pinnedRef)
	r := f.Result
	r.Evaluated = true
	return r
}
