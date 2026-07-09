package config

import (
	"fmt"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/cve"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

// Signature verifier backends selectable via verify.signature.verifier.
const (
	// sigVerifierCosign shells out to a pinned cosign binary. Default backend.
	sigVerifierCosign = "cosign"
	// sigVerifierSigstore is the planned sigstore-go bundle backend. It is
	// experimental and rejected at startup until implemented (see the design notes).
	sigVerifierSigstore = "sigstore-go"
)

// VerifyConfig is the opt-in deploy-time trust gate. When Enabled is false the
// gate is inert and Bulwark's apply behaviour is unchanged. When true, an image
// must clear the enabled axes before apply proceeds. Within an active block
// mode the policy is fail-closed (an axis that cannot be evaluated blocks
// rather than passes). Per the design notes the initial signature mode on a fresh
// enable is warn (observe-only), not block; see signatureMode.
type VerifyConfig struct {
	Enabled   bool                  `yaml:"enabled"`
	Signature VerifySignatureConfig `yaml:"signature"`
	Vuln      VerifyVulnConfig      `yaml:"vuln"`
}

// VerifySignatureConfig configures cosign signature verification.
type VerifySignatureConfig struct {
	Mode       string                 `yaml:"mode"`     // off | warn | block (default warn on fresh enable, the design notes)
	Verifier   string                 `yaml:"verifier"` // cosign (default) | sigstore-go (experimental, not enabled)
	Identities []VerifyIdentityConfig `yaml:"identities"`
	Key        string                 `yaml:"key"`    // path/ref to a public key for keyed verify
	Cosign     VerifyCosignConfig     `yaml:"cosign"` // pinned cosign binary for the cosign backend
}

// VerifyCosignConfig pins the cosign binary the signature axis shells out to,
// so the trust gate verifies against a known-good tool instead of whatever
// cosign happens to be on PATH. Both version and digest are required when the
// signature axis is active (fail-closed: the gate must not trust ambient tools).
// A digest is public integrity metadata, not a secret; it is safe in config.
type VerifyCosignConfig struct {
	Binary  string `yaml:"binary"`  // path to the cosign executable ("" => resolve "cosign" on PATH)
	Version string `yaml:"version"` // expected `cosign version` token, e.g. "2.4.1"
	Digest  string `yaml:"digest"`  // expected sha256 of the binary (bare hex or sha256:-prefixed)
}

// VerifyIdentityConfig is one allowed keyless signer.
type VerifyIdentityConfig struct {
	SAN    string `yaml:"san"`    // regexp matched against the certificate SAN
	Issuer string `yaml:"issuer"` // OIDC issuer to pin (optional but recommended)
}

// VerifyVulnConfig configures the vulnerability axis, reusing the #8 CVE source.
type VerifyVulnConfig struct {
	Mode           string `yaml:"mode"`            // off | warn | block (default block when threshold set)
	BlockThreshold string `yaml:"block_threshold"` // off | high | critical
}

// signatureMode returns the effective signature mode. Per the design notes
// (progressive enforcement), an UNSET mode resolves to warn: a freshly
// enabled signature axis observes and reports would-block verdicts rather
// than halting the fleet. Operators then progress warn -> populate trusted
// identities -> block. An explicit "block" is honoured unchanged, and
// verify.enabled defaults to false, so this warn default is only reachable
// once an operator actively turns the gate on.
func (c *Config) signatureMode() verify.Mode {
	if strings.TrimSpace(c.Verify.Signature.Mode) == "" {
		return verify.ModeWarn
	}
	m, _ := verify.ParseMode(c.Verify.Signature.Mode)
	return m
}

// signatureVerifierKind returns the effective signature backend token,
// defaulting to cosign when unset.
func (c *Config) signatureVerifierKind() string {
	v := strings.ToLower(strings.TrimSpace(c.Verify.Signature.Verifier))
	if v == "" {
		return sigVerifierCosign
	}
	return v
}

// vulnAxis returns the effective vuln mode and threshold, applying the default
// that a set threshold with an unset mode blocks.
func (c *Config) vulnAxis() (verify.Mode, cve.Severity) {
	thr := parseVerifyThreshold(c.Verify.Vuln.BlockThreshold)
	if thr == cve.SeverityUnknown {
		return verify.ModeOff, cve.SeverityUnknown
	}
	if strings.TrimSpace(c.Verify.Vuln.Mode) == "" {
		return verify.ModeBlock, thr
	}
	m, _ := verify.ParseMode(c.Verify.Vuln.Mode)
	return m, thr
}

// parseVerifyThreshold maps the config token to a severity. Only high/critical
// are valid block thresholds; everything else disables the axis.
func parseVerifyThreshold(s string) cve.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return cve.SeverityCritical
	case "high":
		return cve.SeverityHigh
	default:
		return cve.SeverityUnknown
	}
}

// validateVerify rejects a malformed verify block at startup so an operator who
// thinks they enabled the trust gate doesn't silently get nothing. No-op when
// verify.enabled is false.
func (c *Config) validateVerify() error {
	if !c.Verify.Enabled {
		return nil
	}
	if _, err := verify.ParseMode(c.Verify.Signature.Mode); err != nil {
		return fmt.Errorf("verify.signature.mode: %w", err)
	}
	if _, err := verify.ParseMode(c.Verify.Vuln.Mode); err != nil {
		return fmt.Errorf("verify.vuln.mode: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(c.Verify.Vuln.BlockThreshold)) {
	case "", "off", "high", "critical":
	default:
		return fmt.Errorf("verify.vuln.block_threshold %q is not off/high/critical", c.Verify.Vuln.BlockThreshold)
	}

	sigMode := c.signatureMode()
	if sigMode != verify.ModeOff {
		// Any identity that IS listed must carry a SAN, in either mode.
		for i, id := range c.Verify.Signature.Identities {
			if strings.TrimSpace(id.SAN) == "" {
				return fmt.Errorf("verify.signature.identities[%d].san must not be empty", i)
			}
		}
		// block mode is fail-closed and must be fully specified: a trust
		// anchor (identity or key) AND a pinned verifier. warn mode is the
		// the design notes observe-only state, valid with empty identities[] and no
		// cosign pin; unverifiable images then surface as warn/would-block
		// telemetry instead of a startup rejection.
		if sigMode == verify.ModeBlock {
			if len(c.Verify.Signature.Identities) == 0 && strings.TrimSpace(c.Verify.Signature.Key) == "" {
				return fmt.Errorf("verify.signature requires at least one identity or a key when mode is block")
			}
			if err := c.validateSignatureVerifier(); err != nil {
				return err
			}
		}
	}

	vulnMode, _ := c.vulnAxis()
	if sigMode == verify.ModeOff && vulnMode == verify.ModeOff {
		return fmt.Errorf("verify.enabled=true but neither the signature nor the vuln axis is active")
	}
	return nil
}

// validateSignatureVerifier enforces backend selection and, for cosign, the
// mandatory binary pin. Called only when the signature axis is active.
func (c *Config) validateSignatureVerifier() error {
	switch c.signatureVerifierKind() {
	case sigVerifierCosign:
		return validateCosignPin(c.Verify.Signature.Cosign)
	case sigVerifierSigstore:
		return fmt.Errorf("verify.signature.verifier %q is experimental and not enabled in this build; use %q (see docs/verify-gate.md and docs/the design notes-signature-verifier.md)", sigVerifierSigstore, sigVerifierCosign)
	default:
		return fmt.Errorf("verify.signature.verifier %q is not recognised (want %q or %q)", c.Verify.Signature.Verifier, sigVerifierCosign, sigVerifierSigstore)
	}
}

// validateCosignPin requires both a version and a sha256 digest so the gate
// verifies against a known-good binary and never trusts ambient tooling.
func validateCosignPin(cc VerifyCosignConfig) error {
	ver := strings.TrimSpace(cc.Version)
	dig := normalizeCosignDigest(cc.Digest)
	if ver == "" || dig == "" {
		return fmt.Errorf("verify.signature.cosign: both version and digest (sha256) must be pinned when the signature axis is active — the gate must not trust ambient cosign tooling")
	}
	if !isSHA256Hex(dig) {
		return fmt.Errorf("verify.signature.cosign.digest must be a sha256 hex string (64 hex chars, optionally sha256:-prefixed)")
	}
	return nil
}

// normalizeCosignDigest lowercases and strips an optional "sha256:" prefix.
func normalizeCosignDigest(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "sha256:")
}

// isSHA256Hex reports whether s is exactly 64 lowercase hex characters.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// VerifyPolicy converts the validated config into a runtime verify.Policy. Call
// Validate first; VerifyPolicy assumes well-formed input and applies the
// fail-closed defaults.
func (c *Config) VerifyPolicy() verify.Policy {
	pol := verify.Policy{Enabled: c.Verify.Enabled}
	if !c.Verify.Enabled {
		return pol
	}
	sp := verify.SignaturePolicy{Mode: c.signatureMode(), Key: strings.TrimSpace(c.Verify.Signature.Key)}
	for _, id := range c.Verify.Signature.Identities {
		sp.Identities = append(sp.Identities, verify.Identity{
			SANRegexp: strings.TrimSpace(id.SAN),
			Issuer:    strings.TrimSpace(id.Issuer),
		})
	}
	pol.Signature = sp
	vmode, thr := c.vulnAxis()
	pol.Vuln = verify.VulnPolicy{Mode: vmode, BlockThreshold: thr}
	return pol
}

// SignatureVerifier builds the configured signature verifier, or nil when the
// signature axis is off (the gate then never invokes it). Assumes validateVerify
// has already accepted the config; it still returns an error for an unusable
// backend so a wiring mistake fails closed rather than panicking.
func (c *Config) SignatureVerifier() (verify.SignatureVerifier, error) {
	if !c.Verify.Enabled || c.signatureMode() == verify.ModeOff {
		return nil, nil
	}
	switch c.signatureVerifierKind() {
	case sigVerifierCosign:
		return &verify.CosignVerifier{
			Bin:     strings.TrimSpace(c.Verify.Signature.Cosign.Binary),
			Version: strings.TrimSpace(c.Verify.Signature.Cosign.Version),
			Digest:  normalizeCosignDigest(c.Verify.Signature.Cosign.Digest),
		}, nil
	case sigVerifierSigstore:
		return nil, fmt.Errorf("verify.signature.verifier %q is experimental and not enabled", sigVerifierSigstore)
	default:
		return nil, fmt.Errorf("verify.signature.verifier %q is not recognised", c.Verify.Signature.Verifier)
	}
}
