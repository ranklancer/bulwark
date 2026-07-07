package config

import (
	"fmt"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/cve"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

// VerifyConfig is the opt-in deploy-time trust gate. When Enabled is false the
// gate is inert and Bulwark's apply behaviour is unchanged. When true, an image
// must clear the enabled axes before apply proceeds; the policy is fail-closed
// (an unset signature mode defaults to block, and an axis that cannot be
// evaluated blocks rather than passes).
type VerifyConfig struct {
	Enabled   bool                  `yaml:"enabled"`
	Signature VerifySignatureConfig `yaml:"signature"`
	Vuln      VerifyVulnConfig      `yaml:"vuln"`
}

// VerifySignatureConfig configures cosign signature verification.
type VerifySignatureConfig struct {
	Mode       string                 `yaml:"mode"` // off | warn | block (default block when enabled)
	Identities []VerifyIdentityConfig `yaml:"identities"`
	Key        string                 `yaml:"key"` // path/ref to a public key for keyed verify
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

// signatureMode returns the effective signature mode, applying the fail-closed
// default: when verify is enabled and the mode is unset, block.
func (c *Config) signatureMode() verify.Mode {
	if strings.TrimSpace(c.Verify.Signature.Mode) == "" {
		return verify.ModeBlock
	}
	m, _ := verify.ParseMode(c.Verify.Signature.Mode)
	return m
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
		if len(c.Verify.Signature.Identities) == 0 && strings.TrimSpace(c.Verify.Signature.Key) == "" {
			return fmt.Errorf("verify.signature requires at least one identity or a key when the signature axis is active")
		}
		for i, id := range c.Verify.Signature.Identities {
			if strings.TrimSpace(id.SAN) == "" {
				return fmt.Errorf("verify.signature.identities[%d].san must not be empty", i)
			}
		}
	}

	vulnMode, _ := c.vulnAxis()
	if sigMode == verify.ModeOff && vulnMode == verify.ModeOff {
		return fmt.Errorf("verify.enabled=true but neither the signature nor the vuln axis is active")
	}
	return nil
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
