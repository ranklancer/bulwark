package config

import (
	"testing"

	"github.com/bulwark-docker/bulwark/internal/cve"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

func enabledSigConfig() *Config {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Identities = []VerifyIdentityConfig{{SAN: "^https://github.com/ranklancer/.+$", Issuer: "https://token.actions.githubusercontent.com"}}
	return c
}

func TestValidateVerify_DisabledIsNoop(t *testing.T) {
	c := &Config{}
	if err := c.validateVerify(); err != nil {
		t.Fatalf("disabled verify must validate, got %v", err)
	}
	if c.VerifyPolicy().Enabled {
		t.Fatal("disabled policy must be inert")
	}
}

func TestValidateVerify_DefaultsToBlock(t *testing.T) {
	c := enabledSigConfig()
	if err := c.validateVerify(); err != nil {
		t.Fatalf("valid signature config must pass, got %v", err)
	}
	pol := c.VerifyPolicy()
	if pol.Signature.Mode != verify.ModeBlock {
		t.Fatalf("unset signature mode must default to block, got %s", pol.Signature.Mode)
	}
}

func TestValidateVerify_SignatureNeedsIdentityOrKey(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "block"
	if err := c.validateVerify(); err == nil {
		t.Fatal("block signature with no identity/key must fail validation")
	}
}

func TestValidateVerify_VulnOnlyAxis(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "off"
	c.Verify.Vuln.BlockThreshold = "critical"
	if err := c.validateVerify(); err != nil {
		t.Fatalf("vuln-only axis must validate, got %v", err)
	}
	pol := c.VerifyPolicy()
	if pol.Vuln.Mode != verify.ModeBlock || pol.Vuln.BlockThreshold != cve.SeverityCritical {
		t.Fatalf("vuln axis must default to block at critical, got mode=%s thr=%s", pol.Vuln.Mode, pol.Vuln.BlockThreshold)
	}
}

func TestValidateVerify_BadThreshold(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Vuln.BlockThreshold = "medium"
	if err := c.validateVerify(); err == nil {
		t.Fatal("medium block_threshold must be rejected")
	}
}

func TestValidateVerify_NothingActive(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "off"
	if err := c.validateVerify(); err == nil {
		t.Fatal("enabled verify with no active axis must fail")
	}
}

func TestValidateVerify_BadMode(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "enforce"
	if err := c.validateVerify(); err == nil {
		t.Fatal("invalid signature mode must be rejected")
	}
}
