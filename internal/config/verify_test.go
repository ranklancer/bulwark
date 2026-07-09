package config

import (
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/cve"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

// validCosignPin is a well-formed, non-secret pin used by the enabled-signature
// fixtures. The digest is a placeholder 64-hex value, not a real binary hash.
func validCosignPin() VerifyCosignConfig {
	return VerifyCosignConfig{
		Binary:  "/usr/local/bin/cosign",
		Version: "2.4.1",
		Digest:  "sha256:" + strings.Repeat("a", 64),
	}
}

func enabledSigConfig() *Config {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Identities = []VerifyIdentityConfig{{SAN: "^https://github.com/ranklancer/.+$", Issuer: "https://token.actions.githubusercontent.com"}}
	c.Verify.Signature.Cosign = validCosignPin()
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

func TestValidateVerify_UnsetDefaultsToWarn(t *testing.T) {
	// the design notes: an unset signature mode on a fresh enable resolves to warn
	// (observe-only), not block. verify.enabled defaults to false, so no fleet
	// is downgraded without an operator explicitly turning the gate on.
	c := enabledSigConfig()
	if err := c.validateVerify(); err != nil {
		t.Fatalf("valid signature config must pass, got %v", err)
	}
	pol := c.VerifyPolicy()
	if pol.Signature.Mode != verify.ModeWarn {
		t.Fatalf("unset signature mode must default to warn (the design notes), got %s", pol.Signature.Mode)
	}
}

func TestValidateVerify_SignatureNeedsIdentityOrKey(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "block"
	c.Verify.Signature.Cosign = validCosignPin()
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

// --- cosign binary pin (hardening) ---

func TestValidateVerify_CosignPinRequiredWhenSignatureActive(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "block"                // pin/backend validation is block-only (the design notes)
	c.Verify.Signature.Cosign = VerifyCosignConfig{} // no version/digest
	if err := c.validateVerify(); err == nil {
		t.Fatal("active signature axis without a pinned cosign version+digest must be rejected (fail-closed: no ambient tooling)")
	}
}

func TestValidateVerify_CosignVersionAloneInsufficient(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "block"                                // pin/backend validation is block-only (the design notes)
	c.Verify.Signature.Cosign = VerifyCosignConfig{Version: "2.4.1"} // digest missing
	if err := c.validateVerify(); err == nil {
		t.Fatal("version without digest must be rejected — both are required")
	}
}

func TestValidateVerify_CosignDigestMustBeSHA256Hex(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "block" // pin/backend validation is block-only (the design notes)
	c.Verify.Signature.Cosign = VerifyCosignConfig{Version: "2.4.1", Digest: "not-a-real-digest"}
	if err := c.validateVerify(); err == nil {
		t.Fatal("a malformed digest must be rejected")
	}
}

func TestValidateVerify_CosignDigestAcceptsBareHex(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "block" // pin/backend validation is block-only (the design notes)
	c.Verify.Signature.Cosign = VerifyCosignConfig{Version: "2.4.1", Digest: strings.Repeat("b", 64)}
	if err := c.validateVerify(); err != nil {
		t.Fatalf("a bare 64-hex digest (no sha256: prefix) must be accepted, got %v", err)
	}
}

func TestValidateVerify_SigstoreBackendRejectedAsExperimental(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "block" // pin/backend validation is block-only (the design notes)
	c.Verify.Signature.Verifier = "sigstore-go"
	if err := c.validateVerify(); err == nil {
		t.Fatal("the sigstore-go backend is experimental and must be rejected at startup")
	}
}

func TestValidateVerify_UnknownBackendRejected(t *testing.T) {
	c := enabledSigConfig()
	c.Verify.Signature.Mode = "block" // pin/backend validation is block-only (the design notes)
	c.Verify.Signature.Verifier = "notary"
	if err := c.validateVerify(); err == nil {
		t.Fatal("an unrecognised signature backend must be rejected")
	}
}

func TestSignatureVerifier_BuildsPinnedCosign(t *testing.T) {
	c := enabledSigConfig()
	if err := c.validateVerify(); err != nil {
		t.Fatalf("fixture must be valid, got %v", err)
	}
	sv, err := c.SignatureVerifier()
	if err != nil {
		t.Fatalf("SignatureVerifier: %v", err)
	}
	cv, ok := sv.(*verify.CosignVerifier)
	if !ok {
		t.Fatalf("default backend must be *verify.CosignVerifier, got %T", sv)
	}
	if cv.Version != "2.4.1" {
		t.Fatalf("pinned version not propagated, got %q", cv.Version)
	}
	if cv.Digest != strings.Repeat("a", 64) {
		t.Fatalf("pinned digest must be normalized to bare hex, got %q", cv.Digest)
	}
	if cv.Bin != "/usr/local/bin/cosign" {
		t.Fatalf("pinned binary path not propagated, got %q", cv.Bin)
	}
}

func TestSignatureVerifier_NilWhenSignatureOff(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "off"
	c.Verify.Vuln.BlockThreshold = "critical"
	sv, err := c.SignatureVerifier()
	if err != nil {
		t.Fatalf("vuln-only config must not error building the (unused) signature verifier: %v", err)
	}
	if sv != nil {
		t.Fatal("signature-off must yield a nil verifier (the gate never calls it)")
	}
}

func TestValidateVerify_WarnEmptyIdentitiesPasses(t *testing.T) {
	// the design notes: warn is the observe-only state and is valid with no identities
	// and no cosign pin — unverifiable images surface as would-block telemetry
	// rather than failing startup.
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "warn"
	if err := c.validateVerify(); err != nil {
		t.Fatalf("warn with empty identities must validate, got %v", err)
	}
	if pol := c.VerifyPolicy(); pol.Signature.Mode != verify.ModeWarn {
		t.Fatalf("mode must be warn, got %s", pol.Signature.Mode)
	}
}

func TestValidateVerify_WarnPermitsMissingCosignPin(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "warn"
	c.Verify.Signature.Identities = []VerifyIdentityConfig{{SAN: "^https://github.com/ranklancer/.+$"}}
	// No cosign pin configured: warn must not reject on a missing pin.
	if err := c.validateVerify(); err != nil {
		t.Fatalf("warn must permit a missing cosign pin, got %v", err)
	}
}

func TestValidateVerify_BlockRequiresCosignPin(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Signature.Mode = "block"
	c.Verify.Signature.Identities = []VerifyIdentityConfig{{SAN: "^https://github.com/ranklancer/.+$"}}
	// No cosign pin: block is fail-closed and must reject.
	if err := c.validateVerify(); err == nil {
		t.Fatal("block must require a pinned cosign version+digest")
	}
}

// TestSignatureMode_EnforcementModeResolution pins the design notes resolution of
// every enforcement mode: an UNSET mode resolves to warn; explicit off/warn/
// block resolve to themselves.
func TestSignatureMode_EnforcementModeResolution(t *testing.T) {
	cases := []struct {
		mode string
		want verify.Mode
	}{
		{"", verify.ModeWarn}, // unset -> warn (the design notes)
		{"off", verify.ModeOff},
		{"warn", verify.ModeWarn},
		{"block", verify.ModeBlock},
	}
	for _, tc := range cases {
		c := &Config{}
		c.Verify.Enabled = true
		c.Verify.Signature.Mode = tc.mode
		if got := c.VerifyPolicy().Signature.Mode; got != tc.want {
			t.Errorf("mode %q -> Signature.Mode %v, want %v", tc.mode, got, tc.want)
		}
	}
}
