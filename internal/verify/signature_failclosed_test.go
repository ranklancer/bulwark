package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Regression tests for the p849 §8 finding #4 / p842 fail-closed requirement:
// an EMPTY or FORGED signature must never be treated as trusted. These tests
// would FAIL against the estate's old non-empty-string check
// (`if [[ -z "$signature" ]]`, which accepted any non-empty string as
// "verified") and PASS against the real cosign-backed verifier wired into the
// verify gate. They pin the exact failure mode the finding named, so a future
// regression back to a presence-only check is caught here, not at deploy time.

// TestSignatureVerify_EmptyOutput_FailsClosed pins the EMPTY case: cosign
// exits non-zero with no output at all (no signature material found). The
// verifier must report a definitive untrusted verdict (Verified=false, Err=nil
// — a real signature verdict, not an unknown) and name the absence in Detail.
func TestSignatureVerify_EmptyOutput_FailsClosed(t *testing.T) {
	c := &CosignVerifier{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("an empty signature result must never verify")
	}
	if res.Err != nil {
		t.Fatalf("empty signature is a definitive untrusted verdict; Err must stay nil, got %v", res.Err)
	}
	if !strings.Contains(res.Detail, "no trusted signature found") {
		t.Fatalf("empty signature detail should name the absence, got %q", res.Detail)
	}
}

// TestSignatureVerify_ForgedSignature_FailsClosed pins the FORGED case: cosign
// rejects a present-but-invalid signature with a non-zero exit. A forged
// signature must be definitively untrusted — never an unknown, never verified.
func TestSignatureVerify_ForgedSignature_FailsClosed(t *testing.T) {
	c := &CosignVerifier{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("error: invalid signature when validating ASN.1 encoded signature"), errors.New("exit status 1")
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("a forged signature must never verify")
	}
	if res.Err != nil {
		t.Fatalf("forged signature is a definitive untrusted verdict; Err must stay nil, got %v", res.Err)
	}
}

// TestGate_EmptySignatureResult_FailsClosed pins the gate-level empty case: a
// verifier that returns no trusted signature (zero-value result) must produce
// DecisionBlock in block mode, with the untrusted reason surfaced.
func TestGate_EmptySignatureResult_FailsClosed(t *testing.T) {
	g := Gate{
		Policy:    Policy{Enabled: true, Signature: sigBlockPolicy()},
		Signature: &FakeSignatureVerifier{Result: SignatureResult{}},
	}
	v := g.Evaluate(context.Background(), Input{PinnedRef: "repo@sha256:abc"})
	if v.Decision != DecisionBlock || v.Allowed() {
		t.Fatalf("empty signature result in block mode must block, got %s", v.Decision)
	}
	if !hasReasonContaining(v.Reasons, "signature: untrusted or unsigned") {
		t.Fatalf("empty signature block must surface the untrusted reason, got %v", v.Reasons)
	}
}
