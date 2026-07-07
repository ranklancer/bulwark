package verify

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestCosignVerify_TrustedKeyless(t *testing.T) {
	var gotArgs []string
	c := &CosignVerifier{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		return []byte("{}"), nil // exit 0 == verified
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: "^https://github.com/ranklancer/.+$", Issuer: "https://token.actions.githubusercontent.com"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if !res.Verified {
		t.Fatalf("expected verified, detail=%q err=%v", res.Detail, res.Err)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "--certificate-identity-regexp") || !strings.Contains(joined, "--certificate-oidc-issuer") {
		t.Fatalf("cosign args missing identity flags: %s", joined)
	}
	if gotArgs[len(gotArgs)-1] != "repo@sha256:abc" {
		t.Fatalf("last arg must be the pinned ref, got %s", gotArgs[len(gotArgs)-1])
	}
}

func TestCosignVerify_UntrustedIsDefinitiveNotError(t *testing.T) {
	c := &CosignVerifier{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("error: no matching signatures"), errors.New("exit status 1")
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("must not be verified")
	}
	if res.Err != nil {
		t.Fatalf("a non-zero cosign exit is definitive, Err must stay nil, got %v", res.Err)
	}
}

func TestCosignVerify_MissingBinaryFailsUnknown(t *testing.T) {
	c := &CosignVerifier{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, &exec.Error{Name: "cosign", Err: exec.ErrNotFound}
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Err == nil {
		t.Fatal("missing cosign binary must set Err (unknown -> fail closed upstream)")
	}
}

func TestCosignVerify_KeyedPreferred(t *testing.T) {
	var sawKey bool
	c := &CosignVerifier{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		for i, a := range args {
			if a == "--key" && i+1 < len(args) && args[i+1] == "/keys/pub.pem" {
				sawKey = true
			}
		}
		return []byte("{}"), nil
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Key: "/keys/pub.pem"}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if !res.Verified || !sawKey {
		t.Fatalf("keyed verify must pass --key, verified=%v sawKey=%v", res.Verified, sawKey)
	}
}

func TestCosignVerify_SecondIdentityMatches(t *testing.T) {
	calls := 0
	c := &CosignVerifier{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("no match"), errors.New("exit status 1")
		}
		return []byte("{}"), nil
	}}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: "a"}, {SANRegexp: "b"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if !res.Verified || calls != 2 {
		t.Fatalf("second identity should match after first fails, verified=%v calls=%d", res.Verified, calls)
	}
}

func TestFakeSignatureVerifier_RecordsCalls(t *testing.T) {
	f := &FakeSignatureVerifier{Result: SignatureResult{Verified: true}}
	f.Verify(context.Background(), "repo@sha256:abc", SignaturePolicy{})
	if len(f.Calls) != 1 || f.Calls[0] != "repo@sha256:abc" {
		t.Fatalf("fake must record the pinned ref, got %v", f.Calls)
	}
}
