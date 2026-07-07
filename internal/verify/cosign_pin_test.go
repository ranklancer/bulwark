package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeBinary is stand-in bytes for the cosign executable; tests hash these to
// derive a matching pin, so no real cosign binary is ever required.
var fakeBinary = []byte("pretend-this-is-the-cosign-binary-v2.4.1")

func fakeBinaryDigest() string {
	sum := sha256.Sum256(fakeBinary)
	return hex.EncodeToString(sum[:])
}

// goodVersionRunner answers `cosign version` with the pinned token and any
// `cosign verify ...` with success (exit 0 == verified).
func goodVersionRunner(version string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "version" {
			return []byte("GitVersion:    " + version + "\n"), nil
		}
		return []byte("{}"), nil
	}
}

func TestCosignPin_GoodBinaryPasses(t *testing.T) {
	c := &CosignVerifier{
		Bin:        "/opt/cosign/cosign",
		Version:    "2.4.1",
		Digest:     "sha256:" + fakeBinaryDigest(),
		run:        goodVersionRunner("2.4.1"),
		readBinary: func(_ string) ([]byte, error) { return fakeBinary, nil },
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Err != nil {
		t.Fatalf("pinned-good binary must not error, got %v", res.Err)
	}
	if !res.Verified {
		t.Fatalf("pinned-good binary should verify, detail=%q", res.Detail)
	}
}

func TestCosignPin_WrongDigestFailsClosed(t *testing.T) {
	c := &CosignVerifier{
		Bin:        "/opt/cosign/cosign",
		Version:    "2.4.1",
		Digest:     strings.Repeat("f", 64), // deliberately not the real hash
		run:        goodVersionRunner("2.4.1"),
		readBinary: func(_ string) ([]byte, error) { return fakeBinary, nil },
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("a digest mismatch must never verify")
	}
	if res.Err == nil {
		t.Fatal("a digest mismatch must set Err (unknown -> fail closed upstream)")
	}
	if !strings.Contains(res.Err.Error(), "digest mismatch") {
		t.Fatalf("error should name the digest mismatch, got %v", res.Err)
	}
}

func TestCosignPin_MissingBinaryFailsClosed(t *testing.T) {
	c := &CosignVerifier{
		Bin:        "/opt/cosign/cosign",
		Version:    "2.4.1",
		Digest:     "sha256:" + fakeBinaryDigest(),
		run:        goodVersionRunner("2.4.1"),
		readBinary: func(_ string) ([]byte, error) { return nil, os.ErrNotExist },
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("a missing binary must never verify")
	}
	if res.Err == nil {
		t.Fatal("a missing pinned binary must set Err (fail closed)")
	}
}

func TestCosignPin_VersionMismatchFailsClosed(t *testing.T) {
	c := &CosignVerifier{
		Bin:        "/opt/cosign/cosign",
		Version:    "2.4.1",
		Digest:     "sha256:" + fakeBinaryDigest(),
		run:        goodVersionRunner("2.3.0"), // reports a different version
		readBinary: func(_ string) ([]byte, error) { return fakeBinary, nil },
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("a version mismatch must never verify")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "version mismatch") {
		t.Fatalf("a version mismatch must set a naming Err, got %v", res.Err)
	}
}

func TestCosignPin_UnpinnedRetainsAmbientBehaviour(t *testing.T) {
	// No Version/Digest => integrity check skipped; the verifier behaves exactly
	// as before hardening. readBinary must never be consulted.
	c := &CosignVerifier{
		run: goodVersionRunner("whatever"),
		readBinary: func(_ string) ([]byte, error) {
			t.Fatal("readBinary must not be called when unpinned")
			return nil, nil
		},
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Err != nil || !res.Verified {
		t.Fatalf("unpinned verifier should behave as before, verified=%v err=%v", res.Verified, res.Err)
	}
}

func TestCosignPin_IntegrityMemoizedAfterSuccess(t *testing.T) {
	reads := 0
	c := &CosignVerifier{
		Bin:        "/opt/cosign/cosign",
		Version:    "2.4.1",
		Digest:     "sha256:" + fakeBinaryDigest(),
		run:        goodVersionRunner("2.4.1"),
		readBinary: func(_ string) ([]byte, error) { reads++; return fakeBinary, nil },
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	_ = c.Verify(context.Background(), "repo@sha256:abc", pol)
	_ = c.Verify(context.Background(), "repo@sha256:def", pol)
	if reads != 1 {
		t.Fatalf("integrity check should run once and memoize, binary read %d times", reads)
	}
}

func TestCosignPin_UntrustedIsStillDefinitiveWithValidPin(t *testing.T) {
	// A valid pin plus a non-zero cosign exit is a definitive "untrusted":
	// Verified=false but Err stays nil (a real signature verdict, not unknown).
	c := &CosignVerifier{
		Bin:     "/opt/cosign/cosign",
		Version: "2.4.1",
		Digest:  "sha256:" + fakeBinaryDigest(),
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "version" {
				return []byte("GitVersion: 2.4.1"), nil
			}
			return []byte("error: no matching signatures"), errors.New("exit status 1")
		},
		readBinary: func(_ string) ([]byte, error) { return fakeBinary, nil },
	}
	pol := SignaturePolicy{Mode: ModeBlock, Identities: []Identity{{SANRegexp: ".*"}}}
	res := c.Verify(context.Background(), "repo@sha256:abc", pol)
	if res.Verified {
		t.Fatal("must not verify an unsigned image")
	}
	if res.Err != nil {
		t.Fatalf("a definitive untrusted verdict must keep Err nil, got %v", res.Err)
	}
}
