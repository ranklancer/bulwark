package verify

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SignatureResult is the outcome of the signature axis for one image.
type SignatureResult struct {
	Evaluated bool
	Verified  bool
	Identity  string // matched signer identity (SAN regexp), when verified keyless
	Issuer    string // matched OIDC issuer, when verified keyless
	Err       error  // non-nil => verification could not be completed (unknown)
	Detail    string // short human-readable detail (never contains secrets)
}

// SignatureVerifier checks that a digest-pinned image reference carries a
// trusted signature under the given policy. Implementations must be safe for
// concurrent use and must not mutate the image.
type SignatureVerifier interface {
	Verify(ctx context.Context, pinnedRef string, pol SignaturePolicy) SignatureResult
}

// CosignVerifier verifies signatures by shelling out to the cosign binary. We
// adopt the proven primitive rather than linking sigstore-go, keeping Bulwark's
// binary small and its dependency surface tiny — the same design choice the
// docker client makes by speaking the Engine API directly instead of importing
// the Docker SDK.
type CosignVerifier struct {
	Bin     string        // cosign executable; "" => "cosign"
	Timeout time.Duration // per-verification bound; 0 => 60s
	// run is the exec seam. nil uses os/exec; tests inject a fake so unit tests
	// never require cosign to be installed.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (c *CosignVerifier) bin() string {
	if c.Bin != "" {
		return c.Bin
	}
	return "cosign"
}

func (c *CosignVerifier) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 60 * time.Second
}

func (c *CosignVerifier) exec(ctx context.Context, args ...string) ([]byte, error) {
	if c.run != nil {
		return c.run(ctx, c.bin(), args...)
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(), args...)
	return cmd.CombinedOutput()
}

// Verify tries keyed verification first (when a key is configured), then each
// configured keyless identity. The first success wins. A non-zero cosign exit
// is a definitive "not trusted" (Err stays nil); only an inability to run
// cosign at all sets Err, which the fail-closed gate treats as a block.
func (c *CosignVerifier) Verify(ctx context.Context, pinnedRef string, pol SignaturePolicy) SignatureResult {
	res := SignatureResult{Evaluated: true}

	if pol.Key != "" {
		out, err := c.exec(ctx, "verify", "--key", pol.Key, "--output", "json", pinnedRef)
		if err == nil {
			res.Verified = true
			res.Detail = "verified with configured key"
			return res
		}
		if isExecUnavailable(err) {
			res.Err = fmt.Errorf("cosign unavailable: %w", err)
			return res
		}
		res.Detail = firstLine(out)
	}

	for _, id := range pol.Identities {
		args := []string{"verify", "--certificate-identity-regexp", id.SANRegexp}
		if id.Issuer != "" {
			args = append(args, "--certificate-oidc-issuer", id.Issuer)
		}
		args = append(args, "--output", "json", pinnedRef)
		out, err := c.exec(ctx, args...)
		if err == nil {
			res.Verified = true
			res.Identity = id.SANRegexp
			res.Issuer = id.Issuer
			res.Detail = "verified keyless identity"
			return res
		}
		if isExecUnavailable(err) {
			res.Err = fmt.Errorf("cosign unavailable: %w", err)
			return res
		}
		res.Detail = firstLine(out)
	}

	if res.Detail == "" {
		res.Detail = "no trusted signature found"
	}
	return res
}

// isExecUnavailable reports whether err means cosign could not be executed at
// all (missing binary), as opposed to running and reporting an untrusted image.
func isExecUnavailable(err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	var ee *exec.Error
	return errors.As(err, &ee)
}

// firstLine returns a trimmed first line of output, bounded so log/audit detail
// stays tractable.
func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const cap = 200
	if len(s) > cap {
		s = s[:cap] + "..."
	}
	return s
}

// FakeSignatureVerifier is a test double: it returns a programmed result and
// records the pinned refs it was asked to verify.
type FakeSignatureVerifier struct {
	Result SignatureResult
	Calls  []string
}

// Verify records the call and returns the programmed result.
func (f *FakeSignatureVerifier) Verify(_ context.Context, pinnedRef string, _ SignaturePolicy) SignatureResult {
	f.Calls = append(f.Calls, pinnedRef)
	r := f.Result
	r.Evaluated = true
	return r
}
