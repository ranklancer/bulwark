package verify

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
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
//
// Consistent with that pinned-artifact doctrine, the verifier never trusts the
// ambient cosign on PATH: before the binary is invoked it is checked against a
// config-driven pin (both an expected version AND an expected sha256 of the
// executable). If the pinned binary is missing, unreadable, or does not match,
// every Verify returns an unknown result (Err set) that the fail-closed gate
// treats as a block. Pinning is disabled only when both Version and Digest are
// empty (retaining the pre-hardening behaviour for callers that opt out).
type CosignVerifier struct {
	Bin     string        // cosign executable; "" => "cosign"
	Timeout time.Duration // per-verification bound; 0 => 60s

	// Version is the token the pinned cosign binary must report from
	// `cosign version` (matched as a substring of the command output, e.g.
	// "2.4.1"). Empty disables version pinning. Config-driven; never hardcoded.
	Version string

	// Digest is the expected SHA-256 of the cosign binary file, hex-encoded and
	// optionally "sha256:"-prefixed. The on-disk bytes are hashed and compared
	// before the binary is invoked. Empty disables digest pinning. Config-driven;
	// never hardcoded.
	Digest string

	// run is the exec seam. nil uses os/exec; tests inject a fake so unit tests
	// never require cosign to be installed.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)

	// readBinary is the file-read seam used by the digest check. nil uses
	// os.ReadFile; tests inject a fake so the integrity check needs no real
	// binary on disk.
	readBinary func(path string) ([]byte, error)

	// lookPath resolves a bare binary name to a filesystem path for hashing.
	// nil uses exec.LookPath; tests that pin a digest pass an explicit path.
	lookPath func(file string) (string, error)

	mu          sync.Mutex
	integrityOK bool // memoized success of the one-time integrity check
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
	cmd := exec.CommandContext(cctx, c.bin(), args...) // #nosec G204 -- cosign binary and args from config; exec argv, no shell
	return cmd.CombinedOutput()
}

// readBin reads the cosign executable's bytes for the digest check.
func (c *CosignVerifier) readBin(path string) ([]byte, error) {
	if c.readBinary != nil {
		return c.readBinary(path)
	}
	return os.ReadFile(path) // #nosec G304 -- key/cert path from the operator verify config
}

// resolveBinPath returns the filesystem path of the cosign binary. An explicit
// path (containing a separator) is used as-is; a bare name is resolved on PATH.
func (c *CosignVerifier) resolveBinPath() (string, error) {
	b := c.bin()
	if strings.ContainsRune(b, os.PathSeparator) || strings.ContainsRune(b, '/') {
		return b, nil
	}
	lp := c.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	return lp(b)
}

// ensureIntegrity verifies the pinned cosign binary once, before first use. It
// is fail-closed: any inability to confirm the pin returns an error. Success is
// memoized; a failure is retried on the next call.
func (c *CosignVerifier) ensureIntegrity(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.integrityOK {
		return nil
	}
	if err := c.checkIntegrity(ctx); err != nil {
		return err
	}
	c.integrityOK = true
	return nil
}

// checkIntegrity enforces the digest and version pins. It reads/executes only
// through the seams so it is fully testable without a real cosign binary.
func (c *CosignVerifier) checkIntegrity(ctx context.Context) error {
	// Digest pin: hash the on-disk binary and compare in constant time.
	if want := normalizeDigest(c.Digest); want != "" {
		path, err := c.resolveBinPath()
		if err != nil {
			return fmt.Errorf("cosign binary not found for digest pin: %w", err)
		}
		data, err := c.readBin(path)
		if err != nil {
			return fmt.Errorf("cosign binary unreadable for digest pin: %w", err)
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return fmt.Errorf("cosign binary digest mismatch: pinned sha256:%s but on-disk is sha256:%s", want, got)
		}
	}
	// Version pin: run `cosign version` and require the pinned token appears.
	if want := strings.TrimSpace(c.Version); want != "" {
		out, err := c.exec(ctx, "version")
		if err != nil {
			if isExecUnavailable(err) {
				return fmt.Errorf("cosign unavailable for version pin: %w", err)
			}
			return fmt.Errorf("cosign version check failed: %w", err)
		}
		if !strings.Contains(string(out), want) {
			return fmt.Errorf("cosign version mismatch: pinned %q not reported by the binary", want)
		}
	}
	return nil
}

// Verify tries keyed verification first (when a key is configured), then each
// configured keyless identity. The first success wins. A non-zero cosign exit
// is a definitive "not trusted" (Err stays nil); only an inability to run
// cosign at all — or a failed integrity pin — sets Err, which the fail-closed
// gate treats as a block.
func (c *CosignVerifier) Verify(ctx context.Context, pinnedRef string, pol SignaturePolicy) SignatureResult {
	res := SignatureResult{Evaluated: true}

	// Integrity gate: never trust ambient tooling. If the cosign binary is
	// missing or does not match its pinned version+digest, we cannot trust any
	// verdict it would produce, so return an unknown result the gate blocks on.
	if err := c.ensureIntegrity(ctx); err != nil {
		res.Err = fmt.Errorf("cosign integrity check failed: %w", err)
		res.Detail = "pinned cosign binary failed integrity verification"
		return res
	}

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

// normalizeDigest lowercases and strips an optional "sha256:" prefix, returning
// the bare hex digest ("" if the input is blank).
func normalizeDigest(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "sha256:")
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
