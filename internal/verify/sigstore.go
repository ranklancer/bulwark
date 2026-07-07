package verify

import (
	"context"
	"fmt"
)

// SigstoreVerifier is the planned fast-follow signature verifier built on the
// sigstore-go library's bundle-verification API — sigstore-go's production-
// stable surface. It is EXPERIMENTAL and NOT ENABLED in this build.
//
// Why a stub, not an implementation (the design notes, docs/the design notes-signature-verifier.md):
//
//   - go.mod size. The whole point of the cosign shell-out is a tiny module
//     (today: two direct requires). Linking sigstore-go pulls in a large
//     transitive tree (the sigstore libraries, protobuf-specs, TUF, x509
//     tooling), which defeats that goal. We do not add the dependency until a
//     bundle-verification path is actually needed.
//   - Registry image-ref maturity. sigstore-go's stable, ergonomic surface is
//     bundle verification (an offline .sigstore bundle). Verifying a signature
//     that lives in an OCI registry alongside the image — Bulwark's actual input
//     — is better served by cosign's own verification package (the Kyverno
//     pattern) as a separate fast-follow.
//
// The type conforms to SignatureVerifier so it can be selected via config once
// implemented, and so a mistaken selection fails closed rather than silently
// admitting an image: every Verify returns an unknown result (Err set) that the
// block-mode gate treats as a block. Selection is additionally rejected at
// config-validation time (see internal/config/verify.go) so an operator gets
// immediate, startup-time feedback instead of a per-image block.
type SigstoreVerifier struct {
	// BundlePath is a placeholder for the future offline-bundle source. It is
	// intentionally unused until the implementation lands.
	BundlePath string
}

// Verify is a fail-closed placeholder. It never admits an image.
func (s *SigstoreVerifier) Verify(_ context.Context, _ string, _ SignaturePolicy) SignatureResult {
	return SignatureResult{
		Evaluated: true,
		Err:       fmt.Errorf("sigstore-go verifier is experimental and not enabled in this build; select verifier %q (see docs/the design notes-signature-verifier.md)", "cosign"),
		Detail:    "sigstore-go verifier not enabled",
	}
}

// compile-time assertion that the stub satisfies the interface.
var _ SignatureVerifier = (*SigstoreVerifier)(nil)
