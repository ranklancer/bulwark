# the design notes: Signature verifier implementation strategy for the trust gate

Status: Accepted (P0). Supersedes: none. Superseded by: none.
Date: 2026-07-07.

This architecture decision record is maintained in accordance with
ISO/IEC/IEEE 15289:2019 (information item content) and ISO/IEC/IEEE 26515:2018
(user and system documentation in an agile life cycle). It contains no
personally identifying information and no secret material; all identifiers are
placeholders or public, non-secret integrity metadata.

## 1. Scope

This record documents how Bulwark's deploy-time trust gate
(`internal/verify`, `verify:` configuration block) performs container image
*signature* verification, and the plan for evolving that mechanism. It does not
cover the vulnerability axis, the stability classifier, or break-glass, which
are described in `docs/verify-gate.md`.

## 2. Context

The trust gate must confirm that the exact digest-pinned image about to be
applied carries a signature from a trusted identity. Signature verification is
security-critical cryptography that Bulwark deliberately does not re-implement.
Three implementation approaches were considered:

1. Shell out to the `cosign` binary (the proven CLI primitive).
2. Link the `sigstore-go` library and verify Sigstore *bundles* in-process.
3. Link cosign's own verification package (`pkg/`), the pattern Kyverno uses,
   to verify signatures attached to an image in an OCI registry in-process.

Two forces dominate the decision:

- Dependency surface. A core design goal of Bulwark is a small binary and a
  tiny module graph — the same rationale behind talking to the Docker Engine
  API directly instead of importing the Docker SDK. Today `go.mod` has two
  direct requirements.
- Bulwark's actual input. The gate is handed a registry image reference
  pinned by digest (`repo@sha256:...`), not an offline bundle file.

## 3. Decision

### 3.1 Now (P0): hardened cosign-binary shell-out — default

`internal/verify.CosignVerifier` shells out to `cosign verify`. It is the
default and only enabled backend. To keep the gate from trusting *ambient*
tooling — consistent with Bulwark's pinned-artifact, direct-Engine-HTTP
doctrine — the binary is pinned and its integrity is verified before use:

- The operator pins BOTH an expected version and an expected SHA-256 digest of
  the `cosign` executable, via configuration (`verify.signature.cosign.version`
  and `verify.signature.cosign.digest`). Neither value is hardcoded.
- Before the binary is invoked, its on-disk bytes are hashed and compared to
  the pinned digest (constant-time), and `cosign version` is checked against the
  pinned version. The check runs once and is memoized on success.
- The behaviour is fail-closed: a missing, unreadable, wrong-digest, or
  wrong-version binary yields an "unknown" result that the block-mode gate
  treats as a block. It never silently trusts whatever `cosign` is on `PATH`.
- When the signature axis is active, configuration validation *requires* the
  pin (version + well-formed sha256), so an operator cannot enable the gate
  against ambient tooling by omission.

Rationale: smallest dependency graph (integrity check uses only the Go standard
library — `crypto/sha256`, `crypto/subtle`, `encoding/hex`), a mature and
widely trusted verifier, and direct support for registry image references.

### 3.2 Fast-follow: `sigstore-go` bundle verification — stubbed, not enabled

`internal/verify.SigstoreVerifier` is an interface-conformant stub selectable
via `verify.signature.verifier: sigstore-go`. It is EXPERIMENTAL and NOT
ENABLED: selecting it is rejected at configuration-validation time (fail-closed,
startup feedback), and the stub itself returns a fail-closed "unknown" result if
ever constructed directly. The `sigstore-go` dependency is intentionally NOT
added to `go.mod`.

Rationale for stub-plus-ADR rather than a full implementation now: adding
`sigstore-go` pulls in a large transitive tree (the Sigstore libraries,
protobuf-specs, TUF, x509 tooling), which materially bloats the module and
defeats the purpose of the shell-out. `sigstore-go`'s production-stable,
ergonomic surface is *bundle* verification (an offline `.sigstore` bundle),
whereas Bulwark's input is a registry image reference; adopting it well implies
either producing/fetching bundles or waiting for its registry-image-ref path to
mature.

### 3.3 Fast-follow: cosign `pkg/` in-process — registry image-refs (Kyverno pattern)

For verifying signatures that live in an OCI registry alongside the image —
Bulwark's actual input — the better in-process option is cosign's own
verification package, the approach Kyverno uses. This is recorded as the
preferred path for an eventual in-process implementation, gated behind the same
`SignatureVerifier` interface and the same go.mod-size trade-off review.

## 4. Trade-offs

| Backend | go.mod / binary size | Error typing | Registry image-ref maturity | Status |
|---------|----------------------|--------------|-----------------------------|--------|
| cosign binary (shell-out) | Smallest — stdlib only | Coarse (exit code + text) | Native (cosign's core use) | Enabled default (P0), pinned + fail-closed |
| sigstore-go (bundle) | Large transitive tree | Rich, typed Go errors | Bundle-first; image-ref path less mature | Stub only, not enabled |
| cosign pkg/ (in-process) | Large (much of cosign) | Typed Go errors | Native | Recorded, not implemented |

The principal trade-off Bulwark accepts today: coarse error typing and a
process boundary, in exchange for a tiny dependency graph and native registry
image-ref support. Typed errors and an in-process path are the motivations to
revisit when the dependency-size cost is justified.

## 5. Consequences

- The `SignatureVerifier` interface (`Verify(ctx, pinnedRef, pol)
  SignatureResult`) is the stable seam; all three backends conform to it, so a
  future switch does not disturb the gate, the reconcile interception, or the
  audit/metrics surface.
- Operators must provision a pinned `cosign` binary (version + digest) to run
  the signature axis. Runtime prerequisites are documented in
  `docs/verify-gate.md`.
- The digest is public integrity metadata (not a secret) and is safe to store
  in configuration; signing keys and webhook secrets remain Docker secrets,
  never committed.

## 6. Revisiting criteria

Reconsider enabling an in-process backend when: (a) typed verification errors
are needed for finer verdict messaging; (b) removing the runtime `cosign`
dependency outweighs the module-size cost; or (c) `sigstore-go`'s registry
image-reference verification reaches the same maturity as its bundle path.
