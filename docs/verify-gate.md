# Bulwark Deploy-Time Trust Gate

Status: P0 (signature + vulnerability axes, break-glass). Provenance (SLSA) and
the external admission API are planned for P1.

This document is maintained in accordance with ISO/IEC/IEEE 15289:2019
(information item content) and ISO/IEC/IEEE 26515:2018 (user documentation in an
agile life cycle). It contains no personally identifying information and no
secret material; all identifiers below are placeholders.

## 1. Scope

This document describes the configuration, behaviour, and operational
considerations of Bulwark's deploy-time trust gate (`verify:` configuration
block). It applies to the `bulwark run` daemon apply path. It does not cover the
stability classifier or the security-urgency axis, which are documented
separately.

## 2. Purpose

Bulwark automates safe container image updates. The trust gate exists to let
that automation proceed with confidence: it is a *trust engine*, not a friction
wall. Before an already-eligible update is applied, the gate confirms the exact
image about to be deployed is trusted. A passing verdict lets the normal
auto-apply flow continue; only a failing verdict holds or overrides the update.

## 3. Concepts

### 3.1 Axes

The gate evaluates up to two independent axes on the digest-pinned image:

- Signature — the image digest must carry a valid cosign signature from a
  trusted keyless identity (certificate SAN + OIDC issuer) or a trusted public
  key. Verification is performed by invoking a *pinned* `cosign` binary (see
  §4.1 and the design notes); Bulwark does not embed signing/verification cryptography
  and does not trust an unpinned `cosign` on `PATH`.
- Vulnerability — the image must carry no vulnerability at or above a configured
  severity threshold. Vulnerability data is read from the same pluggable CVE
  source used by the security-urgency feature (Trivy/Grype reports).

### 3.2 Modes

Each axis has an enforcement mode: `off` (not evaluated), `warn` (evaluated;
failures are surfaced but do not block), or `block` (evaluated; failures block
apply, subject to break-glass).

### 3.3 Verdicts

Evaluation yields one verdict per candidate image:

- `allow` — every enabled axis passed. Auto-apply proceeds.
- `warn` — an axis failed only in warn mode. Auto-apply proceeds; the failure is
  surfaced.
- `block` — a block-mode axis failed and no break-glass applied. The update is
  held; the updater is never invoked.
- `break_glass` — a block-mode axis failed but a valid break-glass override let
  the apply proceed. The override is recorded.

### 3.4 Fail-closed

The gate is fail-closed. In block mode, an axis that cannot be evaluated — a
verifier or source error, a missing `cosign` binary, or a missing dependency —
is treated as a failure, not a pass. When `verify.enabled` is false the gate is
inert and apply behaviour is unchanged.

## 4. Configuration reference

The `verify:` block (see `configs/bulwark.example.yaml`):

- `enabled` (bool) — master switch. `false` (default) is a no-op.
- `signature.mode` (`off`|`warn`|`block`) — defaults to `block` when `enabled`
  and left unset.
- `signature.identities[]` — allowed keyless signers, each `{ san, issuer }`.
  `san` is a regular expression matched against the certificate SAN. Any single
  match trusts the image.
- `signature.key` — path/ref to a cosign public key for keyed verification. When
  set, keyed verification is attempted first. Provide via `${VAR}` and a mounted
  secret; never commit key material.
- `signature.verifier` (`cosign`|`sigstore-go`) — signature backend. Defaults to
  `cosign`. `sigstore-go` is experimental and rejected at startup (see §4.1 and
  the design notes).
- `signature.cosign.binary` — path to the cosign executable (default: resolve
  `cosign` on `PATH`).
- `signature.cosign.version` — expected `cosign version` token (e.g. `2.4.1`).
  Required when the signature axis is active.
- `signature.cosign.digest` — expected SHA-256 of the cosign binary (bare hex or
  `sha256:`-prefixed). Required when the signature axis is active; a public,
  non-secret integrity value.
- `vuln.mode` (`off`|`warn`|`block`) — defaults to `block` when a threshold is
  set.
- `vuln.block_threshold` (`off`|`high`|`critical`) — the lowest severity that
  fails the axis. `off` disables the axis. Requires a configured
  `security.cve_source`.

At least one axis must be active when `enabled` is true; an all-inactive block
is rejected at startup.

## 4.1 Signature verifier backends

Signature verification is pluggable behind the `SignatureVerifier` interface.
Two implementations are planned; the first is the enabled default.

- cosign-binary (now, hardened) — the default. Shells out to a pinned `cosign`
  binary (version + sha256 digest, verified before use, fail-closed). Smallest
  dependency footprint; native support for registry image references.
- sigstore-go (fast-follow, not enabled) — an in-process backend built on
  sigstore-go bundle verification. Present as an interface-conformant stub and
  rejected at startup; the dependency is intentionally not yet added because it
  materially enlarges the module. For registry image references specifically,
  cosign's own verification package (the Kyverno pattern) is the recorded
  in-process option.

The trade-offs (module size, error typing, registry-image-verification
maturity) and the full rationale are recorded in the design notes
(`docs/the design notes-signature-verifier.md`).

## 5. Break-glass

A deliberate, audited override for shipping an image that would otherwise be
blocked (for example, a vendor image that is not yet signed). It is set with
container labels:

- `bulwark.verify.break-glass` — a non-empty human reason. Required to activate.
- `bulwark.verify.break-glass-expires` — optional RFC3339 timestamp. A past or
  unparseable expiry is not honoured (fail-closed).

Break-glass is intentionally easy to set but never silent: every honoured
override is written to the append-only audit log and counted in metrics.

## 6. Observability

Every verdict is surfaced through existing channels:

- Audit log (`audit.jsonl`): `apply.blocked` and `apply.break_glass` actions,
  with container, image, level, digest, and rationale.
- Live event stream: `apply.blocked` and `apply.break_glass` events.
- Notifiers: a blocked update is reported with the `Blocked` action.
- Metrics (`/metrics`): `bulwark_verify_verdicts_total{decision=...}`.

## 7. Runtime prerequisites

- A `cosign` binary matching the pinned `verify.signature.cosign.version` and
  `verify.signature.cosign.digest` must be available to the daemon for the
  signature axis. Its integrity is checked before first use; a missing or
  mismatched binary fails closed (blocks) rather than trusting ambient tooling.
- The vulnerability axis requires a configured `security.cve_source` (Trivy or
  Grype report directory).
- Signing key material and any webhook secrets are provisioned as Docker secrets
  sourced from the operator's secret manager; they are never stored in the
  configuration file or the repository.

## 8. Behaviour matrix (block mode)

| Signature | Vulnerability | Break-glass | Verdict      | Apply |
|-----------|---------------|-------------|--------------|-------|
| trusted   | clean         | -           | allow        | yes   |
| trusted   | >= threshold  | none        | block        | no    |
| untrusted | clean         | none        | block        | no    |
| untrusted | any           | valid       | break_glass  | yes   |
| untrusted | any           | expired     | block        | no    |
| unevaluable (error) | -   | none        | block        | no    |

## 9. Security considerations

- The gate verifies the digest-pinned reference that will actually be deployed,
  not merely the tag.
- Fail-closed ensures a broken verifier or missing tool cannot silently admit an
  untrusted image.
- Break-glass is bounded (optional expiry) and always audited, so operational
  overrides remain accountable.
- The gate complements, and does not replace, network- and identity-layer
  controls in front of the daemon.

## 10. Limitations and planned work

- P0 enforces on the `bulwark run` daemon apply path. The one-shot
  `bulwark scan --apply` path and dry-run verdict preview are planned follow-ups.
- P1: SLSA provenance via `cosign verify-attestation`, an external
  `GET /verify?image=...@digest` admission API for pre-reconcile checks, and a
  signed "verified digest" artifact.
