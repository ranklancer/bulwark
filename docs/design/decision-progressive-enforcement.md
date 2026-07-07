# the design notes: Progressive-enforcement (safe-default) posture for the signature gate

Status: Proposed (for review). Supersedes: none. Superseded by: none.
Date: 2026-07-07.

This architecture decision record is maintained in accordance with
ISO/IEC/IEEE 15289:2019 (information item content) and ISO/IEC/IEEE 26515:2018
(user and system documentation in an agile life cycle). It contains no
personally identifying information and no secret material; all identifiers are
placeholders or public, non-secret configuration tokens.

> This ADR is a PROPOSAL for review. It does not change any current default in
> code. The artifact is the decision record; adoption (and any code change) is
> a separate, explicit step. See section 3.5 for exactly what is and is not
> being changed.

## 1. Scope

This record proposes the default *enforcement posture* of the deploy-time trust
gate's signature axis (`verify.signature`, `internal/verify`) — that is, how
strict the gate is on a fresh deployment and how an operator should progress to
full enforcement. It complements the design notes, which covers how signatures are
verified (the pinned cosign shell-out). It does not propose changes to the
verifier implementation, the vulnerability axis, or break-glass.

## 2. Context

The trust gate is opt-in (`verify.enabled: false` by default; the gate is
inert until switched on). Once enabled, the signature axis today resolves an
unset `verify.signature.mode` to `block` (`Config.signatureMode()` returns
`ModeBlock`), and the gate is fail-closed: an axis that cannot be evaluated
blocks rather than passes.

That default is secure, but for an auto-updating fleet it is a footgun. On a
fresh deployment `verify.signature.identities[]` is empty, so no keyless signer
is trusted yet. The first time an operator sets `verify.enabled: true`, every
image whose signature is absent, from an unlisted signer, or unverifiable
resolves to a blocking verdict — which can instantly halt the fleet's
auto-updates. The predictable operator reaction to "enabling security stopped
all my updates" is to disable the gate entirely, which yields *no* signature
checking at all: the strict default produces the least secure steady state.

The principle behind the scan tooling's recommendation is therefore:
**secure-by-default, but not a footgun** — enabling the gate should never be an
all-or-nothing cliff, and the safe path to full enforcement should be the
documented, obvious one.

## 3. Decision (proposed)

### 3.1 Fresh-deploy default: warn, not block

On a fresh enablement of the signature axis (verify just turned on, no
`identities[]` populated, `mode` unset), the effective default should be
`warn` (or, as an alternative discussed in section 6, `off`) rather than
`block`. Enabling the gate then *observes and reports* rather than halting
updates. Fail-closed evaluation is preserved *within* whatever mode is active;
this proposal concerns only the initial mode selection, not the meaning of
`block`.

### 3.2 Documented progression to enforcement

Enforcement is reached by a short, documented progression rather than a single
switch:

1. **warn** — enable the axis in `warn`. Bulwark evaluates every candidate and
   reports would-block verdicts without stopping applies.
2. **gather telemetry** — collect, over a representative window, (a) the set of
   images that *would* block and (b) the signer identities actually observed
   (SAN + OIDC issuer) on the images the operator already trusts in practice.
3. **populate `signature.identities[]`** — from that telemetry, add the
   intended keyless signers (and/or a `key` for keyed verify), so the trusted
   set reflects the real fleet.
4. **flip to `block`** — set `verify.signature.mode: block` once the would-block
   set has converged to only genuinely untrusted images.

### 3.3 Remediation-aware verdict output

To make the progression tractable, a blocking (or would-block) verdict should
explain *why* and *how to fix it*, not merely that it blocked. Each verdict
should distinguish at least: no signature present; signature present but signer
not in `identities[]` (surfacing the observed SAN/issuer so it can be added);
and verifier unavailable / pin mismatch (pointing at the cosign pin in
the design notes). The remediation text names the concrete next action (e.g. "add an
identity with san=… issuer=…", "provision the pinned cosign binary").

### 3.4 Principle to bake in vs. specifics to keep operational

What should be baked into Bulwark as durable design principle:

- **Secure-by-default-but-not-a-footgun**: enabling a gate must not instantly
  break a working fleet.
- **Progressive enforcement**: warn -> observe -> enumerate trust -> enforce is
  a first-class, documented workflow with the tooling (telemetry + remediation
  output) to support it.

What should remain per-fleet operational detail (not encoded as policy): the
actual `identities[]` list, the length of the observation window, and the
exact timing of the flip to `block`.

### 3.5 Explicitly NOT changed by this ADR

- No code default is flipped. `signatureMode()` still resolves an unset mode to
  `block` until and unless this proposal is accepted and implemented separately.
- The meaning of `block` and the fail-closed "unevaluable axis blocks" rule are
  unchanged.
- `verify.enabled` remains `false` by default.

## 4. Trade-offs

| Posture | On fresh enable | Security during onboarding | Failure mode | 
|---------|-----------------|-----------------------------|--------------|
| block-by-default (today) | May halt all auto-updates | Strongest — nothing unsigned passes | Operator disables the gate -> no checking at all | 
| warn-by-default (proposed) | Updates continue; would-blocks reported | Observing, not enforcing, until flipped | Operator never flips to block -> enforcement never begins | 
| off-by-default | No effect until configured | None until configured | Same as warn, minus the telemetry signal | 

The proposed posture accepts a bounded window of observe-only enforcement in
exchange for an onboarding path operators will actually complete, on the
argument that a fleet that reaches `block` after a week of `warn` is more
secure than one that blocks on day one and gets switched off on day two. The
residual risk (operators who never flip to `block`) is mitigated by the
remediation output and by surfacing "you are still in warn" as a visible state.

## 5. Consequences

- If adopted, the change touches: the unset-mode default in the signature axis
  (fresh-enable resolves to warn), the verdict/telemetry surface (would-block +
  observed-signer reporting), and remediation strings — plus documentation of
  the progression. It does not touch the verifier backends (the design notes).
- Operators get a safe onramp: turning the gate on is non-destructive, and the
  path to enforcement is explicit and tool-assisted.
- Documentation (`docs/verify-gate.md`) would gain the warn -> block runbook.

## 6. Open questions for review

1. **warn vs off as the fresh default.** `warn` gives immediate telemetry (the
   would-block set and observed signers) at the cost of doing verification work
   with no enforcement; `off` is the most conservative "no surprises" default
   but yields no signal until explicitly configured. Recommendation: `warn`,
   for the telemetry.
2. **Auto-population of `identities[]`.** Should observed signers be offered as
   a reviewed suggestion (operator confirms) rather than written automatically,
   to avoid trusting an attacker's signer that happened to appear during the
   window? Recommendation: suggest, never auto-trust.
3. **Telemetry location and retention** for the would-block/observed-signer
   data (reuse the existing state store vs. notifier-only), and whether a
   "still in warn after N days" reminder should be emitted.
