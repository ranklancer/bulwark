# Verify-before-pull

Bulwark refuses to pull an image during an auto-update until that image's
supply-chain trust has been evaluated. This is the flagship guard that
separates bulwark from a bare update poller: an update is not *applied*
before it is *verified*.

It is the update-loop counterpart to the admission gate (the deploy-time admission gate).
the admission gate gates a workload at deploy; verify-before-pull gates the *pull* that an
auto-update would otherwise perform. Both drive the same the trust engine trust engine
(`internal/verify`).

> **Note:** verify-before-pull only engages when the updater is given a
> verifier. With no verify policy wired, the updater behaves exactly as
> before (backward-compatible): it pulls and recreates without a trust
> check. To enforce, configure the trust axes (signature / provenance /
> vulnerabilities) so `bulwark run` builds a non-nil gate.

## Where it sits in the update pipeline

```
inspect -> [verify-before-pull] -> pre-update hook -> PULL -> recreate -> health -> rollback
                    |
                    +-- not digest-pinned?  -> REFUSE (fail closed, no pull)
                    +-- verdict.Blocked()?  -> REFUSE (no pull)
                    +-- allow / warn        -> proceed to hook + pull
```

The check runs *before* the pre-update hook and *before* the pull, so a
blocked update never touches the registry or the running container.

## Decision rules

| Condition | Outcome | Rationale |
|---|---|---|
| target is not digest-pinned (`@sha256:...`) | REFUSE, no pull | an unpinned ref cannot be attested; a tag can be re-pointed between verify and pull (TOCTOU) |
| verifier returns `Block` | REFUSE, no pull | signature / provenance / vulnerability policy failed |
| verifier returns `Allow` / `Warn` / `BreakGlass` | proceed | trust satisfied (or explicitly overridden) |
| no verifier configured | proceed | backward-compatible; feature is opt-in |

Digest-pinning is checked with the canonical `registry.IsSHA256Digest`
matcher, not a substring test, so only a well-formed `sha256:<64 hex>`
digest counts as pinned.

The refusal is **fail-closed**: any state that cannot be positively
verified (unpinned target, verifier error surfaced as a block) stops the
pull. Bulwark never pulls an image it could not attest.

## Result fields

`updater.Result` carries the outcome for callers and logs:

- `VerifyDecision` — the `verify.Decision` returned by the engine
  (empty when no verifier ran).
- `VerifyBlocked` — `true` when verify-before-pull aborted the update
  (either an unpinned target or a blocking verdict). When set, `Err`
  explains why and no pull was attempted.

## Scope and non-goals

- Engages on the auto-update trigger (`bulwark run` daemon loop). The
  reconcile/decision layer already gates candidates via the trust engine; this guard
  closes the *apply* path so a queued candidate cannot be pulled
  unverified.
- Does **not** resolve a mutable tag to a digest on the user's behalf
  (a future phase). Today an unpinned target is refused, not rewritten.
- Does **not** re-implement verification: it delegates entirely to the
  the trust engine engine. Policy, thresholds, and break-glass live there.

See the verify-before-pull design for the full design, threat model, and phased plan.

## Break-glass

A verdict of `BreakGlass` — a block-mode trust failure overridden by a valid,
audited break-glass **label** — is honored at the pull boundary, not just at
the deploy-time decision gate. To reach it, the target container's labels are
forwarded into the trust gate (`verify.Input.Labels`); without them the
override was unreachable and a break-glassed update would be re-blocked at the
pull step. When it fires, the updater:

- sets `Result.VerifyBreakGlass = true`;
- emits a distinct audit log (`updater: verify-before-pull OVERRIDDEN by
  break-glass`) with the reason and summary;
- proceeds to pull (break-glass is an allow, not a block).

The deploy-time gate records the store audit event; this closes the loop at the
pull boundary so an override is never silent.

## Where the gate runs

Verify-before-pull is wired wherever bulwark applies an update:

| Trigger | Gate wiring |
|---|---|
| `bulwark run` (daemon auto-update) | `upd.Verify` set from the verify config |
| `bulwark scan --apply` (one-shot) | `attachVerifyGate` sets `upd.Verify` from the same config |
| `bulwark apply` | shared apply path; labels forwarded via `ApplyOptions.Labels` |

`scan --apply` previously constructed its updater **without** the gate, so a
one-shot apply could pull an unverified image while the daemon blocked it.
`attachVerifyGate` closes that bypass and fails closed at startup on a broken
gate. When verification is disabled the wiring is a no-op (backward-compatible).
