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
