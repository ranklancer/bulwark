# Stage-B Dev-Loop Canary - Work Unit stg-aprime-canary-0010-150c15d9

## Purpose

This document is the tracked surface for staging work unit stg-aprime-canary-0010-150c15d9. It records, for a reader new to the repository, what the automated dev-loop verifies before a produced change is allowed to open a pull request. It describes only the generic stage contract and deliberately names no host, address, or credential.

## Stage sequence

The dev-loop runs each produced change through an ordered, fail-closed sequence. A stage must pass for the next one to run; any failure parks the change and stops the run.

1. Build gate: the change is built in an isolated worktree and the full build-and-test target must pass, reporting a coverage figure and a reproducible proof hash.
2. Parameter-freshness check: the run is rejected if it was produced against stale inputs, which prevents replay of an outdated build.
3. Configuration verification: a fixed set of trusted-config invariants (signature, manifest, and pin checks) must all hold before review begins.
4. Independent review: a separate reviewer inspects the produced diff against its declared surface and returns a verdict; only an explicit approval advances the run.
5. Provenance signing: the approved result is signed, and the run continues only when the signature is valid and the signer identity matches the expected pin.
6. Park: a draft pull request is opened for human approval. The pipeline never merges, so a person always owns the merge decision.

## Guarantees

- Fail-closed: a missing or unreadable artifact, a failed check, or a non-approving review each park the run instead of letting it proceed.
- Least authority: publish credentials are minted for the park step and revoked immediately after use.
- No auto-merge: the terminal action is a draft pull request only.

## Scope of this unit

Work unit stg-aprime-canary-0010-150c15d9 is a staging canary. Its only tracked surface is this document, which keeps the blast radius limited to documentation while still exercising the full stage sequence end to end.
