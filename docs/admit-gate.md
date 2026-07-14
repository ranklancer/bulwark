# `bulwark admit` — deploy-time supply-chain admission gate (the admission-gate design, Phase 1)

`bulwark admit` evaluates the **supply-chain posture** of the images in one or
more compose files and returns **ALLOW / WARN / BREAK_GLASS / BLOCK**. It exits
non-zero on **BLOCK**, so it gates a deploy:

```sh
bulwark admit compose.yaml && docker compose up -d
```

It is the deploy-boundary counterpart to digest pinning (digest pinning) and the trust engine trust
engine (`internal/verify`): digest pinning makes images *pinnable*, the trust engine verifies a pinned
image's signature / SBOM / provenance / vulnerabilities during bulwark's own
update loop, and the admission gate runs that same trust engine at the moment a workload is
deployed — plus a new **pin-state axis**. See the admission-gate design for the full design.

## Axes

| Axis | Question | Source |
|---|---|---|
| pin-state | is the image digest-pinned? | ref carries `@sha256:` **or** the pin store holds a digest |
| signature | signed by a trusted identity? | the trust engine (`internal/verify`) |
| provenance / SBOM | trusted SLSA provenance / SBOM present? | the trust engine (SBOM warn-only, per an internal note) |
| vulnerability | free of CVEs at/above the block threshold? | the trust engine via the scan source |

An **unpinned** image cannot have its signature/SBOM/provenance/vulnerabilities
verified — there is no digest to attest — so the pin-state axis is the gate for
it. To enforce the trust axes you must first enforce pinning: **pin, then
verify.** The trust axes only run for pinned images.

## Modes & progressive enforcement

Each axis is Off / Warn / Block. The pin-state axis is set with `--pin-mode`
(`off|warn|block`, default **warn**); the signature/provenance/vulnerability
modes come from the verify policy in `--config`. Warn-default means adopting the
gate never breaks a running homelab — ratchet each axis to `block` as coverage
improves (per the design notes).

## Exit-code contract

- `allow`, `warn`, `break_glass` → exit **0** (deploy proceeds).
- `block` → exit **non-zero** (deploy refused).

Only BLOCK stops a deploy. WARN is advisory (visible in the report, exit 0). A
valid, **audited** break-glass converts a would-be block into `break_glass`
(exit 0, recorded on the audit trail) — the same mechanism the trust engine uses; there is no
un-audited override.

## Fail-closed

In block mode an axis that **cannot be evaluated** (verifier/source/network
error, or a missing dependency) is treated as a **failure, not a pass** — the
gate never silently allows an image it could not check.

## Usage

```sh
bulwark admit [--config bulwark.yaml] [--data-dir DIR] [--pin-mode off|warn|block] \
              [--format text|json] <compose.yaml> [<compose.yaml> ...]
```

- `--data-dir` — reads `pins.json` so a tag captured/pinned by `bulwark capture`
  counts as pinned even when the compose file still shows the tag.
- `--format json` — machine-readable per-image + aggregate verdict for pipelines.

## Scope (Phase 1) & limitations

- Targets are **compose files** parsed directly. Resolving any `capture.Source`
  backend (Dockge, Portainer, Komodo, quadlets, Unraid) and emitting the exact
  pinned digests to deploy is **Phase 2**.
- Enforcement is the **exit code** the operator wires in (`admit && up`).
  Transparent interception (a `docker compose` CLI plugin / pre-`up` hook) is
  **Phase 3**; until then an operator can run `docker compose up` directly and
  skip the gate (documented residual `T-shim`).
- Break-glass labels are supported by the engine but not yet extracted from
  compose service labels in Phase 1.
