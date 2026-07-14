# Design note — the admission-gate design Phase 2 (first slice): `${VAR}`-expansion digest resolution

Status: implemented behind the full gate, parked for review. Spec: the admission-gate design (internal engineering notes). Component: `internal/admit` + `bulwark admit`.

## Boundary

Phase 1's pin-state axis keyed off the reference **as written** (`capture.ImageRef.Raw`). A compose image whose digest arrives via variable expansion —

```yaml
services:
  app:
    image: nginx@${DIGEST}   # with a co-located .env: DIGEST=sha256:…
```

— therefore read as **UNPINNED** (a documented false-negative, PR #59), even though the concrete reference compose would deploy (`nginx@sha256:…`) *is* digest-pinned. A fully var-defined `image: ${IMG}` has the same problem.

## Decision

admit recognises a digest that arrives through `.env`/`${VAR}` expansion as **pinned**, and hands the resolved digest to the trust engine trust engine for verification (signature / SBOM / provenance / vuln) exactly as for a hard-coded digest. The compose parser already resolves the reference into `ImageRef.Ref` via `expandVars` over the co-located `.env` (pure string substitution — `${VAR}`, `${VAR:-default}` — no code execution); admit consumes that resolved value.

### Pin provenance is surfaced

Each admitted image carries a `PinSource`:

- `literal` — a digest in the ref as written,
- `var` — resolved from `.env`/`${VAR}` expansion,
- `store` — captured by `bulwark capture`.

It is reported per-image (text `pinned(var)` / JSON `pin_source`), so a var-sourced pin is transparent rather than silently equivalent to a hard pin. Precedence: `literal` → `var` → `store` → unpinned.

## Resolution model & the safe direction

admit resolves `${VAR}` from the **co-located `.env` only** (`loadDotEnv(dir)`), which is a *subset* of the sources `docker compose` consults (`.env` **plus** process/shell env, with shell taking precedence). Consequences:

- An unresolved `${VAR}` (no `.env` value, no default) leaves no digest → admit reads it **UNPINNED** (warn/block per pin-mode). admit **under-resolving is the safe direction** — it never invents a pin.
- A var that expands to a **tag** (`nginx:${TAG}` → `nginx:1.27`) has no digest → still UNPINNED. Only digests count.

## Residual `T-env-drift` (documented)

Because compose also honours shell env (above `.env`), a `${DIGEST}` overridden in the deploy shell could make `docker compose up` deploy a *different* digest than the one admit verified from `.env`. Mitigations:

1. `bulwark admit` is a **pre-`up` gate**; run it in the same environment / working directory as `up`.
2. A var-sourced pin is reported `PinSource=var`, so the weaker provenance is visible; operators wanting the strongest guarantee hard-pin the digest in the compose file.
3. A future slice may reconcile admit's resolver with compose's full env precedence, or emit the exact resolved digests to deploy (the Phase-2 T-toctou item), closing the drift entirely.

## Scope

admit-only (engine `PinSource` plumbing + `admitPinState` + report). **No new parser** — reuses the already-fuzzed compose extractor; string-only logic added. The broader Phase-2 items (`capture.Source`-resolved targets; emit-pinned-digests) remain queued.
