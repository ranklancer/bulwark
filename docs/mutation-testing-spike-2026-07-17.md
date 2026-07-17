# Mutation-testing spike — Gremlins on internal/verify (advisory)

Date: 2026-07-17
Status: Spike / feasibility report. **Advisory — not wired as a blocking gate.**

## Goal

Feasibility-test mutation testing on one security-core package to learn (a) the
tool's fit and runtime and (b) whether our tests actually *catch injected bugs*,
not just execute lines. Target: `internal/verify` (the trust engine).

## Tool

- **Gremlins** (`github.com/go-gremlins/gremlins`) — the actively-maintained
  modern Go mutation tester. Primary choice per direction; `go-mutesting`
  fallback not needed.
- **Version caveat (important for CI adoption):** the current release `v0.6.0`
  requires **Go >= 1.25**. This repo pins `GOTOOLCHAIN=local` on go1.22.12, so
  `go install ...@latest` fails to build. The spike ran against a
  Go-1.22-compatible Gremlins build already present on the runner. **Adopting
  Gremlins in CI implies a Go-toolchain bump** (or a pinned older Gremlins) —
  the same toolchain decision that currently keeps `govulncheck` advisory.

## Command

```
gremlins unleash ./internal/verify      # (dry-run first for mutant census)
```

## Results

| Metric | Value |
|---|---|
| Runnable mutants | 69 |
| Killed | 51 |
| **Lived (survivors)** | **7** |
| Not covered | 11 |
| Timed out | 11 |
| Not viable | 0 |
| **Test efficacy** (killed / (killed+lived)) | **87.93%** |
| Mutator coverage | 84.06% |
| Wall-clock runtime | **~25s** (1.7s coverage + 23.4s mutation), single package, on the dev runner |

Runtime is modest for one package (~25s). A repo-wide run scales with covered
mutants across all packages; a practical CI shape is **scoped to changed
security packages**, not the whole module.

## Surviving mutants (concrete "shallow test" findings)

Ordered by security relevance. These are places where an injected bug was NOT
caught by any test — candidates for the behavioural fail-closed test follow-up.

1. **`gate.go:166` CONDITIONALS_NEGATION** — break-glass "present but expired"
   branch (`if bg.Reason != "" && bg.Expired`). No test pins that an expired
   break-glass still **blocks** with the expected reason. *Security-relevant.*
2. **`gate.go:118`, `gate.go:120` CONDITIONALS_BOUNDARY** — boundary conditions
   in the gate decision path. Tests don't pin the exact threshold/branch edges.
   *Security-relevant.*
3. **`verify.go:186` CONDITIONALS_BOUNDARY** — `len(v.Vuln.Blocking) > 0` on the
   `RemediationVulnerable` path. The empty-vs-non-empty blocking boundary isn't
   pinned. *Security-relevant.*
4. **`signature.go:228` CONDITIONALS_NEGATION** — default-detail assignment
   (`if res.Detail == ""` -> "no trusted signature found"). Minor: a
   human-readable detail string, not a decision. *Low.*
5. **`signature.go:255`, `signature.go:259` CONDITIONALS_BOUNDARY** — inside the
   `firstLine` string-truncation helper (newline index, 200-char cap). Cosmetic
   formatting boundaries. *Low / acceptable.*

## Recommendation

- Keep Gremlins **advisory** for now (matches the direction).
- Feed survivors #1–#3 into the behavioural fail-closed test work (they are
  exactly the block/expiry/boundary paths that must not silently flip).
- **Before any CI wiring:** resolve the Go-toolchain constraint (Gremlins v0.6.0
  needs Go >= 1.25). If/when wired, run **scoped to changed security packages**
  with an efficacy threshold (start low, e.g. 80%, ratchet up), never a
  whole-module blocking run.
