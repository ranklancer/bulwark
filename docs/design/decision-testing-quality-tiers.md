# the design notes: Risk-tiered coverage floors and testing quality

Status: Accepted
Date: 2026-07-17

## Context

Coverage was gated by a single global floor (`COVER_MIN`, 74% of total
statements). A global-average floor has two failure modes for a security tool:

1. **It hides regressions in the code that matters.** A trust-engine package can
   lose meaningful coverage while the average stays green, propped up by
   high-coverage boilerplate elsewhere.
2. **It rewards hollow tests.** The cheapest way to lift a global average is to
   line-fill pure data types and `main()` wiring with assertions that execute
   code but verify little. That buys a number, not assurance.

The an internal audit audit surfaced several sub-floor packages. Rather than chase a uniform
74% by padding boilerplate, we tier the requirement by risk.

## Decision

Coverage is enforced **per package**, sized to the package's risk, by
`scripts/coverage-floors.sh` (statement-weighted, computed directly from the
coverage profile). The gate is wired into `make cover` / `make gate-full`.

**Tiers (target floors — the enforced end-state):**

- **Security / logic tier — 85%.** The trust- and mutation-critical packages:
  `internal/verify`, `internal/admit`, `internal/registry`, `internal/cve`,
  `internal/reconcile`, `internal/capture`, `internal/updater`. Coverage here
  must come from **behavioural, fail-closed tests** (assert the block/deny/error
  paths), not happy-path line-filling.
- **Base tier — 74%.** Supporting packages with untrusted-input handling but a
  lower blast radius: `internal/config`, `internal/configstore`,
  `internal/notifier`.
- **Default — 74%** for every other measured package.

**Excluded from the metric entirely** (neither floored nor counted in the
total) — genuine boilerplate where line coverage measures nothing useful:

- `pkg/types` — pure data types and enum String/JSON plumbing.
- `cmd/bulwark`, `cmd/bulwark-diun-relay` — `main()`, flag parsing, exit and
  HTTP-server bootstrap wiring (exercised by smoke tests, not units).
- `internal/api/ui` — HTML dashboard render wiring with no own tests, exercised
  only indirectly through `internal/api` integration tests.

## Ratchet policy

Floors **never decrease**. Where a package is currently below its tier target,
the script encodes an **interim floor at its present level** to prevent
backsliding, and the gap to target is closed by adding real tests (see the
behavioural-test and fuzzing follow-ups), after which its floor is raised toward
the target. This keeps every intermediate PR green while the trend is monotonic.

Interim floors at time of adoption (target in parentheses):
`verify 78 (85)`, `registry 76 (85)`, `cve 81 (85)`, `capture 82 (85)`,
`updater 81 (85)`; `admit 85` and `reconcile 85` already meet target;
`config 71 (74)`, `configstore 73 (74)`, `notifier 71 (74)`.

## Consequences

- A drop in any security package fails the gate immediately, independent of the
  average — the regression can't hide.
- Contributors are steered toward behavioural tests on risky code and away from
  padding boilerplate for a number.
- Adding a new package picks up the 74% default unless explicitly tiered; new
  boilerplate must be justified and added to the exclusion list in the script
  (and here), not silently averaged away.
- The interim floors are a ledger of known test-quality debt with an explicit
  target, not a permanent resting point.
