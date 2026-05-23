# Phase 4 — Measurement + CI (perf/ci-budget)

Branch carries four commits. Splits the gate into deterministic
(bundle-size budget; hard fail) and exploratory (Lighthouse CI;
best-effort while we collect a baseline) so PR signal is high.

| # | Commit subject | Files touched |
|---|---|---|
| 1 | `perf: Phase 4 plan doc` | `docs/perf-phase-4-plan.md` |
| 2 | `perf: bundle-size budget gate` | `web/scripts/perf-budget.mjs` (new), `web/package.json`, `web/README.md` |
| 3 | `perf: Lighthouse CI config` | `web/.lighthouserc.json` (new), `web/package.json`, `web/README.md` |
| 4 | `perf: CI workflow runs both perf gates` | `.github/workflows/ci.yml` |

## What each commit ships

### 2 — Bundle-size budget
- `web/scripts/perf-budget.mjs` walks
  `../internal/api/ui-react/dist/assets/`, gzips each file in
  memory, and reports per-file sizes. Fails (exit 1) when any of:
  - Single chunk > **200 KB** gzipped.
  - Entry + vendor combined > **350 KB** gzipped.
  - Total CSS > **40 KB** gzipped.
- Thresholds tunable via env vars
  (`BULWARK_PERF_PER_CHUNK_GZ_KB`, `BULWARK_PERF_ENTRY_GZ_KB`,
  `BULWARK_PERF_CSS_GZ_KB`) so the operator can ratchet down without
  a code change.
- `npm run perf:check` is the local-dev alias.
- Today's build PASSES all three budgets — they're honest starter
  numbers, not aspirations. Phase 3's lazy-route landing left
  headroom; a follow-up PR can tighten once we have stable numbers.

### 3 — Lighthouse CI config
- `web/.lighthouserc.json` configures `@lhci/cli` to:
  - Spin up bulwark in the runner via
    `bulwark serve --no-docker --listen :8080` (anonymous mode;
    CI-only, never production).
  - Hit `http://localhost:8080/` once with `preset=desktop`.
  - Assert LCP < 1500 ms, total transfer < 500 KB, CLS < 0.1.
- `npm run perf:lighthouse` is the local-dev alias (runs LHCI
  against an already-running daemon).
- LHCI ships as `npx`-only (not in `devDependencies`) so
  `package-lock.json` stays skinny and the Chromium download only
  happens in the perf job.

### 4 — CI workflow
- New `perf` job in `.github/workflows/ci.yml`:
  - Runs after `build-test` (needs the SPA build to grade).
  - Hard-fail step: bundle-size budget.
  - Best-effort step: LHCI (`continue-on-error: true` until we
    have a baseline; flipped to hard fail in a follow-up).
- Job is unconditional (runs on every PR); the cost is ~30 s of
  setup + ~10 s of actual checks. Worth the always-on signal.

## What this phase deliberately does NOT do

- A CI step that auths against a live `bulwark.example.com`.
  No stored creds in CI for that surface; the in-runner anonymous
  bulwark is the auditable baseline.
- A historical perf graph / regression-over-time chart. LHCI's
  upload-to-storage is wired off; the per-run summary in the job
  log is enough.
- Auto-tightening of budgets. Operator decides when to ratchet.

## Verification

After all four commits land:

```sh
# Local: should PASS with current numbers
cd web
npm run build
npm run perf:check
```

Manual CI confirmation (on a draft PR):
1. `perf budget` job appears in checks and goes green.
2. Deliberately balloon the bundle (e.g. add a huge dep), push,
   confirm `perf budget` goes red.
3. Confirm the LHCI step prints a real LCP/transfer/CLS reading
   in its log even when it doesn't fail the job.
