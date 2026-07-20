---
name: repo
type: repo
agent: CodeActAgent
---

# Bulwark — OpenHands repo agent

## Read `AGENTS.md` first

The canonical agent instructions for this repository are in **`AGENTS.md` at the
repo root**. Read it at the start of every task. It is the single source of
truth for:

- what Bulwark is (Docker container update guardian;
  `classify → verify-gate → snapshot → apply → health-verify → notify/audit`)
- the engineered dev-loop and the **local-first worktree workflow**
- the **full gate** that must pass (`make gate-full`, smoke, gitleaks + PII scan)
- PR & branch discipline
- the security doctrine
- repo structure and build/test commands

Everything below is **OpenHands-lane specific only**. Shared conventions are not
repeated here — if this file and `AGENTS.md` ever disagree, `AGENTS.md` wins.

## OpenHands-specific

- **You are the routine-tier producer only.** Author a focused change and open a
  pull request. You do not review and you do not merge; the independent
  adversarial review-loop owns everything after the PR is opened.
- **Branch prefix:** this lane prefixes work branches **`openhands/…`** (the
  Claude lane uses its own prefixes). Branch from `main`.
- **Never push to `main`; never self-merge.** The PR-only credential enforces
  this — treat a permission error there as correct behavior, not an obstacle to
  route around.
- **Work in a git worktree and get the gate green locally before opening the
  PR.** Do not use CI as your iteration loop. Full sequence in `AGENTS.md`.
- **Tier:** this lane runs on **local Devstral**. Keep changes small, focused,
  and verifier-friendly — narrow diffs, tests alongside, clear commit messages.
  If a change wants to sprawl, stop and split it into separate reviewable PRs.
- **Node is required for the full dashboard build** (`cd web && npm ci &&
  npm run build`); `go build` alone succeeds against the committed `dist/`
  placeholder but serves the legacy dashboard. Check which one your change needs.
