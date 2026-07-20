# AGENTS.md — Bulwark

**Canonical agent instructions for this repository.** Every coding agent — Claude
Code, OpenHands, or a human following the same loop — reads *this* file.
`CLAUDE.md` and `.openhands/microagents/repo.md` are thin pointers here; do not
duplicate content into them.

## What this repo is

**Bulwark** is an intelligent Docker container update guardian. It watches
registries, classifies the risk of each pending update (semver + release notes),
runs candidates through a deploy-time **verify-gate** (cosign signature +
vulnerability), snapshots the filesystem, applies, verifies health, and rolls
back on failure.

Lifecycle: `classify → verify-gate → snapshot → apply → health-verify → notify/audit`

The mandate is narrow and deliberate: **automate the updates that are safe to
automate, and only those.** A false BREAKING is annoying; a false SAFE is
dangerous. Bias toward caution in everything you touch.

Bulwark is the *verify* stage of the suite:
forge ([ecumene](https://github.com/ranklancer/ecumene)) → **verify (bulwark)** →
act ([juridical](https://github.com/ranklancer/juridical)).

## The engineered dev-loop

`pull → plan → build → FULL GATE → document → open PR → independent adversarial review → auto-merge on clean`

Agents are the **routine-tier producer only**. You author focused changes and
open a pull request. You are *not* the reviewer and *not* the merger. The
independent adversarial review-loop owns everything after the PR is opened.

### Local-first workflow

Work in a real checkout; do not iterate through CI.

1. **Pull** the default branch and create a **git worktree** for the change:
   `git worktree add ../bulwark-<slug> -b <branch> origin/main`
   A worktree keeps the change isolated and leaves your primary checkout clean.
2. **Plan** before code: approach, files touched, risks, definition of done. Any
   task of three or more steps, or any architectural decision, gets a plan first.
   If execution diverges from the plan, stop and replan.
3. **Build**, then **run the full gate locally** and **iterate until green**.
   A red gate is not a PR.
4. **Document** the change (code comments where non-obvious, docs/ or an ADR
   where the decision is architectural).
5. **Open the PR** only once the gate is green locally.
6. Remove the worktree when the PR merges: `git worktree remove ../bulwark-<slug>`

## PR & branch discipline

- Branch from the default branch (`main`). The **OpenHands lane** prefixes work
  branches `openhands/…`.
- **Never push to `main`.** **Never self-merge** — the PR-only credential
  enforces this; do not attempt to work around it.
- One logical change per PR. Every PR enters the independent review-loop like
  any other change.
- Conventional Commits (`feat(verify): …`, `fix(config): …`, `chore(ci): …`).

## The full gate — MUST pass before anything is "done"

CI and the pre-commit hook run the same targets; mirror them locally. Never mark
work complete without proof it is green — unverified means unfinished.

- `make gate` — `gofmt` (via `make fmt`), `go vet ./...`, `go build ./...`,
  `go test -race -count=1 ./...`.
- `make lint` — `golangci-lint` (pinned `v1.61.0`; config `.golangci.yml`).
- `make cover` — **risk-tiered** per-package coverage floors
  (`scripts/coverage-floors.sh`; see `docs/the design notes-testing-quality-tiers.md`):
  security/logic packages carry an ~85% floor, the config/notifier base tier
  `COVER_MIN=74.0`; genuine boilerplate is excluded rather than padded with
  hollow tests. Floors **ratchet up**, never down.
- **`make gate-full` = `gate lint cover`** — the blocking bar.
- `make smoke` — `bash smoke/run.sh` (hermetic: no network, no Docker).
- **Secret + PII scan** — `gitleaks` and `scripts/check-pii.sh` run on every push
  and in the pre-commit hook (install with `./scripts/install-hooks.sh`).
- `goleak` (`go.uber.org/goleak`) guards against goroutine leaks in tests.
- **Advisory, not yet blocking:** `make vuln` (`govulncheck v1.1.4`) and
  `make sec` (`gosec v2.20.0`). Run them and act on real findings, but both are
  gated on maintainer decisions (Go patch level vs. `GOTOOLCHAIN=local`; gosec
  triage in the capture/store/registry paths). Do not silently wire them into
  `gate-full`, and do not regress them.

Changes to the classifier (`internal/classifier`) require a test for every new
path **and** a rationale note for any policy change.

## Security doctrine

Security is a **design constraint from the first line**, never a later phase.

- **Least privilege.** Bulwark needs only Docker Engine API access (prefer the
  read-mostly socket-proxy pattern) plus its data directory. Keep it that narrow.
- **Zero-leak.** Never commit, echo, or log a secret — in chat, logs, command
  lines, or files; not even rotated ones. Refer to secrets by shape or
  fingerprint only. Config uses `${VAR}` expansion and the `_FILE` convention;
  the API bearer token is minted at `init` (mode 0600). Secret *values* never
  appear in logs or error messages.
- **PII-clean.** No real IPs, emails, or domains in code, tests, or docs — use
  RFC-5737 / RFC-1918 ranges, `example.com`, and `noreply@…`. Enforced by
  `scripts/check-pii.sh`.
- **Fail-closed.** An enabled verify axis that cannot be evaluated blocks; an
  unset signature mode defaults to `block`; an invalid or expired break-glass
  label is ignored rather than honored. Never loosen a control to force a pass.
- **Digest-pinning and pinned tooling.** Reason about images by registry digest,
  not mutable tags. The signature axis refuses an ambient `cosign` — version and
  `sha256` must both be pinned.
- **Root cause, not band-aid.** Fix the actual defect; no patches that mask
  symptoms.
- **Minimal impact / minimal surface.** Touch the least code that achieves the
  goal; leave unrelated code alone. Every operation is idempotent and degrades
  gracefully.

## Repo context

- **Language:** Go 1.22, module `github.com/ranklancer/bulwark`. A single static
  binary that embeds a React SPA. Small, deliberate dependency surface
  (`gopkg.in/yaml.v3`, `brotli`, `goleak`); it speaks the **Docker Engine HTTP
  API directly — no Docker SDK**, keeping the surface auditable.
- **Layout:**
  - `cmd/bulwark` — entrypoint / CLI
  - `internal/` — classifier, api, registry, snapshot, verify, config, notifier
  - `pkg/` — exported types
  - `web/` — React + Vite dashboard (embedded)
  - `configs/` — example + minimal YAML config
  - `docs/` — reference docs and ADRs
  - `scripts/` — `check-pii.sh`, `coverage-floors.sh`, `install-hooks.sh`
  - `smoke/` — hermetic end-to-end smoke suite
- **Build:** `go build ./cmd/bulwark`. The full SPA needs Node 22+:
  `cd web && npm ci && npm run build`. The committed `dist/` placeholder lets
  `go build` succeed without Node (serving the legacy dashboard instead).
- **Dev tooling:** `make tools` installs the pinned linter/vuln/sec versions.
  The box bakes Go 1.22.12 with `GOTOOLCHAIN=local`, so `@latest` installs fail
  the toolchain gate — bump pins deliberately.

## Tier note

The routine tier runs on **local Devstral**. Keep changes small, focused, and
verifier-friendly — narrow diffs, tests alongside, clear commit messages. If a
change wants to sprawl, stop and split it into separate reviewable PRs.
