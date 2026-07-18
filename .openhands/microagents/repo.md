---
name: repo
type: repo
agent: CodeActAgent
---

# Bulwark — repo agent (always loaded)

You are operating inside **bulwark**, the intelligent Docker container update
guardian. This microagent encodes the non-negotiable conventions for every
change. Read it as doctrine, not suggestion.

Bulwark automates only the updates that are *safe* to automate: an update is
`classify → verify-gate → snapshot → apply → health-verify → notify/audit`. A
false BREAKING is annoying; a false SAFE is dangerous. Bias toward caution in
everything you touch.

## Your role in the loop

OpenHands is the **routine-tier producer only**. You author focused changes and
open a pull request. You are *not* the reviewer and *not* the merger. The
engineered dev-loop is:

`pull → plan → build → FULL GATE → document → open PR → independent adversarial review → auto-merge on clean`

Every change flows through that loop. You own `pull → … → open PR`. The
independent review-loop owns the rest.

## PR & branch discipline

- Branch from the default branch; prefix work branches `openhands/…`.
- **Never** push to the default branch (`main`). **Never** self-merge — the
  PR-only credential enforces this; do not attempt to work around it.
- One logical change per PR. Every PR enters the independent review-loop like
  any other change.
- Conventional Commits (`feat(verify): …`, `fix(config): …`, `chore(ci): …`).

## The full gate — MUST pass before you call anything done

CI and the pre-commit hook run the same target; mirror it locally. Do not mark
work complete without proof it is green.

- `make gate` — `gofmt` (via `make fmt`), `go vet ./...`, `go build ./...`,
  `go test -race -count=1 ./...`.
- `make lint` — `golangci-lint` (pinned `v1.61.0`; config `.golangci.yml`).
- `make cover` — **risk-tiered** per-package coverage floors
  (`scripts/coverage-floors.sh`; see `docs/the design notes-testing-quality-tiers.md`):
  security/logic packages carry an ~85% floor, the config/notifier base tier
  `COVER_MIN=74.0`; boilerplate is excluded, not padded. Floors **ratchet up**,
  never down.
- `make gate-full` = `gate lint cover` — the blocking bar.
- `make smoke` — `bash smoke/run.sh` (hermetic; no network, no Docker).
- **Secret + PII scan** — `gitleaks` and `scripts/check-pii.sh` run on every
  push and in the pre-commit hook (`./scripts/install-hooks.sh`).
- `goleak` (`go.uber.org/goleak`) guards against goroutine leaks in tests.
- **Advisory, not yet blocking:** `make vuln` (`govulncheck v1.1.4`) and
  `make sec` (`gosec v2.20.0`) — run them and act on real findings, but they
  are gated on maintainer decisions (see the pipeline-hardening notes in
  internal engineering notes). Do not silently wire them into `gate-full`; do not regress them.

Changes to the classifier (`internal/classifier`) need a test for every new
path **and** a rationale note for any policy change.

## Security doctrine (design constraint, not a phase)

- **Least privilege.** Bulwark needs only Docker Engine API access (prefer the
  read-mostly socket-proxy pattern) plus its data dir. Keep it that narrow.
- **Zero-leak.** Never commit or echo a secret — not even rotated ones; refer
  to secrets by shape/fingerprint. Config uses `${VAR}` expansion and the
  `_FILE` convention only; the API token is minted at `init` (mode 0600).
- **PII-clean.** No real IPs, emails, or domains in code, tests, or docs — use
  RFC-5737 / RFC-1918 ranges, `example.com`, and `noreply@…`.
- **Fail-closed.** An axis that cannot be evaluated blocks; an unset signature
  mode defaults to `block`; an invalid/expired break-glass label is ignored.
- **Root cause, not band-aid. Minimal surface.** Fix the actual defect; touch
  the least code that solves it; leave unrelated code alone. Every operation is
  idempotent and degrades gracefully.

## Repo context

- **Language/layout:** Go 1.22, module `github.com/ranklancer/bulwark`. A single
  static binary that embeds a React SPA. Small, deliberate dependency surface;
  it speaks the Docker Engine HTTP API directly (no Docker SDK).
- **Directories:** `cmd/bulwark` (entrypoint), `internal/` (classifier, api,
  registry, snapshot, verify, …), `pkg/`, `web/` (React + Vite dashboard),
  `configs/`, `docs/` (incl. ADRs), `scripts/`, `smoke/`.
- **Build:** `go build ./cmd/bulwark`. The full SPA needs Node 22+:
  `cd web && npm ci && npm run build`. The committed `dist/` placeholder lets
  `go build` succeed without Node (serving the legacy dashboard).
- **Install dev tooling:** `make tools` (pinned linter/vuln/sec versions; the
  box bakes Go 1.22.12 with `GOTOOLCHAIN=local`, so `@latest` will fail — bump
  pins deliberately).

## Tier note

The routine tier runs on **local Devstral**. Keep changes small, focused, and
verifier-friendly — narrow diffs, clear commit messages, tests alongside. If a
change wants to sprawl, stop and split it into reviewable PRs.
