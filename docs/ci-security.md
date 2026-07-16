# CI / supply-chain hardening

The workflows that build, test, and release Bulwark are themselves treated as a
supply-chain surface. The controls below reduce the blast radius of a
compromised Action, a leaked token, or an unreviewed change to a sensitive
path.

## Least-privilege `GITHUB_TOKEN`

Every workflow declares `permissions: {}` at the top level (deny by default).
Each job then grants only what it needs:

| Workflow / job | Permissions |
|---|---|
| `ci.yml` (all jobs) | `contents: read` |
| `gitleaks.yml` | `contents: read` |
| `release.yml` (build & push) | `contents: read`, `packages: write` |

`packages: write` is scoped to the single release job that pushes to GHCR, not
granted workflow-wide.

## SHA-pinned Actions

Every third-party Action is pinned to a full 40-character commit SHA, with the
human-readable version in a trailing comment (for example
`actions/checkout@34e1148… # v4.3.1`). Pinning to a mutable tag (`@v4`) would
let a retagged or compromised release run in CI; pinning to a SHA makes the
Action immutable and satisfies the OpenSSF Scorecard *Pinned-Dependencies*
check. Version bumps are deliberate, reviewable commits.

## Code ownership

`.github/CODEOWNERS` requires maintainer review on the security-sensitive
surfaces — the trust engine (`internal/verify`), admission gate
(`internal/admit`), scan-source parsers (`internal/cve`), reference handling
(`internal/registry`), the updater, the CLI/daemon wiring, and all CI/release
and dependency-manifest files. A repository ruleset ("Require review from Code
Owners") turns these entries into an enforced gate.

## Secret scanning

Secrets are scanned at three points: a local **pre-commit** `gitleaks` hook, a
dedicated **`gitleaks.yml`** workflow scanning full history on every push/PR,
and a **PII/host-identifier** scan (`scripts/check-pii.sh`) in both pre-commit
and CI. The ruleset is never weakened to silence a finding; confirmed false
positives are suppressed by fingerprint and real secrets are rotated.

## Vulnerability reporting

`SECURITY.md` documents private vulnerability reporting (via GitHub's Security
tab), response-time targets, and a coordinated-disclosure safe harbor.
