# Bulwark

[![CI](https://github.com/ranklancer/bulwark/actions/workflows/ci.yml/badge.svg)](https://github.com/ranklancer/bulwark/actions/workflows/ci.yml)
[![Secret scan](https://github.com/ranklancer/bulwark/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/ranklancer/bulwark/actions/workflows/gitleaks.yml)
[![Go 1.22](https://img.shields.io/badge/go-1.22-00ADD8.svg)](go.mod)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

> **Don't just update. Understand what changed — then prove it's trusted before you apply it.**

Bulwark is an intelligent Docker container update guardian. It watches your
container registries, classifies the risk of each pending update by reading
release notes and comparing semantic versions, runs each candidate image
through a deploy-time **verify-gate** (signature + vulnerability), takes
filesystem-level snapshots, applies the update, verifies health, and rolls
back automatically on failure.

The goal is narrow and deliberate: **automate the updates that are safe to
automate, and only those.** A patch bump from a signed, vulnerability-clean
image should apply itself at 3 a.m. without waking anyone. Anything that is
unsigned, vulnerable, ambiguous, or breaking should stop and ask. Bulwark is
the machinery that draws — and enforces — that line.

It is a spiritual successor to Watchtower (archived December 2025) and goes
substantially further: every update is _understood_ and _verified_ before it
is applied.

---

## Table of contents

- [Why Bulwark?](#why-bulwark)
- [How an update flows](#how-an-update-flows)
- [Three-tier risk classification](#three-tier-risk-classification)
- [The deploy-time verify-gate](#the-deploy-time-verify-gate)
- [Install & quick start](#install--quick-start)
- [CLI](#cli)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security posture](#security-posture)
- [Dashboard](#dashboard)
- [HTTP API](#http-api)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why Bulwark?

The most-requested Watchtower features were never delivered. Bulwark treats
them as the baseline:

| Capability                | Watchtower | **Bulwark**                          |
| ------------------------- | ---------- | ------------------------------------ |
| Detect updates            | ✓          | ✓                                    |
| Risk-classify updates     | —          | ✓ (semver + release-note analysis)   |
| Read release notes        | —          | ✓ (GitHub Releases, DockerHub)       |
| Verify signatures          | —          | ✓ (cosign, keyless or keyed)         |
| Verify vulnerabilities     | —          | ✓ (Trivy / Grype, threshold-gated)   |
| Filesystem snapshots      | —          | ZFS / Btrfs / Restic                 |
| Health-verified rollback  | —          | ✓ (container + filesystem)           |
| Compose-aware apply        | partial    | `depends_on` topological order       |
| Per-container policies     | binary     | rich (stack + container overrides)   |
| Rich notifications        | basic      | per-channel + digest                 |
| Pre / post / rollback hooks | —          | ✓ (sandboxed)                        |
| Web dashboard             | —          | full SPA + live updates (SSE)        |
| SSO / MFA                 | —          | forward-proxy + bearer               |
| Audit log                 | —          | append-only JSONL                    |
| Prometheus metrics        | —          | ✓                                    |

---

## How an update flows

```
registry digest moves
        │
        ▼
   classify ────────────►  SAFE / REVIEW / BREAKING   (semver + release notes)
        │
        ▼
   verify-gate ─────────►  signature axis (cosign)  +  vuln axis (Trivy/Grype)
        │                  fail-closed · off | warn | block · audited break-glass
        ▼
   snapshot ────────────►  ZFS / Btrfs / Restic
        │
        ▼
   apply ───────────────►  pull + recreate (Compose depends_on order)
        │
        ▼
   health-verify ───────►  rollback container + restore snapshot on failure
        │
        ▼
   notify + audit ──────►  Slack / Discord / HA / SMTP / webhook · append-only log
```

The classifier decides *whether an update is safe to automate*. The verify-gate
decides *whether the specific image is trusted enough to let that automation
proceed*. Both must agree before an update applies unattended.

---

## Three-tier risk classification

Every update is sorted into one of three buckets:

- **SAFE** — auto-update. Patch version bumps, image rebuilds without version
  changes, LinuxServer.io `-ls<n>` rebuilds.
- **REVIEW** — notify and wait for explicit approval. Minor version bumps,
  `:latest`-tag movements, anything mentioning "migration required" in the
  release notes.
- **BREAKING** — block until forced. Major version bumps, anything mentioning
  "breaking change" or "incompatible" in the release notes.

The risk level is chosen using a configurable policy. The classifier reads
release notes from GitHub Releases and DockerHub descriptions, scans them for
breaking-change keywords, and combines that with semantic-version analysis and
per-container Docker labels. Over-classification is a design choice: a false
BREAKING is annoying, a false SAFE is dangerous.

---

## The deploy-time verify-gate

Classification answers "is this *kind* of update safe to automate?" The
verify-gate answers a second, independent question just before apply: **"is
*this specific image* trusted enough to let automation proceed?"** It is
**opt-in** (`verify.enabled: false` by default — zero behavior change) and
evaluated at the reconcile chokepoint, so nothing applies without passing it.

Trust is evaluated on two axes, and both are **fail-closed** — an axis that
cannot be evaluated blocks rather than passes:

**Signature axis (cosign).** The image digest must carry a valid cosign
signature from a trusted keyless identity (Fulcio/OIDC SAN + issuer) or a
trusted key. Bulwark never reinvents crypto: it shells out to a **pinned
cosign binary** whose expected `version` *and* `sha256` digest are both
required when the axis is active — the gate verifies against a known-good tool
instead of whatever `cosign` happens to be on `PATH`.

**Vulnerability axis (Trivy / Grype).** The image must carry no vulnerability
at or above a configured `block_threshold` (`high` or `critical`). Findings
come from the pluggable CVE source (`security.cve_source`, Trivy first, Grype
available) that also powers Bulwark's security-urgency signals.

Each axis runs in one of three modes — `off`, `warn`, or `block`:

| Mode    | Behavior                                                              |
| ------- | -------------------------------------------------------------------- |
| `off`   | Axis is not evaluated.                                                |
| `warn`  | Axis is evaluated; failures are surfaced (notify + audit) but apply proceeds. |
| `block` | Axis is evaluated; a failure holds the update (subject to break-glass). |

A verdict is one of `allow`, `warn`, `block`, or `break_glass`. Only `block`
stops an apply.

**Audited break-glass.** A deliberate, one-off deploy of an otherwise-blocked
image is authorized with container labels — never silently:

```yaml
labels:
  bulwark.verify.break-glass: "CVE-2026-1234 patched upstream, waiting on Trivy DB"
  bulwark.verify.break-glass-expires: "2026-07-10T00:00:00Z"   # optional, RFC3339
```

A non-empty reason is required. An expiry is optional but, once set, is
fail-closed: a past or unparseable timestamp is **not** honored. Every honored
override is stamped into the append-only audit log and counted in `/metrics`.

Full reference: **[`docs/verify-gate.md`](docs/verify-gate.md)**. The choice of
a pinned cosign binary over an embedded library is recorded in
**[the design notes](docs/the design notes-signature-verifier.md)**.

---

## Install & quick start

### Run from a published image

```sh
# 1. Generate a starter config + bearer token in one shot.
mkdir -p config data
docker run --rm -v $(pwd)/config:/config \
    ghcr.io/ranklancer/bulwark:latest \
    init --output /config/bulwark.yaml
# This prints the bearer token to stdout — copy it; it appears once.

# 2. Run the daemon.
docker compose -f docker-compose.example.yaml up -d

# 3. Open the dashboard.
open http://localhost:8080/    # paste the token at /login
```

The dashboard's `/login` page exchanges the bearer token for an HTTP-only
session cookie — the token is never stored in the browser. Pages auto-update
as scans complete and apply outcomes land, over Server-Sent Events.

Operators who prefer to manage the token via env-var substitution can copy
`configs/bulwark.minimal.yaml` instead and set `BULWARK_API_TOKEN` in `.env`.
Both paths produce a working daemon.

### Build from source

Source builds need both Go (1.22+) and Node (22+) so Vite can emit the React
bundle the binary embeds:

```sh
git clone https://github.com/ranklancer/bulwark
cd bulwark
cd web && npm ci && npm run build && cd ..
go build ./cmd/bulwark
./bulwark init --output ./bulwark.yaml
./bulwark run --config ./bulwark.yaml --data-dir ./data
```

The committed `internal/api/ui-react/dist/` placeholder lets `go build`
succeed without Node — but the resulting binary serves the legacy vanilla
dashboard at `/` instead of the SPA. Run `npm run build` at least once for the
full experience.

### Docker access & storage permissions

Two operational details commonly trip up a first deployment: how Bulwark
reaches the Docker daemon, and who owns its data directory.

**Reaching the Docker daemon.** `docker.host` (config) / `--docker-host` (flag)
accepts several forms, so a socket proxy is a first-class, supported option —
not a workaround:

- *(empty)*, a path (`/var/run/docker.sock`), or `unix:///path` — a Unix socket.
- `tcp://host:port` — a TCP endpoint, e.g. a
  [`docker-socket-proxy`](https://github.com/Tecnativa/docker-socket-proxy).
- `http://host` / `https://host` — an HTTP endpoint.

The **recommended** pattern, shown in
[`docker-compose.example.yaml`](docker-compose.example.yaml), places a
read-mostly socket-proxy in front of the daemon and points Bulwark at it with
`docker.host: tcp://socket-proxy:2375`. Only the proxy container mounts
`/var/run/docker.sock` (read-only); Bulwark never sees the raw socket, so a
compromised Bulwark cannot drive the daemon directly, and the proxy scopes the
API surface (`CONTAINERS`, `IMAGES`, `POST`, …) to exactly what Bulwark needs.

*Advanced — mounting the socket directly.* If you skip the proxy and bind-mount
`/var/run/docker.sock` into the Bulwark container, the container user must be in
the socket's owning group. Discover the group id and grant it (the Docker
group's GID varies by distro and NAS platform, so read it rather than assuming
`999`):

```sh
stat -c '%g' /var/run/docker.sock   # Linux; prints the Docker group's GID
```

```yaml
services:
  bulwark:
    group_add:
      - "999"   # replace with the GID printed above
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

Direct-mount forfeits the API-surface filtering the proxy provides; prefer the
socket-proxy pattern wherever possible.

**Data directory ownership.** Unlike tools that run as root, the Bulwark image
runs as a **non-root** `bulwark` user created at build time. `/config` is
mounted read-only and `/data` (SQLite state, dedup, configstore) must be
writable by that user. When you bind-mount a host directory for `/data` and hit
a permission error, `chown` it to Bulwark's uid:gid. Read the numeric ids
straight from the image rather than hardcoding them — they are Alpine
system-user defaults and can shift with the base image:

```sh
docker run --rm --entrypoint id ghcr.io/ranklancer/bulwark:<tag> bulwark
# e.g. uid=100(bulwark) gid=101(bulwark)
chown -R 100:101 ./data             # use the ids printed above
```

Notes: a *named volume* (rather than a bind mount) is seeded from the image's
ownership, so no manual `chown` is needed; on SELinux hosts add `:z`/`:Z` to the
volume mount; rootless Docker and Podman remap container uids and may need no
`chown` at all.

---

## CLI

`bulwark <command> [flags]` — run `bulwark <command> --help` for command-specific options.

| Command           | Purpose                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `init`            | Generate a starter config + fresh bearer token (mode 0600).             |
| `run`             | Run the daemon: periodic scan loop + HTTP server in one always-on process. |
| `serve`           | Run the HTTP server only (DIUN webhook receiver) — no scan loop.        |
| `scan`            | Scan local Docker containers for pending updates.                       |
| `check`           | Resolve registry digests, fetch release notes, and classify one update. |
| `classify`        | Classify a hypothetical update offline (semver only, no network).       |
| `queue`           | Inspect / approve / reject pending REVIEW updates.                      |
| `history`         | Inspect and manage persistent scan history & dedup state.              |
| `audit`           | Tail the append-only audit log of decisions, applies, and rollbacks.   |
| `snapshot`        | List / restore / prune filesystem snapshots.                           |
| `notify-test`     | Send a synthetic event to every configured notifier.                   |
| `validate-config` | Parse a config file and report the validation result.                  |
| `version`         | Print version metadata.                                                 |

```sh
# Scan all containers managed by the local Docker daemon, look for digest
# movement on each pinned tag, and report pending updates with risk levels.
bulwark scan
bulwark scan --json | jq '.results[] | select(.update_available)'

# Run the daemon and auto-apply qualifying updates: SAFE always, REVIEW
# updates approved via `bulwark queue approve`. BREAKING never auto-applies.
# When the verify-gate is enabled, an image must also clear it before apply.
bulwark run --config ./bulwark.yaml --data-dir ./data --apply --cron "0 3 * * *"

# Preview what --apply would do without touching containers.
bulwark run --apply --dry-run --config ./bulwark.yaml --data-dir ./data

# Serve only the HTTP surface (DIUN webhook receiver) for cross-host setups.
bulwark serve --config ./bulwark.yaml --data-dir ./data --diun-token "${BULWARK_DIUN_TOKEN}"

# Live check for a specific update: resolve digests, fetch release notes,
# classify. Emits JSON, suitable for piping into shell tooling.
bulwark check lscr.io/linuxserver/sonarr:4.0.9-ls45 4.0.10-ls46 | jq '.level'

# Approval queue: a decision silences notifications about a specific
# (container, image-digest) pair until the next distinct registry digest.
bulwark queue approve sonarr --note "tested in dev" --data-dir ./data

# Snapshot management. Restore + prune are guarded by --yes (destructive).
bulwark snapshot list /var/lib/sonarr --config ./bulwark.yaml
bulwark snapshot restore <id> --yes --config ./bulwark.yaml
```

---

## Configuration

The full, commented reference is
[`configs/bulwark.example.yaml`](configs/bulwark.example.yaml); a stripped-down
starting point is [`configs/bulwark.minimal.yaml`](configs/bulwark.minimal.yaml).
Validate any file with `bulwark validate-config --config ./bulwark.yaml`.

### Secrets

Keep secrets out of YAML. Bulwark expands `${VAR}` tokens in string values at
load time, so mount credentials (Docker secrets, an `.env` file, or the host
environment) and reference them by name:

```yaml
notifications:
  home_assistant:
    token: "${BULWARK_HASS_TOKEN}"
api:
  auth:
    type: bearer
    token: "${BULWARK_API_TOKEN}"
```

`$VAR` (without braces) is intentionally **not** expanded, so YAML strings
containing literal dollar signs are never silently rewritten. Command-based
secrets (`--diun-token`, `--github-token`) also read from environment
variables (`BULWARK_DIUN_TOKEN`, `BULWARK_GITHUB_TOKEN`).

#### Secrets from files (`_FILE`)

Any secret-bearing variable `NAME` also accepts a companion `NAME_FILE` whose
value is a path to a file holding the secret — the Docker-secrets convention
used by the official `postgres`, `mysql`, and `wordpress` images and by
Grafana, Vaultwarden, and GitLab. Bulwark resolves it natively in the config
loader (no entrypoint wrapper needed), so it works both for every `${VAR}`
token in `bulwark.yaml` and for the direct-environment secrets
`BULWARK_DIUN_TOKEN` and `BULWARK_GITHUB_TOKEN`:

```yaml
services:
  bulwark:
    environment:
      BULWARK_DIUN_TOKEN_FILE: /run/secrets/diun_token   # secret read from the file
    secrets:
      - diun_token
secrets:
  diun_token:
    file: ./secrets/diun_token        # host-side, chmod 600
```

Resolution precedence is **inline value -> `_FILE` -> default**: a non-empty
`NAME` is used first; otherwise `NAME_FILE` is read; otherwise the caller's
default applies (an unset `${VAR}` with no `_FILE` is left as the literal
`${VAR}`). A single trailing newline is stripped, so `printf 'tok' > file` and
`echo tok > file` behave identically.

Resolution fails **closed** and never guesses:

- Setting **both** a non-empty `NAME` and its `NAME_FILE` is rejected as
  ambiguous — provide exactly one.
- A `NAME_FILE` that is missing, unreadable, or empty after trimming is an
  error; the process refuses to start with a silently empty secret.

Secret **values** are never written to logs or included in error messages; only
the variable name and, for I/O failures, the file path appear. Full reference
and migration notes: **[`docs/secrets.md`](docs/secrets.md)**.

### The `verify:` block

```yaml
verify:
  enabled: false                 # opt-in; false == zero behavior change
  signature:
    mode: block                  # off | warn | block  (default: block when enabled)
    verifier: cosign             # cosign (default); sigstore-go is experimental & rejected at startup
    identities:                  # keyless (Fulcio/OIDC) allowed signers — any single match trusts
      - san: "^https://github.com/your-org/.+$"        # regexp matched against the cert SAN
        issuer: "https://token.actions.githubusercontent.com"
    key: ""                      # OR a cosign public key path/ref, e.g. "${BULWARK_COSIGN_PUBKEY}"
    cosign:
      binary: "cosign"           # path to the cosign executable (default: resolve on PATH)
      version: "2.4.1"           # expected `cosign version` token   — REQUIRED when the axis is active
      digest: "sha256:<64-hex>"  # expected sha256 of the binary     — REQUIRED when the axis is active
  vuln:
    mode: block                  # off | warn | block  (default: block when a threshold is set)
    block_threshold: "off"       # off | high | critical — consumes the security.cve_source reports
```

The vulnerability axis reuses the shared CVE source:

```yaml
security:
  severity_threshold: critical   # critical | high
  cve_source:
    type: trivy                  # pluggable backend; trivy is the first (grype also available)
    trivy:
      # Directory of `trivy image --format json` reports (paths may use ${VAR}).
```

### Other highlights

- **Auth**: `none` / `bearer` / `forward-proxy` (Authelia, Authentik,
  oauth2-proxy, Cloudflare Access).
- **Per-stack and per-container policy overrides** (Compose project name + glob
  patterns). Treat critical infra (`authentik`, `home-assistant`,
  `vaultwarden`) as `breaking` by default so it never auto-updates.
- **Maintenance windows**: gate auto-apply to off-peak hours.
- **Snapshot backends**: ZFS, Btrfs, Restic (or `none`); a per-container
  `bulwark.snapshot.dataset` label selects the target.
- **Private-registry auth**: explicit YAML credentials per host, with optional
  fall-back to `~/.docker/config.json` (auths, credHelpers, credsStore).
- **Notifications**: Slack, Discord, Home Assistant, SMTP, ntfy, and generic
  webhooks, each with a `min_level`. Digest mode batches non-urgent events;
  BREAKING and rollback events still fire immediately.
- **DIUN webhook receiver**: `api.diun.token` (or `--diun-token` /
  `BULWARK_DIUN_TOKEN`) secures the `POST /api/v1/webhooks/diun` endpoint so
  existing DIUN deployments can drive Bulwark as the decision engine.

---

## Architecture

Bulwark is a single Go binary that embeds the React dashboard. It has a small,
deliberate dependency surface (`gopkg.in/yaml.v3`, `github.com/andybalholm/brotli`).

**It talks to the Docker Engine over its HTTP API directly — no Docker SDK.**
Container enumeration, image pulls, and recreation are issued as raw Engine API
calls over the socket (or a socket-proxy). This keeps the dependency tree tiny
and the surface auditable, and it means the exact API calls Bulwark makes are
visible in the code rather than hidden behind a client library.

The update lifecycle is a linear reconcile pipeline: **classify → verify-gate →
snapshot → apply → health-verify → notify/audit.** The verify-gate is
interposed at the reconcile chokepoint, so no code path can apply an image that
hasn't been through it. Every stage degrades gracefully — if release notes
can't be fetched, classification falls back to semver; if a non-critical
subsystem fails, the pipeline logs and continues — and every operation is
idempotent so a crash-and-restart never leaves state half-applied.

---

## Security posture

- **Fail-closed by design.** An enabled verify axis that cannot be evaluated
  blocks; an unset signature mode defaults to `block`; an invalid or expired
  break-glass label is ignored rather than honored.
- **Pinned, digest-verified tooling.** The signature axis refuses to trust an
  ambient `cosign`: both the expected version and the binary's `sha256` digest
  must be pinned in config before the axis will run.
- **Digest-pinning throughout.** Updates are reasoned about by registry digest,
  not by mutable tags, so a moved `:latest` can't smuggle in an unverified image.
- **Least privilege.** Bulwark needs only Docker Engine API access (a
  read-mostly socket-proxy is recommended) plus its data directory. The
  reference Compose deploy runs unprivileged with `cap_drop: [ALL]`,
  `no-new-privileges`, and host-scoped port binding.
- **Secrets stay out of the repo and out of YAML.** Values are referenced via
  `${VAR}` expansion; the API bearer token is minted at `init` time (mode
  0600) and traded for an HTTP-only session cookie in the browser.
- **Defense in depth on the HTTP surface.** CSRF (Origin + `Sec-Fetch-Site`)
  on every mutating endpoint, a per-IP token-bucket rate limiter on every
  route, and optional HMAC replay protection on the DIUN receiver.
- **CI enforces hygiene.** `gitleaks` secret scanning and a repository PII scan
  (`scripts/check-pii.sh`) run on every push, alongside `go vet` and
  `go test -race`.

---

## Dashboard

The React SPA lives at `/` once the daemon is running:

| Path            | Content                                                          |
| --------------- | --------------------------------------------------------------- |
| `/`             | Latest scan summary, recent-scans table, scan-now button        |
| `/queue`        | Pending REVIEW decisions with per-row Approve / Reject           |
| `/history`      | Paginated scan history, filter by Has-pending / Has-breaking     |
| `/history/:id`  | Full per-container results with click-to-expand digest detail    |
| `/containers`   | Last-scan inventory of monitored containers                      |
| `/notifiers`    | Configured channels with Send-test buttons                       |
| `/snapshots`    | Per-target snapshot listing (read-only; restore via CLI)         |
| `/audit`        | Newest-first audit log with action filters                       |
| `/settings`     | Loaded YAML (secrets redacted) + effective classifier policies   |
| `/legacy/`      | The original vanilla dashboard, kept for one release as a transition |

Auth is via an HTTP-only session cookie issued by `POST /api/v1/sessions` when
you present a valid bearer token. Live updates stream over `GET /api/v1/events`
(Server-Sent Events).

---

## HTTP API

```
POST   /api/v1/webhooks/diun       DIUN webhook receiver (bearer + optional HMAC)
GET    /api/v1/sessions            Auth probe (200 if logged in, 401 otherwise)
POST   /api/v1/sessions            Trade bearer for session cookie
DELETE /api/v1/sessions            Drop the session cookie
GET    /api/v1/scans               List recent scans (limit query)
GET    /api/v1/scans/{id}          Full scan record (id="latest" for most recent)
POST   /api/v1/scans               Trigger an immediate scan (202 Accepted)
GET    /api/v1/queue               Pending + decided approval rows
POST   /api/v1/queue               Approve or reject a decision
DELETE /api/v1/queue/{container}   Forget all decisions for a container
GET    /api/v1/notifications       Notification dedup state
DELETE /api/v1/notifications       Clear dedup state (force re-notify)
GET    /api/v1/audit               Append-only audit log (limit query)
GET    /api/v1/containers          Last-scan container inventory
GET    /api/v1/notifiers           Configured channels + min-level
POST   /api/v1/notifiers/{name}/test  Synthetic event to one channel
GET    /api/v1/snapshots           Snapshot listing (target query, requires backend)
GET    /api/v1/config              Loaded YAML (secrets redacted)
GET    /api/v1/policies            Effective classifier + overrides
GET    /api/v1/events              Server-Sent Events stream
GET    /metrics                    Prometheus text format
GET    /healthz, /readyz           Liveness / readiness probes
```

CSRF is enforced on every mutating endpoint (Origin + `Sec-Fetch-Site` checks),
and a per-IP token-bucket rate limiter wraps every route by default.

---

## Documentation

| Document | What it covers |
| -------- | -------------- |
| [`docs/verify-gate.md`](docs/verify-gate.md) | The deploy-time trust gate: axes, modes, break-glass, wiring. |
| [`docs/the design notes-signature-verifier.md`](docs/the design notes-signature-verifier.md) | Why the signature axis pins a cosign binary rather than embedding a library. |
| [`docs/secrets.md`](docs/secrets.md) | Secrets and the `_FILE` (Docker-secret) convention: precedence, fail-closed semantics, and migration from the entrypoint wrapper. |
| [`docs/the design notes-progressive-enforcement-signature-gate.md`](docs/the design notes-progressive-enforcement-signature-gate.md) | Proposal: progressive-enforcement (safe-default) posture for the signature gate. |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | Host-side deployment: Docker Compose, reverse proxy, TLS, DIUN integration. |
| [`docs/UAT.md`](docs/UAT.md) | Step-by-step smoke-test playbook; each section is independent. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution workflow, code style, and the PII policy. |

Deployment examples use the `bulwark.example.com` placeholder — substitute your
real hostname in your own untracked files.

---

## Roadmap

| Phase  | Scope                                                                   | Status  |
| ------ | ----------------------------------------------------------------------- | ------- |
| 1–2    | Scaffolding, classifier, config, registry client, `check` / `scan`      | shipped |
| 3      | Update orchestration: pull + recreate + health + rollback               | shipped |
| 4      | Filesystem snapshot backends (ZFS, Btrfs)                               | shipped |
| 5      | Pre / post / rollback update hooks (sandboxed)                          | shipped |
| 6–7    | HTTP REST API + embedded dashboard                                      | shipped |
| 8      | Auth: bearer + forward-proxy (Authelia / Authentik SSO + MFA)           | shipped |
| 9–11   | Security follow-ups, observability, maintenance windows, `--dry-run`    | shipped |
| 12     | Compose awareness (`depends_on` parsing, topo-sorted apply)             | shipped |
| 13–14  | Native HA / SMTP / digest notifiers; Restic backend; private-registry auth | shipped |
| 15–16  | HEALTHCHECK `start_period`, HTTP-only cookies; React + Tailwind SPA (SSE) | shipped |
| 17     | Security-urgency axis: pluggable CVE source (Trivy, Grype)              | shipped |
| 18     | Deploy-time verify-gate: cosign signature + vulnerability, break-glass  | shipped |
| 19     | Native `_FILE` (Docker-secret) config resolution — every `${VAR}` and direct-env secret | shipped |
| 20     | Progressive-enforcement decision record for the signature gate ([the design notes](docs/the design notes-progressive-enforcement-signature-gate.md), proposal) | shipped |
| Future | multi-host federation; Slack interactive approvals; signed audit log; LXC / Podman | planned |

---

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
full guide. In short:

- `go vet ./...` and `go test -race ./...` must pass; CI enforces both.
- Changes to the classifier (`internal/classifier`) need tests for every new
  path and a rationale note for any policy change — a false SAFE is dangerous.
- Every operation must be idempotent and degrade gracefully.
- Conventional Commits are encouraged (`feat(verify): …`, `fix(config): …`).

### Repository hygiene (enforced)

This repository is developed under a hardened loop, and the same gates run in
CI and in the pre-commit hook (install with `./scripts/install-hooks.sh`):

- **No PII.** `scripts/check-pii.sh` rejects real IPv4 addresses (only
  RFC-5737 / RFC-1918 ranges), real email addresses (only documentation
  domains and `noreply@…`), and real domain names. Use `example.com` /
  `example.org` / `example.net` in docs and tests.
- **No secrets.** `gitleaks` scans every commit and every CI run; configuration
  examples use `${VAR}` placeholders only.

---

## License

Bulwark is licensed under the **GNU Affero General Public License, version 3.0 only** ([AGPL-3.0-only](LICENSE)). A commercial dual-license is available for organizations that cannot accept the AGPL terms — see [`NOTICE`](NOTICE). Copyright (C) 2026 ranklancer.
