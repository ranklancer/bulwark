# Bulwark

> **Don't just update. Understand what changed.**

Bulwark is an intelligent Docker container update guardian. It watches your
container registries, classifies the risk of each pending update by reading
release notes and comparing semantic versions, takes filesystem-level
snapshots, applies the update, verifies health, and rolls back automatically
on failure.

It is the spiritual successor to Watchtower (archived December 2025) and goes
substantially further: every update is _understood_ before it is applied.

> **Status:** v0.1.0-ready. The full pipeline is shipped: classifier,
> notification dispatcher (Slack / Discord / Home Assistant / SMTP / digest /
> generic webhooks), persistent state (dedup, scan history, approval queue,
> append-only audit log), HTTP API + DIUN-compatible webhook receiver,
> bearer + forward-proxy auth with HTTP-only session cookies, rate limiting,
> CSRF + HMAC replay protection, snapshot backends (ZFS / Btrfs / Restic),
> private-registry auth (YAML hosts + `~/.docker/config.json`), Compose
> `depends_on`-aware apply with stop-on-failure, maintenance windows,
> dry-run, Prometheus `/metrics`, and a React + Tailwind dashboard with
> live updates over Server-Sent Events. See [`Roadmap`](#roadmap).

---

## Why Bulwark?

The most-requested Watchtower features were never delivered:

| Feature                          | Watchtower | Drydock | DockMon | **Bulwark** |
| -------------------------------- | ---------- | ------- | ------- | ----------- |
| Detect updates                   | ✓          | ✓       | ✓       | ✓           |
| Risk-classify updates            | —          | partial | —       | ✓           |
| Read release notes               | —          | —       | —       | ✓           |
| Filesystem snapshots             | —          | —       | —       | ZFS/Btrfs/Restic |
| Health-verified rollback         | —          | image   | image   | ✓ (FS + container) |
| Compose-aware                    | partial    | ✓       | ✓       | depends\_on topo |
| Per-container policies           | binary     | basic   | basic   | rich        |
| Rich notifications               | basic      | basic   | basic   | per-channel + digest |
| Pre/post hooks                   | partial    | —       | —       | ✓ (sandboxed) |
| Web dashboard                    | —          | basic   | basic   | full SPA + live updates |
| SSO / MFA                        | —          | —       | —       | forward-proxy + bearer |
| Audit log                        | —          | —       | —       | append-only JSONL |
| Prometheus metrics               | —          | —       | —       | ✓           |

## Three-tier risk classification

Every update is sorted into one of three buckets:

- **SAFE** — auto-update. Patch version bumps, image rebuilds without version
  changes, LinuxServer.io `-ls<n>` rebuilds.
- **REVIEW** — notify and wait for explicit approval. Minor version bumps,
  `:latest`-tag movements, anything mentioning "migration required" in the
  release notes.
- **BREAKING** — block until the user forces it. Major version bumps, anything
  mentioning "breaking change" or "incompatible" in the release notes.

The risk level is chosen using a configurable policy. The classifier reads
release notes from GitHub Releases and DockerHub descriptions, scans them for
breaking-change keywords, and combines that with semantic-version analysis
and per-container Docker labels.

---

## Quick start

### Run from a published image

```sh
# 1. Generate a bearer token + put it in .env
echo "BULWARK_API_TOKEN=$(openssl rand -hex 32)" > .env

# 2. Copy + adjust the config
mkdir -p config data
cp configs/bulwark.example.yaml config/bulwark.yaml
# In config/bulwark.yaml set api.auth.type: bearer

# 3. Run the daemon
docker compose -f docker-compose.example.yaml up -d

# 4. Open the dashboard
open http://localhost:8080/    # paste the same token at /login
```

The dashboard's `/login` page exchanges the bearer token for an HTTP-only
session cookie — the token is never stored in the browser. Pages auto-update
as scans complete + apply outcomes land, via Server-Sent Events.

### Build from source

Source builds need both Go (1.22+) and Node (22+) so Vite can emit the React
bundle the binary embeds:

```sh
git clone https://github.com/ranklancer/bulwark
cd bulwark
cd web && npm ci && npm run build && cd ..
go build ./cmd/bulwark
./bulwark version
```

The committed `internal/api/ui-react/dist/` placeholder lets `go build`
succeed without Node — but the resulting binary serves the legacy vanilla
dashboard at `/` instead of the SPA. Run `npm run build` at least once for
the full experience.

---

## CLI

```sh
# Scan all containers managed by the local Docker daemon, look for digest
# movement on each pinned tag, and report pending updates with risk levels.
bulwark scan
bulwark scan --json | jq '.results[] | select(.update_available)'
bulwark scan --notify --config ./bulwark.yaml --data-dir ./data

# Run the daemon — periodic scans + HTTP server + dashboard, in a single
# always-on process. SIGINT or SIGTERM trigger a graceful shutdown.
bulwark run --config ./bulwark.yaml --data-dir ./data --scan-interval 6h

# Same daemon, plus auto-apply qualifying updates: SAFE always, REVIEW
# updates that have been approved via `bulwark queue approve`. BREAKING
# never auto-applies. Health verification + container-level rollback
# protect against bad pulls; configured snapshot backend (ZFS / Btrfs /
# Restic) protects against bad data.
bulwark run --config ./bulwark.yaml --data-dir ./data --apply --cron "0 3 * * *"

# Preview what --apply would do without touching containers. Synthesises
# success outcomes so notifications still render exactly as they would
# for a real apply. Audit log records each dry-run with Detail="dry-run".
bulwark run --apply --dry-run --config ./bulwark.yaml --data-dir ./data

# Serve only the HTTP surface (no scan loop). Useful for cross-host
# deployments that ingest events via the DIUN webhook receiver.
bulwark serve --config ./bulwark.yaml --data-dir ./data

# Inspect prior scans + persistent state.
bulwark history list --data-dir ./data
bulwark history show latest --data-dir ./data
bulwark history clear --data-dir ./data    # force re-notify on next scan
bulwark history prune --keep 30 --data-dir ./data

# Tail the append-only audit log (every decision, apply, rollback, clear).
bulwark audit --data-dir ./data --limit 200
bulwark audit --json --data-dir ./data | jq 'select(.action=="apply.rolled_back")'

# Approval queue: decisions silence notifications about a specific
# (container, image-digest) pair forever — the next distinct registry
# digest re-opens the question.
bulwark queue list --data-dir ./data
bulwark queue approve sonarr --note "tested in dev" --data-dir ./data
bulwark queue reject auth --data-dir ./data
bulwark queue forget sonarr --data-dir ./data
bulwark queue clear --data-dir ./data

# Snapshot management — list / restore / prune. Restore + prune are
# guarded by --yes because they're destructive.
bulwark snapshot list /var/lib/sonarr --config ./bulwark.yaml
bulwark snapshot restore <id> --yes --config ./bulwark.yaml
bulwark snapshot prune <id> --yes --config ./bulwark.yaml

# Send a synthetic event to every configured notifier — verifies webhook
# URLs and per-channel formatting without waiting for a real update.
bulwark notify-test --config ./bulwark.yaml

# Live check for a specific update: resolve digests, fetch GitHub release
# notes, classify the resulting update.
bulwark check lscr.io/linuxserver/sonarr:4.0.9-ls45 4.0.10-ls46

# Offline classify: skip the network and classify on semver alone.
bulwark classify \
  --from "lscr.io/linuxserver/sonarr:4.0.9-ls45" \
  --to   "lscr.io/linuxserver/sonarr:4.0.10-ls46"

# Validate a config file:
bulwark validate-config --config ./bulwark.yaml

# Show version:
bulwark version
```

`check` emits the assessment as JSON, suitable for piping into shell tooling:

```sh
bulwark check ghcr.io/owner/app:1.2.3 2.0.0 | jq '.level'
# "breaking"
```

---

## Dashboard

The React SPA lives at `/` once the daemon is running. Eight pages:

| Path | Content |
|------|---------|
| `/` | Latest scan summary, recent-scans table, scan-now button |
| `/queue` | Pending REVIEW decisions with per-row Approve / Reject |
| `/history` | Paginated scan history, filter by Has-pending / Has-breaking |
| `/history/:id` | Full per-container results with click-to-expand digest detail |
| `/containers` | Last-scan inventory of monitored containers |
| `/notifiers` | Configured channels with Send-test buttons |
| `/snapshots` | Per-target snapshot listing (read-only; restore via CLI) |
| `/audit` | Newest-first audit log with action filters |
| `/settings` | Loaded YAML (secrets redacted) + effective classifier policies |
| `/legacy/` | The original vanilla dashboard, kept for one release as a transition |

Auth is via an HTTP-only session cookie issued by `POST /api/v1/sessions`
when you present a valid bearer token. Live updates stream over
`GET /api/v1/events` (Server-Sent Events).

---

## API surface

```
POST /api/v1/webhooks/diun         DIUN webhook receiver (bearer + optional HMAC)
GET  /api/v1/sessions              Auth probe (200 if logged in, 401 otherwise)
POST /api/v1/sessions              Trade bearer for session cookie
DELETE /api/v1/sessions            Drop the session cookie
GET  /api/v1/scans                 List recent scans (limit query)
GET  /api/v1/scans/{id}            Full scan record (id="latest" for most recent)
POST /api/v1/scans                 Trigger an immediate scan (202 Accepted)
GET  /api/v1/queue                 Pending + decided approval rows
POST /api/v1/queue                 Approve or reject a decision
DELETE /api/v1/queue/{container}   Forget all decisions for a container
GET  /api/v1/notifications         Notification dedup state
DELETE /api/v1/notifications       Clear dedup state (force re-notify)
GET  /api/v1/audit                 Append-only audit log (limit query)
GET  /api/v1/containers            Last-scan container inventory
GET  /api/v1/notifiers             Configured channels + min-level
POST /api/v1/notifiers/{name}/test Synthetic event to one channel
GET  /api/v1/snapshots             Snapshot listing (target query, requires backend)
GET  /api/v1/config                Loaded YAML (secrets redacted)
GET  /api/v1/policies              Effective classifier + overrides
GET  /api/v1/events                Server-Sent Events stream
GET  /metrics                      Prometheus text format
GET  /healthz, /readyz             Liveness / readiness probes
```

CSRF is enforced on every mutating endpoint (Origin + Sec-Fetch-Site checks).
A per-IP token-bucket rate limiter wraps every route by default.

---

## Configuration

See [`configs/bulwark.example.yaml`](configs/bulwark.example.yaml) for the
full list of options. Highlights:

- **Auth**: `none` / `bearer` / `forward-proxy` (Authelia, Authentik,
  oauth2-proxy, Cloudflare Access).
- **Per-stack and per-container policy overrides** (Compose project name +
  glob patterns).
- **Maintenance windows**: gate auto-apply to off-peak hours.
- **Trusted-rebuilder list**: LSIO `-ls<n>` rebuilds are SAFE by default.
- **Environment-variable substitution** for secrets: `token: ${HASS_TOKEN}`.
- **Custom keyword lists** for breaking-change / migration / security
  detection.
- **Snapshot backends**: ZFS, Btrfs, Restic (or `none`). Per-container
  `bulwark.snapshot.dataset` label selects the target.
- **Private-registry auth**: explicit YAML credentials per host, optional
  fall-back to `~/.docker/config.json` (auths block, credHelpers, credsStore).
- **Hooks sandbox**: restrict label-supplied script paths to a known
  directory.
- **Notification digest mode**: cron-driven batch dispatch for non-urgent
  events; BREAKING + rollback events still fire immediately.

## Privacy and PII

The codebase is checked by [`scripts/check-pii.sh`](scripts/check-pii.sh):
no real IPv4 addresses (only RFC-reserved ranges), no real email addresses
(only documentation domains), no real domain names. Install the pre-commit
hook with:

```sh
./scripts/install-hooks.sh
```

The same scan runs in CI.

---

## Roadmap

| Phase  | Scope                                                    | Status   |
| ------ | -------------------------------------------------------- | -------- |
| 1      | Scaffolding, classifier, config, CLI                     | shipped  |
| 2a     | OCI registry client + GitHub release-notes + `check`     | shipped  |
| 2b     | Docker socket client, container scanner, `scan` command  | shipped  |
| 2c     | Notifier dispatcher (Slack/Discord/generic), `--notify`  | shipped  |
| 2d     | Persistent state (dedup + history), `bulwark history`    | shipped  |
| 2e     | HTTP server, DIUN webhook receiver, `bulwark serve`      | shipped  |
| 2f     | Continuously-running daemon (`bulwark run`)              | shipped  |
| 2g     | Approval queue (`bulwark queue` + cycle integration)     | shipped  |
| 2h     | Cron-aware scheduling for `bulwark run`                  | shipped  |
| 3      | Update orchestration: pull + recreate + health + rollback | shipped |
| 4      | Filesystem snapshot backends (ZFS, Btrfs)                | shipped  |
| 5      | Pre/post/rollback update hooks                           | shipped  |
| 6      | HTTP REST API for state inspection + decisions           | shipped  |
| 7      | Embedded minimal web dashboard (vanilla JS)              | shipped  |
| 8      | Auth: bearer + forward-proxy (Authelia/Authentik SSO+MFA)| shipped  |
| 9      | Security follow-ups (path traversal, CSRF, hooks-root, rate limit, HMAC + relay) | shipped |
| 10     | Consistency + observability (ID-keyed state, audit log, /metrics, stack overrides) | shipped |
| 11     | Production gating (maintenance windows, --dry-run, POST /api/v1/scans) | shipped |
| 12     | Compose awareness (depends\_on parsing, topo-sorted apply, stop-on-failure) | shipped |
| 13     | Native HA + SMTP + digest notifiers                      | shipped  |
| 14     | Restic backend, snapshot CLI, private-registry auth      | shipped  |
| 15     | Honor HEALTHCHECK start\_period, HTTP-only session cookies | shipped |
| 16     | React + Tailwind dashboard with live updates (SSE)       | shipped  |
| Future | Multi-host federation, write-back settings UI, Slack interactive approvals, signed audit log, LXC / Podman | planned |

## Deployment

For a host-side deployment (Docker Compose, reverse proxy, TLS, optional
DIUN integration) see [`docs/DEPLOY.md`](docs/DEPLOY.md). All examples use
the `bulwark.example.com` placeholder — substitute your real hostname in
your own untracked files.

## User Acceptance Testing

A step-by-step smoke-test playbook lives in
[`docs/UAT.md`](docs/UAT.md). Each section is independent so you can skip
features that aren't enabled in your deployment.

## License

[MIT](LICENSE).
