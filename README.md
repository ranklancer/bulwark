# Bulwark

> **Don't just update. Understand what changed.**

Bulwark is an intelligent Docker container update guardian. It watches your
container registries, classifies the risk of each pending update by reading
release notes and comparing semantic versions, takes filesystem-level
snapshots, applies the update, verifies health, and rolls back automatically
on failure.

It is the spiritual successor to Watchtower (archived December 2025) and goes
substantially further: every update is _understood_ before it is applied.

> **Status:** early development. Shipped: risk classifier; YAML config;
> OCI registry client; GitHub release-notes fetcher; Docker socket client;
> one-shot scanner; notification dispatcher (Slack / Discord / generic JSON
> webhooks); persistent state (notification dedup with TTL, scan history,
> approval queue with approve/reject/forget); HTTP server with DIUN-
> compatible webhook receiver; continuously-running daemon (`bulwark run`).
> Up next: update orchestration with health-verified rollback, snapshot
> backends, and the web UI.

---

## Why Bulwark?

The most-requested Watchtower features were never delivered:

| Feature                          | Watchtower | Drydock | DockMon | **Bulwark** |
| -------------------------------- | ---------- | ------- | ------- | ----------- |
| Detect updates                   | ✓          | ✓       | ✓       | ✓           |
| Risk-classify updates            | —          | partial | —       | ✓           |
| Read release notes               | —          | —       | —       | ✓           |
| Filesystem snapshots (ZFS/Btrfs) | —          | —       | —       | ✓           |
| Health-verified rollback         | —          | image   | image   | ✓ (FS)      |
| Compose-aware                    | partial    | ✓       | ✓       | ✓           |
| Per-container policies           | binary     | basic   | basic   | rich        |
| Rich notifications               | basic      | basic   | basic   | per-channel |
| Pre/post hooks                   | partial    | —       | —       | ✓           |

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

## Quick start

> The daemon is not yet runnable end-to-end. The CLI subcommands below are
> available today.

```sh
# Scan all containers managed by the local Docker daemon, look for digest
# movement on each pinned tag, and report pending updates with risk levels.
bulwark scan
bulwark scan --json | jq '.results[] | select(.update_available)'

# Same scan, plus dispatch notifications to every channel enabled in config.
# --data-dir enables persistent dedup so cron re-runs don't spam.
bulwark scan --notify --config ./bulwark.yaml --data-dir ./data

# Inspect prior scans and the notification dedup state.
bulwark history list --data-dir ./data
bulwark history show latest --data-dir ./data
bulwark history clear --data-dir ./data    # force re-notify on next scan
bulwark history prune --keep 30 --data-dir ./data

# Act on the approval queue. Decisions silence notifications about a
# specific (container, image-digest) pair forever — the next distinct
# registry digest re-opens the question.
bulwark queue list --data-dir ./data
bulwark queue approve sonarr --note "tested in dev" --data-dir ./data
bulwark queue reject auth --data-dir ./data
bulwark queue forget sonarr --data-dir ./data    # re-open the question
bulwark queue clear --data-dir ./data

# Send a synthetic event to every configured channel — useful for verifying
# webhook URLs and per-channel formatting without waiting for a real update.
bulwark notify-test --config ./bulwark.yaml

# Run the long-running HTTP server. Exposes a DIUN-compatible webhook
# receiver so existing DIUN deployments can plug Bulwark in as the "brain"
# without changing their notification setup.
bulwark serve --config ./bulwark.yaml --data-dir ./data
#   POST /api/v1/webhooks/diun    DIUN webhook receiver
#   GET  /healthz, /readyz        liveness / readiness probes

# Run the daemon — periodic scans + HTTP server in a single always-on
# process. SIGINT or SIGTERM trigger a graceful shutdown.
bulwark run --config ./bulwark.yaml --data-dir ./data --scan-interval 6h

# Live check for a specific update: resolve digests in the registry,
# fetch GitHub release notes, classify the resulting update.
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

When the daemon ships, the standard deployment will be:

```sh
docker compose -f docker-compose.example.yaml up -d
```

with a `bulwark.yaml` derived from
[`configs/bulwark.example.yaml`](configs/bulwark.example.yaml).

## How it works

```
┌─────────────────┐   ┌──────────────┐   ┌────────────┐
│ Registry watcher│──▶│  Classifier  │──▶│ Snapshot   │
│ (or DIUN hook)  │   │  (this MVP)  │   │ orchestrator│
└─────────────────┘   └──────────────┘   └────────────┘
                                                │
                                                ▼
┌──────────────┐   ┌─────────────────┐   ┌────────────┐
│ Notification │◀──│ Health verifier │◀──│  Updater   │
│ dispatcher   │   │ + Rollback ctlr │   │ (compose)  │
└──────────────┘   └─────────────────┘   └────────────┘
```

When an update is detected for a container, Bulwark:

1. Looks up the matching policy (YAML config + per-container Docker labels).
2. Asks the classifier to assess the risk (semver delta + release-notes scan).
3. Routes the update through the SAFE / REVIEW / BREAKING path.
4. For SAFE updates: takes a snapshot, runs pre-hooks, pulls and recreates the
   container, polls health checks, runs post-hooks. On health failure, restores
   the snapshot and notifies.
5. For REVIEW updates: queues the update for human approval and notifies with
   full context (version delta, release notes excerpt, link).
6. For BREAKING updates: blocks the update and sends a critical alert.

## Configuration

See [`configs/bulwark.example.yaml`](configs/bulwark.example.yaml) for the
full list of options. Highlights:

- Per-stack and per-container policy overrides.
- Maintenance windows (only update during low-traffic periods).
- Trusted-rebuilder list (LSIO `-ls<n>` rebuilds are SAFE by default).
- Environment-variable substitution for secrets (`token: ${HASS_TOKEN}`).
- Custom keyword lists for breaking-change detection.

## Privacy and PII

The codebase is checked by [`scripts/check-pii.sh`](scripts/check-pii.sh):
no real IPv4 addresses (only RFC-reserved ranges), no real email addresses
(only documentation domains), no real domain names. Install the pre-commit
hook with:

```sh
./scripts/install-hooks.sh
```

The same scan runs in CI.

## Roadmap

| Phase | Scope                                                    | Status   |
| ----- | -------------------------------------------------------- | -------- |
| 1     | Scaffolding, classifier, config, CLI                     | shipped  |
| 2a    | OCI registry client + GitHub release-notes + `check`     | shipped  |
| 2b    | Docker socket client, container scanner, `scan` command  | shipped  |
| 2c    | Notifier dispatcher (Slack/Discord/generic), `--notify`  | shipped  |
| 2d    | Persistent state (dedup + history), `bulwark history`    | shipped  |
| 2e    | HTTP server, DIUN webhook receiver, `bulwark serve`      | shipped  |
| 2f    | Continuously-running daemon (`bulwark run`)              | shipped  |
| 2g    | Approval queue (`bulwark queue` + cycle integration)     | shipped  |
| 2h    | Cron-aware scheduler, maintenance windows                | next     |
| 3     | Snapshot backends (ZFS, Btrfs, volume)                   | planned  |
| 4     | Native HA persistent / SMTP / Shoutrrr notifications     | planned  |
| 5     | Web UI, HTTP API, WebSocket                              | planned  |
| 6     | Hooks, scheduling, multi-arch images                     | planned  |

## License

[MIT](LICENSE).
