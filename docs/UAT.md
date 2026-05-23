# Bulwark — User Acceptance Testing

This is the smoke-test playbook for verifying a fresh Bulwark deployment.
Each section is self-contained and can be skipped if you don't need that
feature.

The intended audience is someone setting up Bulwark for the first time on
their own host. If you're a developer running the test suite, just use
`go test ./...` instead.

> **Safety note.** Bulwark only mutates Docker when `--apply` is passed.
> Every test below is read-only by default; the explicit-apply tests are
> clearly marked.

---

## 0. Prerequisites

- Docker 24+ running on the host (the daemon's API is what Bulwark talks to).
- A directory you can write to for persistent state — `./data` in the
  examples below.
- (Optional) a `bulwark.yaml` from `configs/bulwark.example.yaml` —
  unconfigured features simply stay disabled.

```sh
# Build the binary from source.
go build -o bulwark ./cmd/bulwark

# OR run via Docker once an image is published.
# docker compose -f docker-compose.example.yaml up -d
```

The remainder of this playbook assumes `./bulwark` is the local binary.

---

## 1. Help text + version sanity

```sh
./bulwark version
./bulwark help
```

Expected: a list of every subcommand. If `version` reports `dev`, you built
without `-ldflags`; that's fine for testing.

---

## 2. Offline classifier (no network, no Docker)

```sh
./bulwark classify \
  --from "lscr.io/linuxserver/sonarr:4.0.10-ls45" \
  --to   "lscr.io/linuxserver/sonarr:4.0.11-ls47"
```

**Pass criteria:**
- `level: "safe"` (LSIO rebuild + patch bump).
- `kind: "patch"`.
- A human-readable rationale.

```sh
./bulwark classify \
  --from "ghcr.io/owner/app:1.2.3" \
  --to   "ghcr.io/owner/app:2.0.0"
```

**Pass criteria:**
- `level: "breaking"` (major version bump).

---

## 3. Live classifier (requires registry network access)

```sh
./bulwark check ghcr.io/owner/app:1.2.3 1.3.0
```

**Pass criteria:**
- The command resolves both digests against the registry without auth errors.
- The output JSON contains both `current_digest` and `target_digest`.
- The `notes_source` field appears if the image maps to a known GitHub
  repo (e.g. anything under `lscr.io/linuxserver/`).

If you see a 401 from the registry, the image is private — that's expected.
Try a public image (e.g. `nginx:1.25` against `nginx:1.26`).

---

## 4. Local container scan (read-only)

```sh
./bulwark scan --no-color
```

**Pass criteria:**
- Lists every running container, sorted by risk severity.
- For containers Bulwark can map (most of `lscr.io/linuxserver/*` and
  `ghcr.io/*`), the column shows level + version delta.
- A summary line at the bottom: `N update(s) pending: …`.

If you see "docker: socket not found", you're running outside of a host
with Docker. Pass `--docker-host /custom/path/docker.sock`.

---

## 5. Notification dry-run

If you've configured at least one channel in `bulwark.yaml`:

```sh
./bulwark notify-test --config ./bulwark.yaml
```

**Pass criteria:**
- A test event arrives on every enabled channel.
- The message is clearly labelled `[test]` so receivers know it's a synthetic.
- Each channel reports `ok` on stdout.

The synthetic event bypasses each channel's `min_level` filter, so you'll
receive it even if the channel is configured for `breaking` only.

---

## 6. Persistent scan + dedup

Run a scan with `--data-dir` to record history:

```sh
./bulwark scan --notify --data-dir ./data --no-color
./bulwark history list --data-dir ./data
./bulwark history show latest --data-dir ./data
```

**Pass criteria:**
- The scan finishes and the listing shows one row.
- `show latest` displays per-container detail.
- A second run within the dedup TTL (default 24h) does not re-notify (the
  output's "Notifications" section reports silenced events).

---

## 7. Approval queue

After a scan that found at least one REVIEW update:

```sh
./bulwark queue list --data-dir ./data
./bulwark queue approve <container-name> --note "tested in dev" --data-dir ./data
./bulwark queue list --data-dir ./data    # decision now appears
./bulwark queue forget <container-name> --data-dir ./data  # re-opens
```

**Pass criteria:**
- The decision is recorded immediately.
- A subsequent `scan --notify` does NOT re-notify about the approved
  (container, digest) pair.

---

## 8. HTTP server + dashboard + DIUN webhook

Start the standalone server:

```sh
./bulwark serve --listen :8080 --data-dir ./data
```

Then in a browser visit `http://localhost:8080/` — you should see the
dashboard (queue, recent scans, dedup state). The "Refresh" button picks up
the seeded data immediately; the page also auto-refreshes every 30s.

To verify the DIUN-compatibility webhook:

```sh
curl -X POST http://localhost:8080/api/v1/webhooks/diun \
  -H 'Content-Type: application/json' \
  -d '{"status":"new","image":"ghcr.io/owner/app:1.0","digest":"sha256:test"}'
```

**Pass criteria:**
- Status code 200.
- Response body has `received: true` and (if a matching local container
  exists) `container_matched: true`.

If you've configured an API token in `bulwark.yaml` (`api.diun.token`),
add `-H "Authorization: Bearer <token>"`. Without the token: 401.

---

## 9. Continuous daemon

```sh
./bulwark run --listen :8080 --data-dir ./data --scan-interval 5m
```

**Pass criteria:**
- Startup log line includes `schedule=5m0s`.
- One scan runs immediately (`scan cycle complete`); another runs after
  five minutes.
- Ctrl-C drains in-flight requests within 30 seconds and exits cleanly.

For cron-style schedules:

```sh
./bulwark run --cron "0 3 * * *" --data-dir ./data
```

---

## 10. Auto-apply (DESTRUCTIVE — use a test container)

> **Warning.** This actually pulls and recreates containers. Do this against
> a test container you don't care about, ideally one with a HEALTHCHECK so
> rollback semantics work.

Pick a SAFE update — a `:latest` tag or LSIO rebuild on a non-critical
container — and run:

```sh
./bulwark scan --apply --data-dir ./data --no-color
```

**Pass criteria:**
- The "Notifications" section (if enabled) labels the event
  `Auto-updated: <container>`.
- `docker ps` shows the new image; `docker images <repo>` shows the old
  image is still present (Docker keeps it cached, you can prune later).

To force a rollback test, configure a bogus health check that always
fails before running `--apply`. Bulwark should:
1. Pull the new image.
2. Recreate the container with the new image.
3. Detect Unhealthy.
4. Stop and remove the new container.
5. Rename the old container back; restart it.

---

## 11. Filesystem snapshot rollback (ZFS or Btrfs)

If the container's volumes live on ZFS, label the container:

```yaml
# In your compose file:
labels:
  bulwark.snapshot.dataset: "tank/docker/sonarr"
```

Then run a `--apply` scan. Verify `zfs list -t snapshot tank/docker/sonarr`
shows a `bulwark-…` snapshot during the update window. On health failure
the snapshot is restored before the old container is rebooted.

The snapshot is destroyed on success.

---

## 12. Pre/post update hooks

Place a script at e.g. `/srv/hooks/pre.sh`:

```sh
#!/bin/sh
echo "container=$BULWARK_CONTAINER action=$BULWARK_ACTION new=$BULWARK_NEW_IMAGE" >> /tmp/bulwark-hook.log
```

Then label the container with:

```yaml
labels:
  bulwark.hook.pre-update: /srv/hooks/pre.sh
```

Run an `--apply` scan; check `/tmp/bulwark-hook.log` for the entry.

The pre-update hook gets BULWARK_OLD_IMAGE, BULWARK_NEW_IMAGE,
BULWARK_OLD_DIGEST, BULWARK_NEW_DIGEST, BULWARK_CONTAINER,
BULWARK_CONTAINER_ID, and BULWARK_SNAPSHOT_ID (when configured).

---

## 13. Dashboard sign-in (bearer → cookie)

The React dashboard exchanges your bearer token for an HTTP-only
session cookie. The token never touches `localStorage`.

```sh
# Generate a starter config + token in one step:
bulwark init --output ./bulwark.yaml
# Copy the printed token; you'll need it on the login page.

bulwark run --config ./bulwark.yaml --data-dir ./data &
open http://localhost:8080/
```

What to check:

- Visiting `/` while signed-out redirects to `/login`.
- Pasting the bearer token + clicking "Sign in" puts you on the
  dashboard.
- The browser's cookie inspector shows `bulwark_session` with
  `HttpOnly` set, `SameSite=Lax`, and (if you're behind a TLS
  proxy that sets `X-Forwarded-Proto: https`) `Secure`.
- Closing + reopening the browser keeps you signed in until the
  12h expiry. Clicking "Sign out" drops the cookie immediately.

## 14. SPA pages render

Click each primary nav entry. Each page must render without a
console error.

| Page | Verifies |
|---|---|
| `/` Dashboard | Latest scan summary cards, recent-scans table, "Scan now" button |
| `/queue` | Pending REVIEW decisions with Approve / Reject buttons |
| `/history` | Paginated scan list, "All / Has-pending / Has-breaking" filter chips |
| `/history/<id>` | Per-container result rows, click-to-expand digest detail |
| `/containers` | Last-scan inventory of every monitored container |
| `/notifiers` | Configured channels with min-level + Send-test button (or "no notifiers configured" empty state) |
| `/snapshots` | Target input → snapshot list (or "no backend configured" message) |
| `/audit` | Newest-first event table with auto-detected action filter chips |
| `/settings` | Loaded YAML (with `***` redactions) + effective classifier policies |

Browser console (F12 → Console) should be silent. Any uncaught
exception or 4xx/5xx visible in the Network tab is a UAT failure.

## 15. Live updates (Server-Sent Events)

The dashboard auto-refreshes on key daemon events. No polling.

```sh
# In one terminal, with bulwark running:
curl -X POST -H "Authorization: Bearer <token>" \
     http://localhost:8080/api/v1/scans
```

What to check:

- The dashboard's "Recent scans" table gains a new row within a
  second of the curl call. No browser refresh required.
- Browser DevTools → Network → "events" entry shows a long-lived
  `text/event-stream` response with periodic `: heartbeat`
  comments and `event: scan.completed` entries on each scan.
- `/audit` and `/queue` similarly auto-refresh on
  `decision.recorded`, `apply.success`, `apply.rolled_back`, etc.

## 16. Audit log (CLI + dashboard)

Every decision, apply, rollback, and stack-skip lands in the
append-only audit log.

```sh
# Make a decision, then list audit events.
bulwark queue approve sonarr --note "tested" --data-dir ./data
bulwark audit --data-dir ./data --limit 20

# The same data is visible at /audit in the dashboard.
```

What to check:

- The CLI output and the dashboard's `/audit` table show identical
  rows in the same newest-first order.
- Filter chips on `/audit` narrow the list (e.g. only
  `apply.success` or `decision.recorded`).
- `bulwark audit --json` emits one JSON object per line, suitable
  for `jq` / Loki ingestion.

## 17. Compose-aware apply (`depends_on` topology)

Bulwark applies updates in a Compose stack in dependency-first
order; if a dep fails, peers in the same stack are stack-skipped.

```yaml
# uat-compose.yaml
services:
  db:
    image: postgres:15
    healthcheck:
      test: ["CMD", "pg_isready"]
      start_period: 30s
    labels:
      bulwark.enable: "true"
  web:
    image: ghcr.io/owner/app:1.0
    depends_on:
      db:
        condition: service_started
    labels:
      bulwark.enable: "true"
```

```sh
docker compose -f uat-compose.yaml up -d
bulwark scan --apply --data-dir ./data
```

What to check:

- The daemon log line for the apply phase shows `db` pulled
  before `web` (dependency order respected).
- If you intentionally break `db`'s health (set the wrong
  `pg_isready` args), `web` is reported as `apply.stack_skipped`
  in `bulwark audit` and the dashboard's `/audit` page shows the
  same event with a "peer X failed" detail.

## 18. Snapshot CLI (list / restore / prune)

Read-only listing on the dashboard; destructive actions stay on
the CLI behind `--yes`.

```sh
# After a snapshot has been taken (auto, during an apply with
# bulwark.snapshot.dataset set on the container):
bulwark snapshot list /var/lib/sonarr --config ./bulwark.yaml

# Restore is destructive; --yes is required.
bulwark snapshot restore <id> --yes --config ./bulwark.yaml

# Prune frees the storage:
bulwark snapshot prune <id> --yes --config ./bulwark.yaml
```

What to check:

- The dashboard's `/snapshots` page lists the same rows when you
  paste the same target.
- Without `--yes`, restore + prune fail with a clear
  "confirmation required" message — no destructive action.
- After restore, the container's data matches what was captured
  at snapshot time (verify with a known-good fixture file).

## 19. Maintenance windows + dry-run + manual scan trigger

Three production-safety knobs.

```yaml
# bulwark.yaml — gate auto-apply to a specific window
schedule:
  maintenance_windows:
    - start: "02:00"
      end: "06:00"
      days: [monday, tuesday, wednesday, thursday, friday]
```

```sh
# Outside the window: scans + notifications still run, but apply
# is gated.
bulwark run --config ./bulwark.yaml --data-dir ./data --apply

# Dry-run: full pipeline through eligibility + notification, but
# the updater is NEVER invoked. Audit events tagged "dry-run".
bulwark run --config ./bulwark.yaml --data-dir ./data --apply --dry-run

# Manual trigger via the API (runs an immediate scan).
curl -X POST -H "Authorization: Bearer <token>" \
     http://localhost:8080/api/v1/scans
```

What to check:

- Outside the window: log lines say "outside maintenance window;
  skipping apply phase". Notifications still fire so you see
  pending work.
- `--dry-run`: `docker ps` shows zero new containers. `bulwark
  audit` rows have `"detail": "dry-run"`.
- `POST /api/v1/scans`: returns 202 immediately; the new scan
  appears in `bulwark history list` within seconds.

## 20. Notifier send-test

Verifies wiring from Bulwark all the way to the channel.

```sh
# 1. Configure at least one notifier (Slack, Discord, HA, SMTP, generic).
# 2. From the dashboard, visit /notifiers and click "Send test"
#    on the channel of your choice.
```

What to check:

- A synthetic event arrives in the real Slack channel / Discord
  webhook / HA mobile app / mailbox / etc.
- The synthetic flag bypasses `min_level` filtering — even a
  channel set to `min_level: breaking` receives the test event.
- The dashboard shows "Test event sent to <name>." inline. An
  audit row appears for the dispatch.
- Equivalent CLI: `bulwark notify-test --config ./bulwark.yaml`.

## 21. Private registry auth

Bulwark resolves credentials in this order: explicit YAML hosts
first, then `~/.docker/config.json` (when enabled).

```sh
# Option A — Docker CLI managed:
docker login ghcr.io
# bulwark.yaml:
#   registries:
#     use_docker_config: true

# Option B — explicit YAML:
# registries:
#   hosts:
#     ghcr.io:
#       identity_token: "${GITHUB_TOKEN}"

# Then scan an image from that registry:
bulwark scan --config ./bulwark.yaml | grep ghcr.io
```

What to check:

- Scans of private images succeed (no `401 Unauthorized`).
- Verbose mode (`-v`) shows the registry client picking up the
  token from the configured source.
- Wrong / missing credentials surface a clear `manifest unknown`
  or `denied` error, not a silent fall-through.

## 22. Forward-proxy auth (Authelia / Authentik smoke)

For SSO / MFA, put Bulwark behind a proxy that terminates auth
upstream and trust the resulting identity headers.

```yaml
# bulwark.yaml
api:
  auth:
    type: forward-proxy
    trusted_proxies:
      - 192.0.2.0/24       # the network your reverse proxy lives in
    user_header: Remote-User
    groups_header: Remote-Groups
    required_group: bulwark-operators
```

What to check:

- Requests from outside `trusted_proxies` get 403, even if they
  carry `Remote-User`.
- Requests from inside the trusted network with no identity
  headers get 401.
- Requests with valid headers succeed; the daemon log lines show
  the user from `Remote-User`.
- A user in the IdP but NOT in `bulwark-operators` (or whichever
  group you set) gets 403.

## 23. ntfy push notifications

Verifies the ntfy integration end-to-end against a self-hosted
server or `ntfy.sh`. Risk → priority/tag mapping is hardcoded in
v1: BREAKING + rolled-back → priority 5 + 🚨, REVIEW → 4 + ⚠️,
SAFE → 3 + 📦.

```sh
# Option A — quickest, public ntfy.sh + a random topic:
#   1. On your phone, install the ntfy app and subscribe to
#      "bulwark-uat-<a-random-suffix>".
#   2. In the dashboard, /notifiers → Add notifier → kind = ntfy:
#        server URL: https://ntfy.sh
#        topic:      bulwark-uat-<a-random-suffix>
#        token:      (blank — public topic)
#   3. Click "Send test".

# Option B — self-hosted, with auth:
docker run -d --name ntfy -p 8085:80 binwiederhier/ntfy serve
# Generate an access token via the ntfy CLI or web UI, then in the
# dashboard set:
#   server URL: http://<host>:8085
#   topic:      bulwark
#   token:      tk_...

# Option C — yaml-driven:
#   notifications:
#     ntfy:
#       enabled: true
#       server_url: https://ntfy.example.com
#       topic: bulwark
#       token: ${NTFY_TOKEN}
#       min_level: review
#   Then restart the daemon; the channel appears in /notifiers with
#   the "managed by YAML" badge.
```

What to check:

- The synthetic test event arrives on your subscribed device with
  the 🧪 (`test_tube`) tag — confirms the synthetic-bypass path.
- Trigger a real scan that surfaces a REVIEW update; the
  notification's priority is 4 and the tag is ⚠️ (`warning`).
- Force a rollback (or test against a known-broken image): the
  notification's priority is 5 and the tag is 🚨
  (`rotating_light`). Action wins over risk.
- If the scan result has release notes, tapping the phone
  notification opens the release URL.
- Saved tokens display as `***` in the edit form; leaving the
  field untouched preserves the persisted secret. Typing a new
  value replaces it; blanking it clears.

---

## Reporting issues

When filing a bug, include:

- Bulwark version (`bulwark version`).
- The relevant section of your `bulwark.yaml` (with secrets redacted).
- Container/image references involved (please use docs domains in
  reports — `example.com`, `example.org`, `example.net`).
- The output of `bulwark scan --json` so we can see what the classifier saw.
- Logs from the daemon at `-v` verbosity.
