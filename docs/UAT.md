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

## Reporting issues

When filing a bug, include:

- Bulwark version (`bulwark version`).
- The relevant section of your `bulwark.yaml` (with secrets redacted).
- Container/image references involved (please use docs domains in
  reports — `example.com`, `example.org`, `example.net`).
- The output of `bulwark scan --json` so we can see what the classifier saw.
- Logs from the daemon at `-v` verbosity.
