# Deploying Bulwark

This guide walks through standing up Bulwark on your own host, behind a
reverse proxy with a hostname like `bulwark.example.com`. Examples use the
RFC documentation domain throughout — when you adopt this on your network,
substitute your real hostname in your *own* untracked files.

> The Bulwark project itself never commits real hostnames or IPs (see the
> [PII rule](../CONTRIBUTING.md)). Keep your real values out of any file
> tracked in version control.

---

## Topology

The recommended deployment mounts Bulwark in your existing Docker host
alongside the containers it manages, behind your existing reverse proxy:

```
┌──────────────┐   https://bulwark.example.com    ┌──────────────────┐
│  browser /   │ ───────────────────────────────▶ │ reverse proxy    │
│  cron / curl │                                  │ (Traefik/nginx)  │
└──────────────┘                                  └────────┬─────────┘
                                                           │
                                                  http://bulwark:8080
                                                           │
                                                  ┌────────▼─────────┐
                                                  │  bulwark         │
                                                  │  ─ scan loop     │
                                                  │  ─ DIUN webhook  │
                                                  │  ─ /api/v1/*     │
                                                  │  ─ dashboard     │
                                                  └────────┬─────────┘
                                                           │ /var/run/docker.sock
                                                  ┌────────▼─────────┐
                                                  │  Docker daemon   │
                                                  └──────────────────┘
```

The dashboard, the API, and the DIUN webhook receiver all share the same
port. There's no separate UI service to deploy.

---

## Step 1 — host filesystem layout

```sh
mkdir -p /opt/bulwark/{config,data,hooks}
```

Place a config file at `/opt/bulwark/config/bulwark.yaml` (start from
[`configs/bulwark.example.yaml`](../configs/bulwark.example.yaml) and trim
to what you need). Persist a strong DIUN/API token in a `.env` file
alongside, e.g.:

```sh
# /opt/bulwark/.env  (DO NOT commit this file)
BULWARK_DIUN_TOKEN=$(openssl rand -hex 32)
BULWARK_HASS_TOKEN=...           # if you wired Home Assistant
BULWARK_SLACK_WEBHOOK=...        # if you wired Slack
```

Both files are referenced by the YAML's `${VAR}` placeholders so secrets
never appear in tracked config.

---

## Step 2 — docker compose

```yaml
# /opt/bulwark/docker-compose.yaml
services:
  bulwark:
    image: ghcr.io/bulwark-docker/bulwark:latest
    container_name: bulwark
    restart: unless-stopped
    command:
      - run
      - --config=/config/bulwark.yaml
      - --data-dir=/data
      - --listen=:8080
      - --scan-interval=6h
      # add --apply only when you're ready to let Bulwark recreate containers
      # add --no-fetch-notes if you don't want GitHub release-notes lookups
    env_file:
      - .env
    environment:
      - TZ=UTC
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config:/config:ro
      - ./data:/data
      - ./hooks:/hooks:ro
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    # No public ports — the reverse proxy reaches Bulwark over the Docker
    # network. Add `ports: ["8080:8080"]` if you want to expose it directly.
    networks:
      - proxy

networks:
  proxy:
    external: true
```

If you don't already have a `proxy` network, create one with
`docker network create proxy`, attach your reverse proxy to it, and
attach Bulwark too.

---

## Step 3 — reverse proxy

### Traefik (label-based routing)

Add to the `bulwark` service in `docker-compose.yaml`:

```yaml
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.bulwark.rule=Host(`bulwark.example.com`)"
      - "traefik.http.routers.bulwark.entrypoints=websecure"
      - "traefik.http.routers.bulwark.tls.certresolver=lan"     # your resolver
      - "traefik.http.services.bulwark.loadbalancer.server.port=8080"
```

For LAN-only deployments (no public-internet exposure), use a self-signed
cert resolver or Traefik's built-in `tls=true` without a resolver — the
browser warning is harmless on a trusted network.

### nginx

```nginx
# /etc/nginx/sites-enabled/bulwark
server {
  listen 443 ssl http2;
  server_name bulwark.example.com;

  # Substitute your cert path
  ssl_certificate     /etc/ssl/private/bulwark.crt;
  ssl_certificate_key /etc/ssl/private/bulwark.key;

  # Restrict to LAN
  allow 192.0.2.0/24;       # replace with your LAN range
  deny  all;

  location / {
    proxy_pass         http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-Proto $scheme;
  }
}
```

### Caddy

```
bulwark.example.com {
  @lan remote_ip 192.0.2.0/24
  handle @lan {
    reverse_proxy bulwark:8080
  }
  respond 403
}
```

---

## Step 4 — start the daemon

```sh
cd /opt/bulwark
docker compose up -d
docker compose logs -f bulwark
```

Expected log lines on a healthy startup:

```
serve: ready  addr=:8080 docker=true notifiers=N store=true schedule=6h0m0s
api:   listening  addr=:8080
run/scheduler: tick complete  duration=...
```

The first scan runs immediately; subsequent scans follow `--scan-interval`
or `--cron` if you configured one.

---

## Step 5 — verify

Open `https://bulwark.example.com/` in a browser. The dashboard renders
three sections (pending decisions, recent scans, dedup state). Paste your
DIUN/API token into the field at the top and click Save.

From a shell:

```sh
TOKEN=...        # the token you put in .env
HOST=bulwark.example.com

curl -s "https://$HOST/healthz"
curl -sH "Authorization: Bearer $TOKEN" "https://$HOST/api/v1/scans?limit=5" | jq
curl -sH "Authorization: Bearer $TOKEN" "https://$HOST/api/v1/queue" | jq
```

Then walk the [UAT smoke-test playbook](UAT.md) — sections 1 through 9 are
read-only; sections 10–12 are destructive (`--apply`) and should be run
against a throwaway test container first.

---

## Step 6 — point DIUN at Bulwark (optional)

If you already run [DIUN](https://crazymax.dev/diun/), add Bulwark as a
webhook destination so DIUN's image discovery feeds Bulwark's classifier:

```yaml
# diun's notif config
notif:
  webhook:
    endpoint: https://bulwark.example.com/api/v1/webhooks/diun
    method: POST
    headers:
      Authorization: "Bearer ${BULWARK_DIUN_TOKEN}"
```

Bulwark logs every received webhook and runs the same dedup +
classification + notification pipeline as the periodic scan.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `docker: socket not found` on startup | socket not mounted | Confirm the `/var/run/docker.sock:...:ro` bind is present |
| `docker: permission denied` | container running as a user without docker-group access | Add `user: 0:0` to the compose service, or grant the container's UID `docker` group |
| Dashboard loads but every API call returns 401 | Token in `.env` doesn't match the one in `bulwark.yaml` (or vice versa) | One token, one source — env-var substitution is your friend |
| "no scan history yet" on `bulwark queue approve` | scans haven't been recorded — `--data-dir` not set or scheduler hasn't fired yet | Wait for the first scan, or trigger one with `docker exec bulwark bulwark scan --data-dir /data --notify` |
| ZFS snapshots don't fire | `zfs` binary isn't visible inside the container | Bind-mount the host's `/usr/sbin/zfs` and `/dev/zfs`, or run with `--privileged` (less secure) |

---

## Updating Bulwark itself

```sh
docker compose pull bulwark
docker compose up -d bulwark
```

Bulwark's own image is excluded from auto-update via the
`bulwark.enable: "false"` label in the example compose — it shouldn't
update itself.
