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

## Step 6 — SSO + MFA via forward-proxy auth (recommended)

Bulwark does **not** ship with built-in OIDC, SAML, or MFA. The homelab-
friendly answer is to put a reverse proxy in front that terminates auth
and forwards an `Authorization` decision to Bulwark via headers. Authelia,
Authentik, Pomerium, oauth2-proxy, and Cloudflare Access all support this
pattern; they all give you OIDC and SSO, and Authelia / Authentik give
you TOTP / WebAuthn / push MFA out of the box.

### Bulwark side

```yaml
# in your bulwark.yaml
api:
  auth:
    type: forward-proxy
    trusted_proxies:
      - 192.0.2.0/24       # CIDR your reverse proxy connects from
    user_header:    Remote-User       # what Authelia / Authentik / oauth2-proxy set
    groups_header:  Remote-Groups
    required_group: ops               # optional — only ops can see Bulwark
```

Requests from outside the trusted CIDR are rejected with 403 before the
headers are even read. That's the property that makes header-spoofing
attacks fail closed.

### Authelia (Traefik forward-auth middleware)

```yaml
# Traefik labels on the Bulwark service
- "traefik.http.routers.bulwark.middlewares=authelia@docker"
- "traefik.http.middlewares.authelia.forwardauth.address=http://authelia:9091/api/verify?rd=https%3A%2F%2Fauth.example.com"
- "traefik.http.middlewares.authelia.forwardauth.trustForwardHeader=true"
- "traefik.http.middlewares.authelia.forwardauth.authResponseHeaders=Remote-User,Remote-Groups,Remote-Name,Remote-Email"
```

Then in your Authelia `configuration.yml`:

```yaml
access_control:
  default_policy: deny
  rules:
    - domain: bulwark.example.com
      policy: two_factor          # require TOTP/WebAuthn for Bulwark
      subject: "group:ops"        # gate to a group (matches required_group)
```

### Authentik (proxy outpost)

Create an "Application" with provider type "Proxy" (Forward auth single
application). Set the External Host to `https://bulwark.example.com`. The
outpost's Traefik integration emits the `X-Authentik-User` /
`X-Authentik-Groups` headers — point Bulwark at them:

```yaml
# bulwark.yaml
api:
  auth:
    type: forward-proxy
    trusted_proxies:
      - 192.0.2.0/24
    user_header:    X-Authentik-Username
    groups_header:  X-Authentik-Groups
```

### oauth2-proxy

```yaml
# bulwark.yaml — defaults already match oauth2-proxy
api:
  auth:
    type: forward-proxy
    trusted_proxies:
      - 192.0.2.0/24
    user_header:    X-Auth-Request-User
    groups_header:  X-Auth-Request-Groups
```

`oauth2-proxy` itself is configured in front of the reverse proxy with
your IdP of choice (Google, GitHub, Okta, Keycloak, etc.).

### Audit trail

When forward-proxy auth is configured, every approval recorded via
`POST /api/v1/queue` (or the Approve / Reject buttons in the dashboard)
captures the user from the proxy's identity header — so a
`bulwark queue list` query later shows who approved what:

```sh
$ bulwark queue list --data-dir /opt/bulwark/data --json | jq '.[0]'
{
  "container": "sonarr",
  "decision":  "approved",
  "decided_by": "alice",       # came from Remote-User
  "decided_at": "2026-05-02T15:30:00Z",
  "note":       "tested in dev"
}
```

---

## Step 7 — point DIUN at Bulwark (optional)

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

> The DIUN webhook uses its own `api.diun.token` (machine-to-machine
> bearer), not `api.auth`. Server-to-server callers don't have a human
> identity to forward — keep them on a separate shared secret. If you
> route the DIUN webhook through the same reverse proxy that handles
> SSO for the dashboard, exempt the `/api/v1/webhooks/diun` path from
> the forward-auth middleware so DIUN's POSTs don't get redirected to
> a login page.

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
