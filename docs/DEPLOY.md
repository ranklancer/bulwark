# Deploying Bulwark

This guide walks through standing up Bulwark on your own host, behind a
reverse proxy with a hostname like `bulwark.example.com`. Examples use the
RFC documentation domain throughout — when you adopt this on your network,
substitute your real hostname in your *own* untracked files.

> The Bulwark project itself never commits real hostnames or IPs (see the
> [PII rule](../CONTRIBUTING.md)). Keep your real values out of any file
> tracked in version control.

> ### ⚠ Docker socket = root on the host
>
> Bulwark reads (and, with `--apply`, writes) `/var/run/docker.sock`.
> Anyone who can reach Bulwark's `--apply` path effectively has root on
> the host: they can recreate any container with any image. Treat the
> Bulwark listener accordingly:
>
> - Bind to `127.0.0.1` and put a TLS-terminating reverse proxy in front,
>   OR bind to a private LAN address that no untrusted network can reach.
> - Configure `api.auth.type: forward-proxy` (Authelia/Authentik) or at
>   minimum `bearer` with a strong shared secret.
> - Enable the per-IP rate limiter (on by default; see
>   `api.rate_limit_per_minute`) so a leaked bearer can't be used to
>   hammer the daemon.
> - Run Bulwark with `cap_drop: ALL` and `no-new-privileges:true` so a
>   process compromise doesn't escape its own container.
>
> The same property is true of every other Docker-update tool — it's
> fundamental to the role, not specific to Bulwark — but worth saying
> out loud.

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
    image: ghcr.io/ranklancer/bulwark:latest
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

### Hardening DIUN with HMAC replay protection

If the DIUN webhook traverses a network where bearer tokens could be
captured and replayed (lossy WiFi, shared LANs, anywhere without TLS),
add HMAC-SHA256 signatures on top of the bearer. Bulwark accepts a
`X-Bulwark-Timestamp` + `X-Bulwark-Signature` pair signing the body,
gated on `api.diun.hmac_secret`:

```yaml
# bulwark.yaml
api:
  diun:
    token:       "${BULWARK_DIUN_TOKEN}"
    hmac_secret: "${BULWARK_DIUN_HMAC_SECRET}"   # 32+ random bytes
```

DIUN itself can't compute an HMAC over the body. Bulwark ships a tiny
sidecar — `cmd/bulwark-diun-relay` — that DIUN posts to in cleartext;
the relay signs and forwards to Bulwark. Single binary, stdlib only.

```yaml
# docker-compose snippet — add alongside Bulwark
services:
  bulwark-diun-relay:
    image: ghcr.io/ranklancer/bulwark-diun-relay:latest
    container_name: bulwark-diun-relay
    restart: unless-stopped
    command:
      - --listen=:8090
      - --upstream=http://bulwark:8080/api/v1/webhooks/diun
      - --secret-file=/run/secrets/bulwark_diun_hmac_secret
      - --bearer=${BULWARK_DIUN_TOKEN}        # forwarded as Authorization
    secrets:
      - bulwark_diun_hmac_secret
    networks:
      - proxy
secrets:
  bulwark_diun_hmac_secret:
    file: ./secrets/bulwark_diun_hmac_secret   # 32+ random bytes; chmod 600
```

DIUN points at the relay (NOT directly at Bulwark):

```yaml
notif:
  webhook:
    endpoint: http://bulwark-diun-relay:8090/
    method: POST
```

The relay sees the body in cleartext on the loopback Docker network, signs
it, and forwards to Bulwark over the same network. The replay window
is 5 minutes — captured webhooks past that fail signature verification.

---

## Step 8 — Bearer auth + the dashboard sign-in flow

The dashboard's `/login` page exchanges a bearer token for an
HTTP-only session cookie. Two paths to a token:

```sh
# A. Generated by `bulwark init` (writes a starter config with a
#    literal token at mode 0600, prints the token to stdout once).
bulwark init --output ./config/bulwark.yaml

# B. Hand-rolled, env-var substituted (matches configs/bulwark.minimal.yaml):
echo "BULWARK_API_TOKEN=$(openssl rand -hex 32)" >> .env
```

In `bulwark.yaml`:

```yaml
api:
  auth:
    type: bearer
    token: "${BULWARK_API_TOKEN}"   # or a literal value
```

Operators visit `https://bulwark.example.com/`, paste the token at
`/login`, and the daemon issues a 12-hour HttpOnly + SameSite=Lax
cookie. The bearer token never lives in `localStorage`. The `Secure`
flag is set automatically when the daemon receives the request over
TLS or when a trusted proxy forwards `X-Forwarded-Proto: https`
(see Step 10).

`POST /api/v1/sessions` is the underlying endpoint; CSRF middleware
enforces same-origin on the login form. Logout is `DELETE
/api/v1/sessions`.

---

## Step 9 — Forward-proxy auth (Authelia / Authentik recipe)

For SSO + MFA, terminate auth in your reverse-proxy stack and trust
the resulting identity headers. Bulwark's `forward-proxy` mode is
designed for Authelia, Authentik, oauth2-proxy, Pomerium, and
Cloudflare Access — they all use the same Remote-User pattern.

```yaml
# bulwark.yaml
api:
  listen: "127.0.0.1:8080"      # bind to localhost; only the proxy can reach Bulwark
  auth:
    type: forward-proxy
    trusted_proxies:
      - 192.0.2.0/24             # the network your proxy lives in (RFC-reserved here)
    user_header:    Remote-User
    groups_header:  Remote-Groups
    required_group: bulwark-operators
```

Key safeties:

- Requests from outside `trusted_proxies` are rejected with 403
  before identity headers are read — neutralises header-spoofing
  attacks.
- `required_group` is the operator allowlist. Empty allows any
  authenticated user.
- The `forward-proxy` mode is mutually exclusive with `bearer`. If
  you need both (humans via SSO, machines via bearer for DIUN),
  expose two listeners on different paths or front the bearer-only
  endpoint with a separate proxy rule.

Authelia + nginx ingress example:

```nginx
# nginx /etc/nginx/sites-enabled/bulwark
location /api/verify {
    internal;
    proxy_pass http://authelia.example.com/api/verify;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
}

location / {
    auth_request /api/verify;
    auth_request_set $user $upstream_http_remote_user;
    auth_request_set $groups $upstream_http_remote_groups;
    proxy_set_header Remote-User $user;
    proxy_set_header Remote-Groups $groups;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://127.0.0.1:8080;
}
```

---

## Step 10 — Reverse-proxy headers (REQUIRED behind TLS proxies)

Every TLS-terminating reverse proxy must forward
`X-Forwarded-Proto: https` to Bulwark. Without it, the daemon sees
plain HTTP and refuses to set the `Secure` flag on session cookies
— which means browsers happily send the cookie back over plain
HTTP if a downgrade attack succeeds.

**nginx**:
```nginx
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header Host              $host;
```

**Traefik (label form)**:
```yaml
labels:
  traefik.http.middlewares.bulwark-headers.headers.customrequestheaders.X-Forwarded-Proto: https
  traefik.http.routers.bulwark.middlewares: bulwark-headers
```

**Caddy (Caddyfile)**:
```caddy
bulwark.example.com {
  reverse_proxy 127.0.0.1:8080 {
    header_up X-Forwarded-Proto https
  }
}
```

Bulwark only honours `X-Forwarded-Proto: https` (case-insensitive,
leftmost value if comma-separated). Spoofing this header on plain
HTTP is harmless: modern browsers refuse to accept Secure cookies
on non-HTTPS responses (RFC 6265bis), so the worst case is a
failed login on a misconfigured client — not credential theft.

---

## Step 11 — Docker socket GID

Most Linux hosts ship `/var/run/docker.sock` owned by `root:docker`
with mode 660. The `bulwark` user inside the container isn't in the
host's `docker` group, so `--apply` writes will fail with `EACCES`
even though scans (read-only) work fine.

Find the host's docker GID and pass it through:

```sh
# On the host:
getent group docker | cut -d: -f3
# → e.g. 999

# In docker-compose.yaml:
services:
  bulwark:
    group_add:
      - "999"   # or whatever you got above
```

Alternatives (less safe): run as `user: 0:0`, or run the container
with `--privileged`. Both broaden the blast radius of a process
compromise.

---

## Step 12 — Snapshot backends

Pick one based on what your host already runs. All three options
share the same `bulwark.snapshot.dataset` per-container label.

**ZFS**: bind-mount the binaries + device.
```yaml
volumes:
  - /usr/sbin/zfs:/usr/sbin/zfs:ro
  - /usr/sbin/zpool:/usr/sbin/zpool:ro
  - /dev/zfs:/dev/zfs
```

```yaml
# bulwark.yaml
snapshots:
  backend: zfs
```

**Btrfs**: similar pattern with `/sbin/btrfs`. Subvolume targets
follow the `bulwark.snapshot.dataset` label semantics.

**Restic**: requires the `restic` binary inside the container plus
a password file. Repository can be local, SFTP, S3, B2, or any
restic backend.

```yaml
volumes:
  - /usr/local/bin/restic:/usr/local/bin/restic:ro
  - ./secrets/restic.password:/secrets/restic.password:ro
  - ./restic-repo:/restic-repo
```

```yaml
# bulwark.yaml
snapshots:
  backend: restic
  restic:
    repository:    /restic-repo
    password_file: /secrets/restic.password
```

The password file must be readable by the `bulwark` user. Create
it on the host with `umask 077; echo $REPO_PASSWORD > restic.password`.

---

## Step 13 — Private registry credentials

Two parallel paths; you can use either or both. YAML hosts win when
both are configured.

**Path A — Docker CLI managed (recommended for hand-managed hosts)**:

```sh
docker login ghcr.io
# Writes ~/.docker/config.json on the host.
```

In compose, mount the file read-only into the container:

```yaml
volumes:
  - ~/.docker/config.json:/home/bulwark/.docker/config.json:ro
```

In `bulwark.yaml`:

```yaml
registries:
  use_docker_config: true
```

Bulwark resolves credentials in this order: explicit YAML hosts
first, then the Docker config (auths block, credHelpers per host,
credsStore as global fallback).

**Path B — explicit YAML (recommended for CI-managed credentials)**:

```yaml
registries:
  hosts:
    ghcr.io:
      identity_token: "${GITHUB_TOKEN}"
    registry.example.com:
      username: my-user
      password: "${REGISTRY_EXAMPLE_PASSWORD}"
```

OAuth2 registries (GHCR private images, Docker Hub PATs) accept
the token via the password slot of HTTP Basic; Bulwark handles the
`<token>:<oauth-token>` convention automatically.

---

## Step 14 — DIUN HMAC + the relay sidecar

Stock DIUN sends plain webhooks. To get replay-resistance from the
client side, deploy the bundled `bulwark-diun-relay` between DIUN
and the daemon: it signs each forwarded request with a shared HMAC
secret and a timestamp, and Bulwark rejects signatures older than
5 minutes.

```yaml
# bulwark.yaml
api:
  diun:
    token: "${BULWARK_DIUN_TOKEN}"
    hmac_secret: "${BULWARK_DIUN_HMAC_SECRET}"
```

```yaml
# docker-compose snippet — alongside Bulwark
services:
  bulwark-diun-relay:
    image: ghcr.io/ranklancer/bulwark-diun-relay:latest
    environment:
      - BULWARK_URL=http://bulwark:8080/api/v1/webhooks/diun
      - BULWARK_TOKEN=${BULWARK_DIUN_TOKEN}
      - BULWARK_HMAC_SECRET=${BULWARK_DIUN_HMAC_SECRET}
    ports:
      - "8081:8080"

  diun:
    # … point DIUN's webhook at http://bulwark-diun-relay:8080
```

Bearer-only DIUN deployments still work — leave `hmac_secret` empty
in `bulwark.yaml` and DIUN keeps posting plain webhooks.

---

## Step 15 — Native HA / SMTP / digest notifier recipes

Three notifiers added in Phase 13. All are off by default; enable
each in the `notifications:` block.

**Home Assistant**:

```yaml
notifications:
  homeassistant:
    enabled: true
    url:   "http://homeassistant.example.com:8123"
    token: "${BULWARK_HASS_TOKEN}"
    safe:     { persistent: true,  push: false }
    review:   { persistent: true,  push: true }
    breaking: { persistent: true,  push: true,  critical: true }
    rollback: { persistent: true,  push: true,  critical: true }
```

`persistent` hits `notify.persistent_notification` (the dashboard
banner). `push` hits the Companion app via `notify.notify`.
`critical: true` adds the iOS critical-alert flag that bypasses Do
Not Disturb.

**SMTP**:

```yaml
notifications:
  smtp:
    enabled:  true
    host:     "smtp.example.com"
    port:     587
    username: "bulwark@example.com"
    password: "${BULWARK_SMTP_PASSWORD}"
    from:     "bulwark@example.com"
    to:       ["ops@example.com"]
    tls:      true
```

Multipart/alternative envelope: text/plain + text/html parts. HTML
fields are auto-escaped; injecting `<script>` into a container
name doesn't escape into the rendered email.

**Digest mode** — coalesce non-urgent notifications into a single
batch dispatched on a cron schedule:

```yaml
notifications:
  digest:
    enabled:  true
    schedule: "0 8 * * *"     # daily at 08:00 local time
```

BREAKING events + rollbacks + stack-skipped events still fire
immediately. Only SAFE/REVIEW events queue for the digest.

---

## Step 16 — Maintenance windows + dry-run + manual scan trigger

Three production-safety knobs added in Phase 11.

**Maintenance windows** gate the apply phase. Scans + notifications
keep running; only mutating containers is constrained.

```yaml
schedule:
  maintenance_windows:
    - start: "02:00"
      end:   "06:00"
      days:  [monday, tuesday, wednesday, thursday, friday]
    - start: "00:00"
      end:   "23:59"
      days:  [saturday, sunday]
```

**Dry-run** runs the eligibility + notification pipeline but never
calls the updater:

```sh
bulwark run --apply --dry-run --config /config/bulwark.yaml --data-dir /data
```

Audit events get `"detail": "dry-run"` so you can grep for what
*would* have happened without anything actually moving.

**Manual scan trigger** — POST `/api/v1/scans` runs a scan
immediately, queue-jumping the next periodic firing:

```sh
curl -X POST -H "Authorization: Bearer ${BULWARK_API_TOKEN}" \
     https://bulwark.example.com/api/v1/scans
# 202 Accepted; the new scan appears in `bulwark history list`
# within seconds.
```

---

## Step 17 — Prometheus scrape config

Mount the `/metrics` endpoint in your existing scrape job:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: bulwark
    metrics_path: /metrics
    static_configs:
      - targets: ['bulwark.example.com:443']
        labels:
          service: bulwark
    scheme: https
    bearer_token: ${BULWARK_API_TOKEN}
```

Counters exposed: scans, apply outcomes, notification dispatches,
http_requests by route+status, rate-limited requests, decisions.
The `http_requests` series is high-cardinality friendly: routes
are normalised (no per-id paths) so dashboards with rate panels
don't explode.

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
