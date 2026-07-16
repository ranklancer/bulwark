# Secrets and the `_FILE` environment-variable convention

This document is maintained in accordance with ISO/IEC/IEEE 15289:2019
(information item content) and ISO/IEC/IEEE 26515:2018 (user and system
documentation in an agile life cycle). It contains no personally identifying
information and no secret material; all tokens, paths, and identifiers are
placeholders on documentation domains (`example.com`) or non-secret
illustrative values.

## 1. Scope

This record describes how Bulwark ingests secret-bearing configuration —
API/DIUN tokens, notifier tokens, registry credentials, and similar — and in
particular the native `_FILE` indirection that lets any such value be supplied
from a file (a mounted Docker secret) instead of an inline environment
variable. It covers operator-facing behaviour, precedence, failure semantics,
and the migration from the former entrypoint-wrapper approach. It does not
cover the trust gate's cosign binary pin, which is public integrity metadata
rather than a secret (see `docs/verify-gate.md` and
`docs/the design notes-signature-verifier.md`).

## 2. Background

Bulwark keeps secrets out of the committed YAML in two complementary ways:

1. **`${VAR}` substitution.** Any string-valued field in `bulwark.yaml` may
   contain a `${VAR}` token, which is replaced at load time with the value of
   the environment variable `VAR` (for example `token: ${BULWARK_DIUN_TOKEN}`).
2. **Direct environment variables.** A few secrets are read straight from the
   environment as flag defaults, notably `BULWARK_DIUN_TOKEN` (the DIUN webhook
   shared secret) and `BULWARK_GITHUB_TOKEN` (a GitHub PAT for release-note
   rate limits).

Both paths historically required the *value* to be present in the process
environment. Delivering a secret as a file — the mechanism used by Docker
secrets, Swarm/Compose `secrets:`, and Kubernetes secret volumes — therefore
needed an entrypoint wrapper that read the file and re-exported it. This
document's feature removes that wrapper.

## 3. The `_FILE` convention

For every secret-bearing variable `NAME`, Bulwark also accepts `NAME_FILE`,
whose value is a path to a file containing the secret. This is the widely
adopted Docker-secrets convention used by the official Docker images
(`postgres`, `mysql`, `wordpress`), and by Grafana, Vaultwarden, GitLab, and
linuxserver.io images, among others.

The convention is a first-class feature of the configuration loader, not a
per-variable special case:

- It applies to **every** `${VAR}` token in `bulwark.yaml`. If `VAR` is unset
  but `VAR_FILE` is set, the secret is read from that file and substituted.
  This covers `api.auth.token`, `api.diun.token`, `api.diun.hmac_secret`,
  notifier tokens (`notifications.*`), registry credentials
  (`registries.hosts.*`), the Proxmox API token, and any future
  `${VAR}`-expressed secret with no code change.
- It applies to the direct-environment secrets `BULWARK_DIUN_TOKEN` and
  `BULWARK_GITHUB_TOKEN` via the same resolver, so `BULWARK_DIUN_TOKEN_FILE`
  and `BULWARK_GITHUB_TOKEN_FILE` work identically.

### 3.1 Exactly one source

For a given `NAME`, provide **exactly one** of an inline value or a file:

1. Inline: a non-empty `NAME`.
2. File: `NAME_FILE`, a path whose contents are the secret. A single trailing
   newline is stripped, so `printf 'token' > file` and `echo token > file`
   behave identically.

If neither is set the variable is absent and the caller's default applies (for
a `${VAR}` token with no value, the literal `${VAR}` is left untouched,
preserving prior behaviour).

Setting **both** `NAME` and `NAME_FILE` is rejected as ambiguous (fail-closed),
matching the official docker-entrypoint convention, which refuses to guess
which source to trust rather than silently picking one.

### 3.2 Fail-closed semantics

If both `NAME` and `NAME_FILE` are set, or if `NAME_FILE` is set but the file
is missing, unreadable, or empty after trimming, Bulwark fails closed: configuration loading (or command start-up)
returns a clear error naming the variable and the offending path, and the
process does not start with a silently empty secret. The secret's *value* is
never written to logs or included in any error message — only the variable
name and, for I/O failures, the file path (a path is not the secret).

## 4. Usage

### 4.1 Docker Compose with a mounted secret

```yaml
services:
  bulwark:
    image: ghcr.io/ranklancer/bulwark:${BULWARK_VERSION}
    environment:
      # Point Bulwark at the mounted secret instead of an inline value.
      BULWARK_DIUN_TOKEN_FILE: /run/secrets/diun_token
    secrets:
      - diun_token

secrets:
  diun_token:
    file: /srv/docker-secrets/bulwark/diun_token   # host-side, chmod 600
```

### 4.2 A `${VAR}` field sourced from a file

```yaml
# bulwark.yaml
notifications:
  homeassistant:
    enabled: true
    url: http://hass.example.com:8123
    token: ${HASS_TOKEN}
```

```sh
# HASS_TOKEN itself is unset; the value is delivered as a file.
export HASS_TOKEN_FILE=/run/secrets/hass_token
```

## 5. Migration from the entrypoint wrapper

Previously the DIUN token was injected by an entrypoint wrapper that read a
file and exported `BULWARK_DIUN_TOKEN`. With native `_FILE` support the wrapper
is unnecessary. The migration is a clean repoint:

- The stack sets `BULWARK_DIUN_TOKEN_FILE=/run/secrets/diun_token` and mounts
  the Docker secret, as in section 4.1.
- The secret **file** is still provisioned host-side at
  `/srv/docker-secrets/bulwark/diun_token` through the sanctioned
  `*-secret-bootstrap` Dockge-stack pattern. That provisioning is unchanged;
  only the consumer changes from "wrapper exports the value" to "Bulwark reads
  the file natively."

No host filesystem changes are made by this feature; it only changes how the
running container consumes an already-provisioned secret file.

## 6. Consequences

- Bulwark is natively compatible with Docker secrets, Compose `secrets:`, and
  Kubernetes secret volumes with no entrypoint wrapper.
- Secrets can be removed from the process environment entirely, reducing
  exposure via `/proc/<pid>/environ`, `docker inspect`, and crash dumps.
- Enabling `_FILE` for a variable is purely additive and opt-in: unchanged
  deployments that set inline values behave exactly as before.
