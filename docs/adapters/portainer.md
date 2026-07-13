# Portainer Source adapter

Portainer keeps its stacks in its own database (and, for git-backed stacks, in a
git repo). It is therefore an **API/DB-managed backend** (`Source.Kind() ==
managed`): bulwark pins Portainer stacks **through the Portainer API** and
**never edits files on disk**. The capture core enforces this file-vs-managed
split via `Kind()`.

## How a pin is applied

1. **Discover** — `GET /api/stacks` lists the managed stacks (optionally filtered
   to one endpoint via `endpoint_id`). Each stack becomes a `Target` whose
   `Path` is the numeric stack id.
2. **Locate** — `GET /api/stacks/{id}/file` returns the stack's compose text,
   which is parsed by the same image-ref extractor the file adapters use.
3. **Propose** (dry-run) — the digest pin is computed with the shared,
   fail-closed splice; nothing is written.
4. **Apply** (`--apply`) — the stack is re-fetched (freshness + git check), the
   digest is spliced into the current compose text (fail-closed on drift), and
   the new content is pushed back via `PUT /api/stacks/{id}`, which redeploys the
   stack. The stack's existing environment is preserved.

**Git-backed stacks are refused.** Their source of truth is the git repo;
overwriting via the API would fight it. Bulwark reports them and pins nothing —
pin such stacks in their git source instead.

## Configuration

```yaml
sources:
  - name: portainer
    type: portainer
    endpoint: https://portainer.example:9443   # the Portainer API URL
    creds_ref: PORTAINER_API_KEY               # names the ENV VAR holding the
                                               # API key — the secret is never
                                               # stored inline in config
    endpoint_id: 2         # optional: restrict to one Portainer environment
    ca_file: /etc/ssl/portainer-ca.pem   # optional: trust a private issuing CA
    insecure_skip_verify: false          # explicit opt-in only; logs a warning
```

The API key is created in Portainer (user settings → access tokens) and exported
to the process via the environment variable named by `creds_ref`. It is sent as
the `X-API-Key` header and is never logged.

## Security

* **Managed, never file-mangling.** Pins go through the API; disk files are never
  touched (enforced by `Kind() == managed`).
* **TLS fail-closed by default** — system trust store; a private CA via
  `ca_file`; verification disabled only on explicit `insecure_skip_verify`
  (logged), with a TLS 1.2 floor. Same trust model as the Proxmox client.
* **SSRF guard** — cross-host HTTP redirects are refused, so a hostile/compromised
  endpoint can't bounce the client at internal services.
* **Drift-checked writes** — the compose text is re-fetched at apply time and the
  splice refuses if the target image line changed since propose.
* **Untrusted-input parsing** (compose text from the API/DB) is fuzzed.
* **Dry-run by default**; ambiguous cases (git-backed stacks) are reported, never
  blind-written.

## Limitations (current)

Managed rollback is not yet wired into the canary rollback path (which is
file-backup based); Portainer retains prior stack state and a re-pin can restore
a previous digest. A dedicated managed-rollback path is a follow-up.
