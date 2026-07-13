# Komodo Source adapter

Komodo is an API/DB-managed container orchestrator. Each stack is defined either
in Komodo's own database (a "UI-defined" stack, whose compose text is stored in
the `file_contents` field), in a git repository (a repo / resource-sync-backed
stack), or as files on the managed server. Because the source of truth is the
Komodo backend — not a compose file on the bulwark host — this adapter pins
stacks **through the Komodo API** and never edits files on disk. Its `Kind()` is
`managed`, which the core uses to keep it on the API write path and off the
file-editing path.

Only UI-defined stacks are pinnable. Repo-backed stacks (source of truth = git)
and files-on-server stacks are **refused**: bulwark reports them and pins
nothing, rather than fighting or corrupting the real source of truth.

## How a pin is applied

1. `Discover` lists stacks (`POST /read` `{type: ListStacks}`); one target per
   stack, keyed by stack id.
2. `LocateImageRefs` fetches the stack (`POST /read` `{type: GetStack}`) and
   extracts image references from `config.file_contents` using the shared
   compose parser (the same parser the file adapters use).
3. `ProposePin` computes the pin edit with the shared, adapter-agnostic proposer.
4. `WritePin` re-fetches the stack (freshness + source check), splices the digest
   into the *current* `file_contents` with the shared drift-checked splicer, and
   pushes it back with a **partial** `UpdateStack` (`POST /write`) that carries
   only `file_contents`. Komodo merges the partial config, so the stack's
   `environment` and every other field are preserved untouched.

## Configuration

```yaml
sources:
  - name: komodo
    type: komodo
    endpoint: https://komodo.example:9120   # Komodo API base URL
    creds_ref: KOMODO_API_CREDS             # env var holding "key:secret"
    # ca_file: /etc/bulwark/komodo-ca.pem   # pin a private CA (optional)
    # insecure_skip_verify: false           # opt-out of TLS verification (discouraged)
    # allow_insecure_http: false            # allow a cleartext http:// base (discouraged)
```

Komodo authenticates with an API **key + secret** pair. Both are read from the
single environment variable named by `creds_ref`, formatted `key:secret`. The
secret is never stored inline in configuration, never logged, and never included
in error messages. Provision the key/secret pair with the **minimum scope**
required to read and update the stacks bulwark manages.

## Security

The Komodo client reuses the shared managed-backend hardening (`managed_http.go`),
identical to the Portainer adapter so the two cannot drift:

- **TLS fail-closed** — TLS 1.2 floor; system trust by default; a private CA via
  `ca_file`; verification is disabled only on an explicit, logged
  `insecure_skip_verify` opt-in.
- **Cleartext base refused** — a cleartext `http://` base URL to a non-loopback
  host is refused (credentials would travel unencrypted) unless
  `allow_insecure_http: true` is set; loopback is always allowed.
- **Credential-downgrade redirect guard** — redirects that change host, or that
  change scheme (e.g. an `https`→`http` downgrade that would re-send the
  `X-Api-Key`/`X-Api-Secret` headers over cleartext), are refused.
- **SSRF connect-IP guard** — the dialer inspects the resolved IP just before
  connect and refuses link-local (e.g. cloud-metadata `169.254.0.0/16`),
  multicast and unspecified addresses, containing DNS-rebinding to those targets.
  Loopback and RFC1918 remain allowed (self-hosted orchestrators commonly live
  on a private/loopback address).
- **Drift-checked writes** — the splice fails closed if the live `file_contents`
  no longer contains the exact value seen at propose time, so a stack changed
  out-of-band is never silently overwritten.
- **Positive source signals, fail-closed** — a stack is treated as git-backed if
  `config.repo` or `config.linked_repo` is non-empty, and as files-on-server if
  `config.files_on_host` is true; both are refused. A UI-defined stack with empty
  `file_contents` is also refused (unexpected shape ⇒ do not push an empty
  compose).
- **Bounded reads** — API responses are read under an 8 MiB cap.

## Managed rollback

Managed pins have **no on-disk backup** to restore from, because bulwark never
wrote a file. If a canary fails, the automatic file-rollback path does not apply
to a Komodo pin; the canary controller reports **`MANUAL ROLLBACK REQUIRED`** and
takes no destructive action. Roll back by editing the stack in Komodo (revert the
image tag / remove the digest) and redeploying.

## ⚠️ Required before production: a live smoke test

The adapter is covered by unit tests against a fake Komodo API and an httptest
server, but it has **not** been exercised against a live Komodo instance. Before
relying on it in production, run one capture against a disposable UI-defined
stack and confirm: (1) `Discover`/`LocateImageRefs` return the expected images;
(2) a `--apply` writes the pinned digest via `UpdateStack`; (3) the stack's
`environment` and other config survive the partial update unchanged; (4) a
repo-backed and a files-on-server stack are both refused. The empty-`file_contents`
guard exists specifically because the live `GetStack`/`UpdateStack` contract has
not yet been confirmed end-to-end.
