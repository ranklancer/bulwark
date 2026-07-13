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
4. `WritePin` first re-asserts the new value is a `@sha256:` **digest** pin (parity
   with the file write path -- a hand-built or drifted proposal can never splice a
   bare tag onto the orchestrator), re-fetches the stack (freshness + source
   check), and splices the digest into the *current* `file_contents` with the
   shared drift-checked splicer.
5. It then pushes back a **read-modify-write of the FULL config** (`POST /write`
   `UpdateStack`): the exact `config` object Komodo returned, with **only**
   `file_contents` replaced. This preserves `environment`, volumes and every other
   field **regardless of whether Komodo's `UpdateStack` merges or replaces** the
   config object -- the guarantee does not rest on merge semantics. (The full-config re-send is a JSON round-trip, so an integer config field larger than 2^53 could lose precision; the byte-for-byte env-survival gate below is the backstop.) If the fetched
   stack returns no `config` object, the write is refused (env-preservation cannot
   be guaranteed).

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

## ⚠️ HARD pre-production gate: a live env-survival smoke test

This adapter has **not** been exercised against a live Komodo instance; its
coverage is unit + `httptest` fakes only. Enabling a Komodo source against a
production stack is **BLOCKED** until the following live smoke test passes -- this
is a hard gate, not a recommendation.

Run one capture against a disposable UI-defined stack **that has at least one
`environment` variable set** and assert, in order:

1. `Discover` / `LocateImageRefs` return the stack and its expected image(s).
2. A `--apply` writes the pinned `@sha256:` digest via `UpdateStack`.
3. **Env survival (the blocking assertion):** re-fetch the stack after the write
   and confirm every pre-existing `environment` entry (and any volumes / other
   config) is **byte-for-byte unchanged** -- only `file_contents` differs. If any
   env value is missing or altered, the Komodo `UpdateStack` contract differs from
   what this adapter assumes; **do not ship** -- stop and re-evaluate the write.
4. A repo/resource-sync-backed stack and a files-on-server stack are both refused.
5. A stack whose `GetStack` returns no `config` object is refused (not written empty).

Only after step 3 is verified green against the live API may a Komodo source be
promoted beyond a disposable test stack. The full-config read-modify-write and the
empty-`file_contents` / missing-`config` guards exist precisely because this
contract is unconfirmed end-to-end until this gate runs.
