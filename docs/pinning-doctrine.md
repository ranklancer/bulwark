# Bulwark Digest-Pinning Doctrine (digest pinning)

> Status: doctrine for the digest pinning digest-pin capture + canary capability.
> Maintained per ISO/IEC/IEEE 15289:2019 and ISO/IEC/IEEE 26515:2018.
> No PII, no secrets, no host-specific addresses. Paths shown are illustrative.

## 1. Purpose and scope

Bulwark pins the container images an operator already runs to immutable,
multi-arch **index** digests, so automation reasons about a fixed artifact
rather than a mutable tag. This document is the operating doctrine for that
capability: the safety rules, the provider model, what qualifies for the first
batch, and the capture → verify → canary → batch rollout. It applies to the
`bulwark capture`, `bulwark pin`, and `bulwark canary` commands.

## 2. Two edit disciplines — do not conflate them

Bulwark is a **product** that runs in other operators' environments. Two
completely different "edit" flows exist, and the distinction is load-bearing:

1. **Developing Bulwark's own Go code** is **dev-first / PR-gated**: changes are
   made in a development environment and land in `ranklancer/bulwark` via a pull
   request that must pass the full gate (`gofmt`, `go vet`, `go build`,
   `go test -race`, secret + PII scans) before merge.
2. **Editing an operator's stack definitions at runtime** is an **in-place,
   host-resident, safety-wrapped product operation**. It does **not** assume a
   git repository of the operator's stacks and never routes through a PR. Most
   operators run Docker Compose / Dockge on a host with no IaC repo; Bulwark
   edits the file where it lives, safely, or goes through the orchestrator's API
   for managed backends.

Conflating these — e.g. assuming a user's stacks are in git — is the mistake digest pinning
explicitly corrected (see the digest-pin capture design §0).

## 3. Provider model — file-based vs API/DB-managed

Capture is built around a backend-agnostic `Source` provider interface
(`internal/capture`). The capture and canary core depend only on the interface,
so backends slot in without touching it. The hard rule is **how** a pin is
written:

| Backend | Kind | How Bulwark pins |
|---|---|---|
| Dockge (flat stacks-root) | **file** | edit `compose.yaml` in place |
| Raw compose dirs / single compose files | **file** | edit the compose in place |
| podman quadlets (`.container`) | **file** | edit the `Image=` line in place *(future adapter)* |
| Portainer (stacks-in-DB) | **managed** | Portainer API stack update *(future)* |
| TrueNAS SCALE ix-apps | **managed** | ix-apps API / values *(future)* |
| Komodo | **managed** | Komodo API / its git source-of-truth *(future)* |
| Docker Swarm | **managed** | `service update --image` *(future)* |

**A managed backend is never pinned by editing files on disk** — always through
its API or declared source of truth. digest pinning implements the **file-based compose
adapter only**; managed backends are recognised by config validation but
rejected until their adapter ships.

## 4. What qualifies for the first batch (an internal note), and what defers to the full-fleet sweep

The digest pinning first batch pins only **unambiguous** images:

- a **public registry** reference,
- that resolves to a **multi-arch index** (or is explicitly marked single-arch
  via `bulwark.pin.require-index=false`),
- pinned to a **concrete tag** (not `:latest`, not untagged).

**Deferred to the full-fleet sweep** (the full-fleet sweep), surfaced as `skip` with a reason:

- locally-built images (`build:` context),
- private registries without a configured pull token,
- `:latest`-only or untagged images,
- images composed from `${VAR}` (var-aware pinning is a later refinement),
- **all managed backends** (until their adapter ships).

Capture never blind-writes an ambiguous target; it reports and moves on.

## 5. The rollout runbook: capture → verify → canary → batch

1. **Capture (dry-run).** Point Bulwark at the stacks and preview:
   `bulwark capture --stacks-path /path/to/stacks` (or `--config` with a
   `sources:` block). It prints the exact inline pin it *would* apply and the
   `skip` reasons for everything deferred. **Nothing is written.**
2. **Apply.** Re-run with `--apply`. Each edit is backed up, written atomically,
   and format/comment-preserving; the pin is recorded in `pins.json`. Re-running
   is idempotent.
3. **Verify.** `bulwark capture --verify --config <cfg>` evaluates each pinned
   digest through the trust gate (signature + vulnerability axes) and reports
   the verdict. This is the same gate the daemon uses.
4. **Canary.** Promote one low-risk stack first:
   `bulwark canary start <stack>/<service>`, observe health, then
   `bulwark canary promote <stack>/<service> --config <cfg>` — promotion is
   refused if the trust gate returns `block`. `bulwark canary rollback` restores
   the compose file byte-for-byte from its backup.
5. **Batch.** Once the canary is stable, apply the rest of the unambiguous batch.
   Exceptions from §4 are catalogued and carried to the full-fleet sweep.

## 6. Safety guarantees (the guardrails)

Because in-place edits mutate an operator's infrastructure files, every write is:

- **dry-run by default** — `--apply` is required to write anything;
- **backed up** — the original is copied before any edit, path recorded for rollback;
- **atomic** — temp file + `fsync` + `rename`, never truncate-in-place;
- **format/comment preserving** — only the `image:` scalar changes; every other byte is identical;
- **idempotent** — re-running against an already-pinned file is a no-op;
- **refuse-on-drift** — if the file changed since the pin was proposed, Bulwark refuses rather than risk a bad write;
- **reversible** — `bulwark pin rollback` / `bulwark canary rollback` restore the backup byte-for-byte.

No credentials or secrets are ever written to `pins.json`, to compose files, or
to logs. Registry pull credentials are pull-only and sourced from the secret
store.

## 7. Operator quickstart

```sh
# Preview (writes nothing):
bulwark capture --stacks-path /srv/stacks

# Apply, recording pins under a data dir:
bulwark capture --stacks-path /srv/stacks --data-dir /var/lib/bulwark --apply

# Inspect / roll back a pin:
bulwark pin list --data-dir /var/lib/bulwark
bulwark pin rollback --data-dir /var/lib/bulwark mystack/myservice

# Canary one stack, gated on the trust verdict:
bulwark canary start   --data-dir /var/lib/bulwark mystack/myservice
bulwark canary promote --data-dir /var/lib/bulwark --config /etc/bulwark.yaml mystack/myservice
bulwark canary rollback --data-dir /var/lib/bulwark mystack/myservice
```

## 8. Relationship to the roadmap

digest pinning produces the pinned index digests that **the trust engine** (signature + provenance/SBOM
verification) checks against, and lays the groundwork for **the full-fleet sweep** (extend safe
pinning across the full configured stacks tree; where an operator keeps an IaC
repo, an optional Renovate flow may bump the inline digests via PR — optional,
never assumed).

---
*Doctrine for digest pinning. See the digest-pin capture design (implementation plan) and `docs/verify-gate.md`.*
