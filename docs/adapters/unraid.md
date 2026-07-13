# Unraid Source adapter

Unraid manages each Docker container from an XML **template** —
`/boot/config/plugins/dockerMan/templates-user/my-<Name>.xml` — whose
`<Repository>` element holds the image reference Unraid (re)creates the container
from. The template on disk is the source of truth, so bulwark pins an Unraid
container by editing the `<Repository>` value **in place**, with the full digest pinning
file-safety contract and the same write-boundary guards as the Dockge and
Podman-quadlet adapters. Its `Kind()` is `file`.

## How a pin is applied

1. `Discover` walks each configured template dir for `*.xml` files. It never
   follows a symlink out of a root (`WalkDir`/`Lstat`; a symlinked entry is
   skipped, and every real file is resolved and must still stay within its root —
   fail-closed). The resolved path is carried forward as the target; the target
   name is the template's `my-` prefix and `.xml` suffix stripped (e.g. `Nginx`).
2. `LocateImageRefs` parses the template and returns the single-line
   `<Repository>…</Repository>` value (line number included), classifying
   `:latest`/untagged and unparseable refs as non-pinnable.
3. `ProposePin` computes the digest edit with the shared, adapter-agnostic
   proposer (fail-closed digest validation) — no write.
4. `WritePin` re-asserts, at the write boundary: a Proposal with `Path` and
   `Line`; non-empty old/new values; the new value is an `@sha256:` digest; the
   target still resolves inside a configured template dir (path-traversal /
   symlink-escape guard); and its final component is not a symlink (`O_NOFOLLOW`).
   It then splices only the value inside `<Repository>` with the shared
   drift-checked, format-preserving splicer and writes via the shared
   backup + atomic-rename path. Rollback restores the timestamped backup
   byte-for-byte.

The splice is the single, format-agnostic `spliceValueOnLine` shared with the
compose and quadlet adapters (keyed here on the `<Repository>` open tag), so the
drift-checked edit can never diverge between write paths.

## Configuration

```yaml
sources:
  - name: unraid
    type: unraid
    # paths: [/boot/config/plugins/dockerMan/templates-user]   # explicit roots
    autodiscover: true                                          # else probe the default
    # extra_roots: [/mnt/user/appdata/templates]               # additional roots
```

With `autodiscover: true` and no explicit `paths`, the adapter probes the Unraid
default templates-user root plus any `extra_roots`. Explicit `paths` override
autodetection. Nothing is hardcoded to a specific host.

## Safety contract

- **Dry-run first** — `ProposePin` performs no write.
- **Backup + atomic + rollback** — the original template is copied to a
  timestamped backup before the in-place edit; the write is a same-dir temp file
  + fsync + rename; `Rollback` restores the backup byte-for-byte.
- **Format-preserving** — only the `<Repository>` value changes; every other
  element, attribute, comment and line terminator is byte-preserved.
- **Idempotent** — re-pinning to the same digest is a no-op.
- **Drift-checked, fail-closed** — the target line must still carry the
  `<Repository>` tag and still contain the exact pre-pin value, else refused. A
  `<Repository>` value that spans lines is not spliced (fail-closed).
- **Write-boundary guards (TOCTOU)** — containment and `O_NOFOLLOW` are
  re-checked at write time, narrowing the propose→apply window. `O_NOFOLLOW`
  refuses a final-component symlink swap; it does not cover an
  intermediate-directory symlink swap (same as Dockge) — not exploitable when the
  template roots are root-owned.
- **Digest-only** — a hand-built or drifted proposal whose new value is not a
  canonical `@sha256:` digest is refused; empty `Path`/`Line`/old/new are refused.

The `imageRefsFromUnraidBytes` template parser is fuzzed (never panics on
untrusted template bytes).

## After a pin

Editing the template does not itself update the running container. Re-apply the
template from the Unraid Docker UI (or `docker` tooling) so the container is
recreated on the pinned digest — bulwark does not manage the container lifecycle.
