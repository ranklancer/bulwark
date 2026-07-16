# Podman quadlets Source adapter

Podman's systemd generator reads quadlet unit files — `*.container`, `*.pod`,
`*.kube` — and turns them into systemd services. The unit file on disk is the
source of truth, so bulwark pins a Podman workload by editing the `Image=` key of
a `.container` unit **in place**, with the full digest pinning file-safety contract and the
same write-boundary guards as the Dockge adapter. Its `Kind()` is `file`.

## Scope: which units carry a pinnable image

Only `.container` units have an in-unit image (the `Image=` key in the
`[Container]` section) — that is what this adapter pins. `.pod` units aggregate
containers and carry no image; `.kube` units reference an external Kubernetes
manifest whose images live in that manifest, not the unit. Neither has an in-unit
image, so they yield no pinnable refs here. An `Image=` that points at a `.image`
quadlet unit (an indirection) or is otherwise unparseable is reported
non-pinnable rather than pinned.

## How a pin is applied

1. `Discover` walks each configured unit dir for `*.container` files. It never
   follows a symlink out of a root (WalkDir uses `Lstat`; a symlinked entry is
   skipped, and every real file is resolved and must still stay within its root —
   fail-closed). The resolved path is carried forward as the target.
2. `LocateImageRefs` parses the unit and returns the `[Container]` `Image=`
   reference (line number included), classifying `:latest`/untagged and
   unparseable refs as non-pinnable.
3. `ProposePin` computes the digest edit with the shared, adapter-agnostic
   proposer (fail-closed digest validation) — no write.
4. `WritePin` re-asserts, at the write boundary: the new value is an `@sha256:`
   digest; the target still resolves inside a configured unit dir
   (path-traversal / symlink-escape guard); and its final component is not a
   symlink (`O_NOFOLLOW`). It then splices only the `Image=` value with the shared
   drift-checked, format-preserving splicer and writes via the shared
   backup + atomic-rename path. Rollback restores the timestamped backup
   byte-for-byte.

The splice is the single, format-agnostic `spliceValueOnLine` shared with the
compose adapters (compose keys on `image:`, quadlet on `Image=`), so the
drift-checked edit can never diverge between write paths.

## Configuration

```yaml
sources:
  - name: podman
    type: podman-quadlet
    # paths: [/etc/containers/systemd]   # explicit quadlet unit roots
    autodiscover: true                    # else probe well-known roots
    # extra_roots: [/srv/quadlets]        # additional roots for autodiscovery
```

With `autodiscover: true` and no explicit `paths`, the adapter probes the system
quadlet root (`/etc/containers/systemd`), the per-user root under
`$XDG_CONFIG_HOME`/`$HOME` (`~/.config/containers/systemd`), and any `extra_roots`.
Explicit `paths` override autodetection. Nothing is hardcoded to a specific host.

## Safety contract

- **Dry-run first** — `ProposePin` performs no write; the operator reviews the
  diff before `--apply`.
- **Backup + atomic + rollback** — the original unit is copied to a timestamped
  backup before an in-place edit; the write is a same-dir temp file + fsync +
  rename (a crash never leaves a half-written unit); `Rollback` restores the
  backup byte-for-byte.
- **Format-preserving** — only the `Image=` value changes; every other key,
  comment, blank line and line terminator is byte-preserved.
- **Idempotent** — re-pinning to the same digest is a no-op.
- **Drift-checked, fail-closed** — the target line must still be the `Image=` line
  and still contain the exact pre-pin value, else the write is refused.
- **Write-boundary guards (TOCTOU)** — containment and `O_NOFOLLOW` are
  re-checked at write time, narrowing the propose→apply window: `O_NOFOLLOW`
  refuses a final-component symlink swap and the containment re-check refuses a
  target that no longer resolves inside a root. `O_NOFOLLOW` guards only the
  FINAL component, not an intermediate-directory symlink swap (same as Dockge);
  that is not exploitable when the unit roots are root-owned.
- **Digest-only** — a hand-built or drifted proposal whose new value is not a
  canonical `@sha256:` digest is refused.

The `imageRefsFromQuadletBytes` unit parser is fuzzed (never panics on untrusted
unit-file bytes).

## After a pin

Editing a quadlet unit does not itself restart the service. Reload the generator
and restart the unit through the operator's normal path (e.g. `systemctl
daemon-reload` then restart the generated service) — bulwark does not manage the
systemd lifecycle.
