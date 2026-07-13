# Dockge Source adapter

Dockge stores each stack as `<stacksDir>/<stackName>/compose.yaml` on the host —
its own source of truth. Bulwark's Dockge adapter (`type: dockge`) pins those
stacks by editing the compose files **in place**, delegating the write to the
same audited engine the generic `compose` adapter uses (backup + atomic write +
format/comment-preserving + idempotent + rollback). It is file-based
(`Source.Kind() == file`); it never talks to the Dockge Socket.IO API, because
the on-disk compose files are already Dockge's authoritative definition.

It differs from the generic `compose` adapter only in **discovery**: it
understands Dockge's flat "stacks root" layout and can locate it automatically.

## Configuration

```yaml
sources:
  - name: dockge
    type: dockge
    # Explicit stacks roots (each directly contains <stack>/compose.yaml).
    paths:
      - /opt/stacks
    # …or let bulwark probe well-known locations instead of listing paths:
    autodiscover: true
    # Extra candidate roots consulted during autodiscover (e.g. an
    # additional apps stacks root). General — configure whatever your host uses.
    extra_roots:
      - /mnt/tank/ix-applications/dockge/stacks
    # Optional: point at the compose that runs Dockge itself; its stacks
    # bind-mount is read (never edited) to locate the host stacks root.
    dockge_compose: /opt/dockge/compose.yaml
```

Autodiscover probes, in order: the `dockge_compose` bind-mount (if given), the
`DOCKGE_STACKS_DIR` environment variable, the Dockge default `/opt/stacks`, and
any `extra_roots`. Only existing directories are scanned.

## Safety

* **Dry-run by default.** `bulwark capture` reports proposed pins; `--apply`
  performs the in-place edit (backup first, atomic rename, rollback recorded).
* **Fail-closed containment, checked at both discovery AND write.** A stack
  whose compose file resolves (via symlink) outside its stacks root is skipped
  at discovery; `Target.Path` carries the symlink-resolved path forward; and
  the write boundary re-asserts containment and opens the target with
  `O_NOFOLLOW`. So even if a directory component or the compose file is swapped
  to a symlink between propose and apply (TOCTOU), the write is refused —
  never redirected out of a configured root.
* **Digest-only writes.** Only a canonical `sha256:<64-hex>` digest is ever
  spliced into a compose file; malformed digests are refused at multiple layers.
* **Untrusted-input parsing** (the Dockge-compose stacks-dir locator) is fuzzed.

Anything ambiguous is reported, never blind-written.
