# Contributing to Bulwark

Thank you for considering a contribution. Bulwark is in early development and
the surface area is still small enough that a thoughtful PR can move the
project meaningfully forward.

## Development setup

```sh
git clone https://github.com/ranklancer/bulwark.git
cd bulwark
go build ./...
go test ./...
./scripts/install-hooks.sh   # installs the PII pre-commit hook
```

## Ground rules

These are the project-specific rules. Standard Go style applies otherwise.

### No PII anywhere

The codebase contains no real IP addresses, email addresses, hostnames, or
domain names. Use:

- **IP addresses** from RFC-reserved ranges: 192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24 (RFC 5737), or RFC-1918 private ranges, or 127.x.x.x.
- **Email addresses** on documentation domains: `@example.com`, `@example.org`,
  `@example.net`. The literal `noreply@…` is also accepted.
- **Domain names** on `example.com`, `example.org`, or `example.net`.

`scripts/check-pii.sh` enforces this in CI and in the pre-commit hook.

### Risk classification is the core differentiator

The classifier (`internal/classifier`) is Bulwark's primary value proposition.
Changes to it require:

- Tests for every new code path.
- Test coverage for over-classification: a false BREAKING is acceptable
  (annoying), a false SAFE is not (dangerous).
- A note in the PR description explaining the rationale for any policy change.

### Code style

- `go vet` must pass; CI enforces this.
- `go test -race ./...` must pass; CI enforces this.
- Default to no comments. Add a comment only when the *why* is non-obvious
  (a hidden constraint, a workaround, a non-obvious invariant).
- Use `slog` for structured logging. Every log entry should include the
  stack name, container name, and operation where applicable.
- Use `context.Context` throughout. Long-running operations (snapshot,
  health-check polling) must respect context cancellation.

### Idempotency

Every Bulwark operation must be safe to retry. The update pipeline can crash
and restart at any point; the system must not be left inconsistent.

### Graceful degradation

If the snapshot backend is unavailable, still update (with a warning). If
release notes can't be fetched, still classify based on semver. If
notifications fail, still update. The pipeline must never be blocked by a
non-critical subsystem failure.

## Commit messages

Conventional Commits are encouraged but not strictly required:

```
feat(classifier): treat LSIO -ls bumps as ChangeLSIORebuild
fix(config): expand env vars before YAML parsing
test(classifier): cover prerelease graduation
```

## Reporting issues

When opening an issue, include:

- Bulwark version (`bulwark version`).
- The relevant section of your `bulwark.yaml` (with secrets redacted).
- Container/image references involved (using documentation-domain registries
  if you can — please don't paste your private registry hostnames).
- A reproduction case if possible.

## License

By contributing, you agree your contributions are licensed under the MIT
license, the same license that covers the rest of the project.
