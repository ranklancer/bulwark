# CI hardening (staged)

Drop-in CI files that `bulwark-ci` cannot push (it is contents-only; GitHub
rejects any push touching `.github/workflows/*` without the `workflow` scope).
Activate each with a workflow-scoped token.

## 1. Static-analysis + supply-chain scan gate

`scan.yml` runs golangci-lint + gosec (blocking) and govulncheck (advisory) on
push/PR, mirroring `make gate-full` and the advisory tools. Pinned versions
match the `Makefile` (golangci-lint v1.61.0, govulncheck v1.1.4, gosec v2.20.0),
Go 1.22.

```sh
cp docs/ci/scan.yml .github/workflows/scan.yml
git add .github/workflows/scan.yml
git commit -m "ci: add static-analysis + supply-chain scan gate"
git push   # requires the workflow scope
```

**Make govulncheck blocking** once the CI Go version is bumped past the current
stdlib-CVE patch level (remove `continue-on-error: true`). On Go 1.22 it flags
stdlib CVEs fixed in later Go patches — a toolchain decision, not a repo fix.

## 2. SHA-pin third-party actions

Pin every third-party action to a full commit SHA (a tag is mutable; a SHA is
not) across `ci.yml`, `release.yml`, `docs/release/release-dogfood.yml`, and
`scan.yml`. Pattern:

```yaml
# before
- uses: actions/checkout@v4
# after (SHA of the v4.x tag you vetted, with the tag in a trailing comment)
- uses: actions/checkout@<40-char-sha>   # v4.2.2
```

Actions to pin (resolve each SHA from the tag you vet at pin time):

| Action | Pinned tag to resolve |
|---|---|
| actions/checkout | v4.2.2 |
| actions/setup-go | v5.0.2 |
| golangci/golangci-lint-action | v6.1.1 |
| docker/setup-buildx-action | v3.7.1 |
| docker/login-action | v3.3.0 |
| docker/metadata-action | v5.5.1 |
| goreleaser/goreleaser-action | v6.0.0 |
| anchore/sbom-action | v0.17.2 |
| sigstore/cosign-installer | v3.6.0 |
| slsa-framework/slsa-github-generator | v2.0.0 |

Resolve a tag → SHA with: `gh api repos/<owner>/<repo>/git/ref/tags/<tag> -q .object.sha`
(the annotated-tag object may need a second deref to the commit).

## 3. Digest-pin the Dockerfile base images

Pin each `FROM` to an immutable `@sha256:` digest so a moved tag can't change the
build — the same doctrine Bulwark enforces on the images it guards. In
`Dockerfile`:

```dockerfile
# before
FROM node:${NODE_VERSION}-alpine AS web
FROM golang:${GO_VERSION}-alpine AS go
FROM alpine:3.20
# after (resolve each digest with: docker buildx imagetools inspect <ref>)
FROM node:${NODE_VERSION}-alpine@sha256:<digest> AS web
FROM golang:${GO_VERSION}-alpine@sha256:<digest> AS go
FROM alpine:3.20@sha256:<digest>
```

Keep the human-readable tag alongside the digest (as above) so Dependabot / a
bump PR can still track updates. This change touches only the `Dockerfile`
(pushable by `bulwark-ci`) and can land in the fix-forward PR if you want it now
 it was left out here to keep the security-code changes reviewable in isolation.
