# SLSA & supply-chain posture (dogfooding)

Bulwark is a supply-chain security tool, so its own release chain should meet a
high bar. This tracks the target (SLSA Build **L3**) and the staged work toward
it. Ties to the pre-public hardening backlog items **a hardening tier / a hardening tier / a hardening tier / a hardening tier**.

## Current posture

- Static, reproducible binaries (`CGO_ENABLED=0`, `mod_timestamp`) via GoReleaser.
- SHA-256 `checksums.txt`; CycloneDX SBOM per archive (syft).
- Keyless **cosign** signature over `checksums.txt` (Sigstore, OIDC).
- Draft release for human review.
- **OpenSSF Scorecard** workflow -- **staged, not yet active.** The complete,
  SHA-pinned file lives at `docs/ci/scorecard.yml` (see the Ready-to-commit section below);
  it cannot be pushed to `.github/workflows/` without a workflow-scoped token, and it
  publishes the Scorecard badge + SARIF once the repo is public.

## Gaps to close (staged; land needs the workflow-scoped token)

### 1. SLSA provenance attestation on the image (a hardening tier)

The active release (`release.yml`) builds a multi-arch GHCR image but emits no
in-toto/SLSA provenance. Add buildx-native provenance+SBOM and a signed
attestation over the pushed digest:

```yaml
permissions:
  contents: read
  packages: write
  id-token: write     # Sigstore OIDC
  attestations: write # publish the attestation
# ...
      - name: Build and push
        id: build
        uses: docker/build-push-action@SHA # v6.x
        with:
          # ...existing inputs...
          provenance: mode=max
          sbom: true
      - name: Attest build provenance
        uses: actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373 # v4.1.1
        with:
          subject-name: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true
```

Verify with: `gh attestation verify oci://<image>@<digest> --owner ranklancer`.

### 2. SHA-pin every Action (a hardening tier / supply-chain doctrine)

`release.yml` and `ci.yml` currently pin actions by **mutable tag** (`@v4`, `@v6`,
). Convert each to a commit SHA with a version comment. Resolved SHAs (latest
majors — confirm the major bump is desired before landing, else pin the
in-use major's latest SHA):

| Action | Tag | SHA |
|---|---|---|
| actions/checkout | v7.0.0 | `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| github/codeql-action | v4.37.1 | `7188fc363630916deb702c7fdcf4e481b751f97a` |
| ossf/scorecard-action | v2.4.3 | `4eaacf0543bb3f2c246792bd56e8cdeffafb205a` |
| actions/attest-build-provenance | v4.1.1 | `0f67c3f4856b2e3261c31976d6725780e5e4c373` |
| docker/build-push-action | v7.3.0 | `53b7df96c91f9c12dcc8a07bcb9ccacbed38856a` |
| docker/metadata-action | v6.2.0 | `dc802804100637a589fabce1cb79ff13a1411302` |
| docker/login-action | v4.4.0 | `af1e73f918a031802d376d3c8bbc3fe56130a9b0` |
| docker/setup-buildx-action | v4.2.0 | `bb05f3f5519dd87d3ba754cc423b652a5edd6d2c` |

Note: the docker/* and checkout majors above are NEWER than the ones currently
in `release.yml` (checkout@v4, buildx@v3, login@v3, metadata@v5, build-push@v6).
A major bump can change inputs — validate on a test tag before landing, or pin
each to the latest SHA within its current major to SHA-pin without behaviour change.

### 3. Reproducible-build hardening (a hardening tier)

Add `-trimpath` to the GoReleaser build flags (currently `-s -w -X …`) for
path-independent reproducible binaries.

### 4. Wire the signed-binary release (a hardening tier)

Confirm the GoReleaser SBOM+cosign pipeline actually runs on release (the active
workflow is image-only). Either add a goreleaser release job or fold the binary
signing/SBOM/provenance into `release.yml`.

## Ready-to-commit: .github/workflows/scorecard.yml

The workflow file itself cannot be pushed by the current Contents-R/W PAT
(GitHub refuses workflow-file writes without the `workflow` scope — the
task #16 blocker). Create this file when a workflow-scoped token is
available; it is complete and SHA-pinned as-is:

```yaml
# OpenSSF Scorecard — supply-chain security posture scoring.
#
# Publishes results to the OpenSSF REST API (for the repo's Scorecard badge)
# and uploads SARIF to GitHub code scanning. All actions are SHA-pinned
# (the project's supply-chain doctrine); the trailing comment records the human tag.
#
# NOTE (parked): landing this needs the workflow-scoped token, and Scorecard's
# publish_results + code-scanning upload require the repo to be PUBLIC. It is
# a no-op-until-public safety net staged ahead of the pre-public flip.
name: scorecard

on:
  branch_protection_rule:
  schedule:
    - cron: '30 5 * * 1' # weekly, Monday 05:30 UTC
  push:
    branches: [main]

# Top-level: read-only. The analysis job elevates only what it needs.
permissions: read-all

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    permissions:
      security-events: write # upload SARIF to code scanning
      id-token: write        # publish results to the OpenSSF REST API
    steps:
      - name: Checkout
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false

      - name: Run Scorecard analysis
        uses: ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a # v2.4.3
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload SARIF artifact
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: SARIF file
          path: results.sarif
          retention-days: 5

      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@7188fc363630916deb702c7fdcf4e481b751f97a # v4.37.1
        with:
          sarif_file: results.sarif
```
