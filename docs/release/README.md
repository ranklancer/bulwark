# Release dogfooding

Bulwark verifies other people's images; its **own** releases should meet the
same bar. This directory holds the supply-chain release pipeline that produces,
for every `v*` tag:

- reproducible multi-arch binaries (`linux/amd64`, `linux/arm64`);
- a `checksums.txt` (sha256);
- a **CycloneDX SBOM** per artifact (syft);
- **keyless cosign signatures** over the checksums (and thus every artifact + SBOM);
- **SLSA v1 build provenance** (slsa-github-generator), uploaded to the release.

## Files

- `../../.goreleaser.yaml` — GoReleaser config (builds, archives, checksum,
  SBOM, cosign). Pushable by a contents-only token.
- `release-dogfood.yml` — the GitHub Actions workflow, **staged here**.

## ⚠️ Activation needs a workflow-scoped token

A contents-only token cannot push `.github/workflows/*`; GitHub rejects any push touching
`.github/workflows/*` without the `workflow` scope. To activate:

```sh
cp docs/release/release-dogfood.yml .github/workflows/release-dogfood.yml
git add .github/workflows/release-dogfood.yml
git commit -m "ci(release): activate supply-chain release-dogfood workflow"
git push   # requires a PAT/GitHub App with the `workflow` scope
```

The workflow needs `id-token: write` (OIDC) for keyless cosign + SLSA — no
long-lived signing key is stored.

## Pinned tool versions

| Tool | Version |
|---|---|
| Go (build) | 1.22 |
| GoReleaser | v2.3.2 |
| syft | v1.14.0 |
| cosign | v2.4.1 |
| slsa-github-generator | v2.0.0 |

GoReleaser v2 requires Go ≥ 1.23 to run, so `goreleaser check` runs in CI, not on
the Go-1.22-pinned dev box; the `.goreleaser.yaml` here is YAML-validated locally
and config-checked by the workflow's `goreleaser check` step.

## Verifying a release

```sh
# signature over the checksums (keyless):
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/ranklancer/bulwark/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# then verify a binary against the signed checksums:
sha256sum -c checksums.txt --ignore-missing

# SLSA provenance (attestation uploaded alongside the assets):
slsa-verifier verify-artifact bulwark_<ver>_linux_amd64.tar.gz \
  --provenance-path bulwark_<ver>_linux_amd64.tar.gz.intoto.jsonl \
  --source-uri github.com/ranklancer/bulwark
```
