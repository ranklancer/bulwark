# Vulnerability scan sources

Bulwark's vulnerability axis (`security.cve_source`) is pluggable. Every provider
implements the same read seam — `Vulns(ref) -> ([]Vuln, error)` — and is selected
by `security.cve_source.type`. All providers today are **report-dir** sources:
they read pre-generated JSON reports from a directory, so there is no live
scanner or advisory-API call on the update hot path. A non-matching report is
treated as "none / unknown" (the axis is skipped for that image), never as a
silent pass.

| `type` | Reads | Report format |
|---|---|---|
| `trivy` (default) | `trivy image --format json` reports | Trivy JSON |
| `grype` | `grype -o json` reports | Grype JSON |
| `docker-scout` | `docker scout cves --format sarif` reports | SARIF 2.1.0 |
| `registry` | `osv-scanner --format json` advisory results | OSV results |

## `docker-scout`

```yaml
security:
  enabled: true
  cve_source:
    type: docker-scout
    docker_scout:
      report_dir: /var/lib/bulwark/scout-reports
```

Generate reports with:

```sh
docker scout cves <ref> --format sarif --output <report_dir>/<name>.sarif.json
```

The adapter parses the SARIF `runs[].tool.driver.rules[]` for CVE id, severity
(`properties.cvssV3_severity`, else the numeric `security-severity` CVSS score
bucketed to a band) and title. It identifies the analyzed image from
`runs[].properties.imageName`, falling back to `runs[].automationDetails.id`,
and — when a report declares no image at all — to the report **filename**
(convention: `repo_tag.sarif.json`, with `/` and `:` sanitized to `_`).

## `registry` (advisory)

```yaml
security:
  enabled: true
  cve_source:
    type: registry
    registry:
      report_dir: /var/lib/bulwark/advisories
```

Generate reports with an advisory-database scanner such as osv-scanner:

```sh
osv-scanner --format json --output <report_dir>/<name>.json --image <ref>
```

The adapter parses OSV `results[].packages[].vulnerabilities[]`, preferring a
`CVE-*` alias over the native OSV/GHSA id, and takes severity from
`database_specific.severity` (else a numeric CVSS `severity[].score`). A bare
CVSS vector with no numeric band is left `unknown` rather than guessed. The image
is matched on `results[].source.path`, with the same filename fallback as above.

## Digest matching

When the requested ref is digest-pinned, matching is **strict on digest**: a
report for the same tag but a different digest does not match. This is what keeps
a "current" and a "candidate" image (same tag, different digest) from collapsing
onto one report.

## Truncated reports

A structurally empty (truncated) report — one that parses but carries no runs
or results — is treated as **UNKNOWN** and fails closed, but only for a report
that can be **attributed to the requested reference**. Attribution uses the
report's declared image (`imageName` / `source.path`) and, as a fallback, the
report **filename**. A truncated report that both (a) declares no image in its
content and (b) has a filename that does not match the requested reference
cannot be attributed to any image, and is therefore skipped for all references.

This is safe by design — such a report is never read as "clean" for any
specific image — but a scanner whose output omits the image identity could let
a truncation go unsurfaced. Follow the `repo_tag` filename convention (with `/`
and `:` sanitized to `_`) so a truncated report stays attributable to its image.

## Fail-closed

When `security.enabled=true` and a backend is configured but cannot be built
(unknown provider, missing `report_dir`, or an unimplemented server mode), the
daemon/CLI fails at startup rather than silently disabling the axis.

## Scope & future phases

All providers are report-dir (file-based) in this phase. Live variants — invoking
`docker scout` directly, or fetching a vulnerability/VEX attestation from a
registry's OCI referrers API — are a future phase and would surface as new
`ScanSourceKind`s (`server`, `registry`) without changing the trust gate.
