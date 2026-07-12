package cve

import (
	"fmt"
	"strings"
)

// ScanSourceKind classifies HOW a scan source obtains vulnerability data,
// mirroring the digest pinning capture-provider split (file-based vs API/managed). It lets
// the daemon select, validate, and describe a backend uniformly, and lets new
// providers slot in without touching the trust gate.
type ScanSourceKind string

const (
	// ScanKindReportDir reads pre-generated JSON reports from a directory
	// (`trivy image -f json`, `grype -o json`). File-based; no live scanner call
	// on the hot path. This is the only implemented kind today.
	ScanKindReportDir ScanSourceKind = "report-dir"
	// ScanKindServer talks to a running scanner server (Trivy/Grype server mode).
	// Not implemented yet — rejected at construction until an adapter ships.
	ScanKindServer ScanSourceKind = "server"
	// ScanKindRegistry reads advisories from a registry's vulnerability API
	// (e.g. Docker Scout, Harbor). Not implemented yet.
	ScanKindRegistry ScanSourceKind = "registry"
)

// ScanSource is the provider abstraction over vulnerability scanners. It extends
// the read seam (Source) with provider identity + kind, so a backend can be
// selected from config, validated, and surfaced in audit/telemetry the same way
// digest pinning's capture.Source is. A ScanSource IS a Source, so it drops into verify.Gate
// (and anything else taking a cve.Source) unchanged.
type ScanSource interface {
	Source
	// Provider is the backend name: "trivy", "grype", "docker-scout", ...
	Provider() string
	// Kind classifies how it obtains data.
	Kind() ScanSourceKind
}

// scanSource decorates a Source with provider identity + kind.
type scanSource struct {
	Source
	provider string
	kind     ScanSourceKind
}

func (s scanSource) Provider() string     { return s.provider }
func (s scanSource) Kind() ScanSourceKind { return s.kind }

// NewTrivyReportDir wraps a Trivy JSON-report directory as a ScanSource.
func NewTrivyReportDir(dir string) ScanSource {
	return scanSource{Source: TrivyDirSource{Dir: dir}, provider: "trivy", kind: ScanKindReportDir}
}

// NewGrypeReportDir wraps a Grype JSON-report directory as a ScanSource.
func NewGrypeReportDir(dir string) ScanSource {
	return scanSource{Source: GrypeDirSource{Dir: dir}, provider: "grype", kind: ScanKindReportDir}
}

// ScanSourceSpec is a resolved backend selection (from config).
type ScanSourceSpec struct {
	Provider  string // trivy | grype | docker-scout | registry
	ReportDir string // report-dir kind
	ServerURL string // server kind (not implemented)
}

// NewScanSource builds the configured ScanSource. Unimplemented providers and
// modes (server mode, docker-scout, registry advisories) return a clear error so
// a misconfiguration fails closed at construction rather than silently disabling
// the vulnerability axis — mirroring digest pinning's managed-backend rejection.
func NewScanSource(spec ScanSourceSpec) (ScanSource, error) {
	provider := strings.ToLower(strings.TrimSpace(spec.Provider))
	if provider == "" {
		provider = "trivy"
	}
	switch provider {
	case "trivy", "grype":
		if strings.TrimSpace(spec.ServerURL) != "" {
			return nil, fmt.Errorf("cve: %s server mode is not implemented yet (use report_dir)", provider)
		}
		if strings.TrimSpace(spec.ReportDir) == "" {
			return nil, fmt.Errorf("cve: %s scan source requires report_dir", provider)
		}
		if provider == "grype" {
			return NewGrypeReportDir(spec.ReportDir), nil
		}
		return NewTrivyReportDir(spec.ReportDir), nil
	case "docker-scout":
		return nil, fmt.Errorf("cve: docker-scout scan source is not implemented yet")
	case "registry":
		return nil, fmt.Errorf("cve: registry-advisory scan source is not implemented yet")
	default:
		return nil, fmt.Errorf("cve: unknown scan source provider %q (valid: trivy, grype)", spec.Provider)
	}
}
