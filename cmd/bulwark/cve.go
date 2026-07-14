package main

import (
	"fmt"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/cve"
)

// buildCVESource turns the loaded security block into a cve.Source plus the
// severity threshold to count toward urgency. It selects a backend through the
// cve.ScanSource provider factory (trivy | grype today; docker-scout / registry
// are recognised extension points that fail closed until an adapter ships).
//
// Returns (nil, _) when the security axis is disabled or no backend is
// configured — the scanner treats a nil source as "no security axis", a clean
// no-op. Config validation (validateSecurity) rejects a malformed backend at
// startup; here we additionally fail safe to "no axis" rather than crash a scan
// loop if construction ever errors.
func buildCVESource(cfg *config.Config) (cve.Source, cve.Severity, error) {
	if cfg == nil || !cfg.Security.Enabled {
		return nil, cve.SeverityUnknown, nil
	}
	threshold := cve.SeverityCritical
	if strings.EqualFold(strings.TrimSpace(cfg.Security.SeverityThreshold), "high") {
		threshold = cve.SeverityHigh
	}

	c := cfg.Security.CVESource
	provider := strings.ToLower(strings.TrimSpace(c.Type))
	if provider == "" {
		provider = "trivy"
	}
	var reportDir, serverURL string
	switch provider {
	case "trivy":
		reportDir, serverURL = c.Trivy.ReportDir, c.Trivy.ServerURL
	case "grype":
		reportDir, serverURL = c.Grype.ReportDir, c.Grype.ServerURL
	case "docker-scout":
		reportDir, serverURL = c.DockerScout.ReportDir, c.DockerScout.ServerURL
	case "registry":
		reportDir, serverURL = c.Registry.ReportDir, c.Registry.ServerURL
	}
	// Preserve the "silently off when unconfigured" behaviour: a trivy/grype
	// type with no report_dir (or server_url) leaves the axis inert. This is a
	// deliberate no-op, not a misconfiguration.
	if strings.TrimSpace(reportDir) == "" && strings.TrimSpace(serverURL) == "" {
		return nil, threshold, nil
	}

	src, err := cve.NewScanSource(cve.ScanSourceSpec{Provider: provider, ReportDir: reportDir, ServerURL: serverURL})
	if err != nil {
		// Fail closed: security is enabled and a backend IS configured, but it
		// cannot be built. Do NOT silently disable the vulnerability axis — that
		// would admit images through a gate the operator believes is active.
		// Surface the error so the daemon/CLI fails at startup.
		return nil, threshold, fmt.Errorf("cve: security.enabled but scan source %q could not be built: %w", provider, err)
	}
	return src, threshold, nil
}
