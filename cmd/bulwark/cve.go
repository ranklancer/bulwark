package main

import (
	"strings"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/cve"
)

// buildCVESource turns the loaded security block into a cve.Source plus the
// severity threshold to count toward urgency. Returns (nil, _) when the
// security axis is disabled or no usable backend is configured — the scanner
// treats a nil source as "no security axis", a clean no-op.
func buildCVESource(cfg *config.Config) (cve.Source, cve.Severity) {
	if cfg == nil || !cfg.Security.Enabled {
		return nil, cve.SeverityUnknown
	}
	threshold := cve.SeverityCritical
	if strings.EqualFold(strings.TrimSpace(cfg.Security.SeverityThreshold), "high") {
		threshold = cve.SeverityHigh
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Security.CVESource.Type)) {
	case "", "trivy":
		if dir := cfg.Security.CVESource.Trivy.ReportDir; dir != "" {
			return cve.TrivyDirSource{Dir: dir}, threshold
		}
		return nil, threshold
	default:
		return nil, threshold
	}
}
