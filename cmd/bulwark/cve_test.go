package main

import (
	"testing"

	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/internal/cve"
)

func TestBuildCVESource(t *testing.T) {
	if src, _, _ := buildCVESource(nil); src != nil {
		t.Error("nil config must yield nil source")
	}
	if src, _, _ := buildCVESource(&config.Config{}); src != nil {
		t.Error("disabled security must yield nil source")
	}
	cfg := &config.Config{}
	cfg.Security.Enabled = true
	cfg.Security.SeverityThreshold = "high"
	cfg.Security.CVESource.Type = "trivy"
	cfg.Security.CVESource.Trivy.ReportDir = "/var/reports"
	src, th, err := buildCVESource(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src == nil {
		t.Fatal("expected a TrivyDirSource")
	}
	ss, ok := src.(cve.ScanSource)
	if !ok {
		t.Errorf("expected a cve.ScanSource, got %T", src)
	} else if ss.Provider() != "trivy" || ss.Kind() != cve.ScanKindReportDir {
		t.Errorf("provider/kind = %q/%q, want trivy/report-dir", ss.Provider(), ss.Kind())
	}
	if th != cve.SeverityHigh {
		t.Errorf("threshold = %v, want high", th)
	}
	// enabled but no report dir => nil source (nothing usable)
	cfg.Security.CVESource.Trivy.ReportDir = ""
	if src, _, _ := buildCVESource(cfg); src != nil {
		t.Error("trivy without report_dir must yield nil source")
	}
}

// TestBuildCVESource_FailClosed guards the review fix: when security.enabled
// and a backend is CONFIGURED but cannot be built (here: trivy server mode,
// unimplemented), buildCVESource must error at startup rather than silently
// disabling the vulnerability axis (fail-open).
func TestBuildCVESource_FailClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Enabled = true
	cfg.Security.CVESource.Type = "trivy"
	cfg.Security.CVESource.Trivy.ServerURL = "https://trivy.internal:4954"
	src, _, err := buildCVESource(cfg)
	if err == nil {
		t.Fatal("expected a fail-closed error when a configured scan source cannot build")
	}
	if src != nil {
		t.Error("no source must be returned on a build failure")
	}
}
