package main

import (
	"testing"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/cve"
)

func TestBuildCVESource(t *testing.T) {
	if src, _ := buildCVESource(nil); src != nil {
		t.Error("nil config must yield nil source")
	}
	if src, _ := buildCVESource(&config.Config{}); src != nil {
		t.Error("disabled security must yield nil source")
	}
	cfg := &config.Config{}
	cfg.Security.Enabled = true
	cfg.Security.SeverityThreshold = "high"
	cfg.Security.CVESource.Type = "trivy"
	cfg.Security.CVESource.Trivy.ReportDir = "/var/reports"
	src, th := buildCVESource(cfg)
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
	if src, _ := buildCVESource(cfg); src != nil {
		t.Error("trivy without report_dir must yield nil source")
	}
}
