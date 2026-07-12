package config

import (
	"strings"
	"testing"
)

// item 4: the provenance block->warn degrade must surface as a startup advisory.
func TestVerifyWarnings_ProvenanceBlockEmptyBuilder(t *testing.T) {
	c := &Config{}
	c.Verify.Enabled = true
	c.Verify.Provenance.Mode = "block" // empty builder_id => degrade => warning
	w := c.VerifyWarnings()
	if len(w) != 1 || !strings.Contains(w[0], "degraded to warn") {
		t.Fatalf("warnings = %v, want the block->warn degrade advisory", w)
	}
	c.Verify.Provenance.BuilderID = "^https://github.com/acme/.+$"
	if got := c.VerifyWarnings(); len(got) != 0 {
		t.Fatalf("expected no warnings once builder_id is set, got %v", got)
	}
	c.Verify.Enabled = false
	if got := (&Config{}).VerifyWarnings(); got != nil {
		t.Fatalf("disabled verify should yield no warnings, got %v", got)
	}
}

// item 3a: a server_url with no report_dir must be rejected until server mode ships.
func TestValidateSecurity_RejectsServerURLOnly(t *testing.T) {
	c := &Config{}
	c.Security.Enabled = true
	c.Security.CVESource.Type = "trivy"
	c.Security.CVESource.Trivy.ServerURL = "http://scanner:4954" // no report_dir
	if err := c.validateSecurity(); err == nil {
		t.Fatal("expected rejection: server mode not implemented; report_dir required")
	}
	c.Security.CVESource.Trivy.ReportDir = "/reports"
	if err := c.validateSecurity(); err != nil {
		t.Fatalf("report_dir should validate: %v", err)
	}
}
