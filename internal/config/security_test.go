package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadDoc(t *testing.T, doc string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bulwark.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadSecurityBlock(t *testing.T) {
	c, err := loadDoc(t, `
classification:
  default_risk: review
security:
  enabled: true
  severity_threshold: high
  auto_apply_urgent_safe: true
  cve_source:
    type: trivy
    trivy:
      report_dir: /var/reports
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Security.Enabled || c.Security.SeverityThreshold != "high" || !c.Security.AutoApplyUrgentSafe {
		t.Errorf("security block parsed wrong: %+v", c.Security)
	}
	if c.Security.CVESource.Type != "trivy" || c.Security.CVESource.Trivy.ReportDir != "/var/reports" {
		t.Errorf("cve_source parsed wrong: %+v", c.Security.CVESource)
	}
}

func TestValidateSecurity_Rejects(t *testing.T) {
	// enabled trivy but no report_dir/server_url
	if _, err := loadDoc(t, "classification:\n  default_risk: review\nsecurity:\n  enabled: true\n  cve_source:\n    type: trivy\n"); err == nil {
		t.Error("expected error: trivy enabled without report_dir")
	}
	// bad threshold
	if _, err := loadDoc(t, "classification:\n  default_risk: review\nsecurity:\n  enabled: true\n  severity_threshold: bogus\n  cve_source:\n    type: trivy\n    trivy:\n      report_dir: /x\n"); err == nil {
		t.Error("expected error: bad severity_threshold")
	}
	// unknown source type
	if _, err := loadDoc(t, "classification:\n  default_risk: review\nsecurity:\n  enabled: true\n  cve_source:\n    type: grype\n"); err == nil {
		t.Error("expected error: unsupported cve_source.type")
	}
	// disabled => no validation, no error even if empty
	if _, err := loadDoc(t, "classification:\n  default_risk: review\nsecurity:\n  enabled: false\n"); err != nil {
		t.Errorf("disabled security must not error: %v", err)
	}
}
