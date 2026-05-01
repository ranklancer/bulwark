package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestLoad_Defaults_NoPath(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path: %v", err)
	}
	if c.Classification.Policies.Patch != "safe" {
		t.Errorf("default policies.patch = %q, want safe", c.Classification.Policies.Patch)
	}
	if c.Classification.DefaultRisk != "review" {
		t.Errorf("default risk = %q, want review", c.Classification.DefaultRisk)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bulwark.yaml")
	contents := `
docker:
  host: unix:///var/run/docker.sock

classification:
  default_risk: review
  policies:
    patch: safe
    minor: review
    major: breaking
  breaking_keywords:
    - custom-breaking-token

overrides:
  stacks:
    critical-stack:
      risk_override: breaking
  containers:
    "*-db":
      risk_override: review
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Overrides.Stacks["critical-stack"].RiskOverride; got != "breaking" {
		t.Errorf("override risk = %q, want breaking", got)
	}
	if !contains(c.Classification.BreakingKeywords, "custom-breaking-token") {
		t.Errorf("custom keyword missing from %v", c.Classification.BreakingKeywords)
	}
}

func TestLoad_EnvVarSubstitution(t *testing.T) {
	t.Setenv("BULWARK_TEST_TOKEN", "secret-value")
	dir := t.TempDir()
	path := filepath.Join(dir, "bulwark.yaml")
	contents := `
notifications:
  homeassistant:
    enabled: true
    url: http://hass.example.com:8123
    token: ${BULWARK_TEST_TOKEN}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Notifications.HomeAssistant.Token != "secret-value" {
		t.Errorf("env var not expanded; got %q", c.Notifications.HomeAssistant.Token)
	}
}

func TestLoad_EnvVarUnset_LeavesPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bulwark.yaml")
	contents := `
notifications:
  homeassistant:
    token: ${BULWARK_DEFINITELY_UNSET}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Notifications.HomeAssistant.Token != "${BULWARK_DEFINITELY_UNSET}" {
		t.Errorf("unset env var should be left as-is; got %q", c.Notifications.HomeAssistant.Token)
	}
}

func TestValidate_RejectsBadRiskLevel(t *testing.T) {
	c := Defaults()
	c.Classification.DefaultRisk = "panic-mode"
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation error for invalid risk level")
	}
}

func TestValidate_RejectsBadSnapshotBackend(t *testing.T) {
	c := Defaults()
	c.Snapshots.Backend = "magic"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "snapshots.backend") {
		t.Fatalf("expected snapshot backend error, got: %v", err)
	}
}

func TestClassifierConfig_AppliesPolicyOverrides(t *testing.T) {
	c := Defaults()
	c.Classification.Policies.Minor = "safe" // unusual: trust minor bumps
	cc := c.ClassifierConfig()
	if cc.Policy.Minor != types.RiskSafe {
		t.Errorf("classifier minor = %v, want RiskSafe", cc.Policy.Minor)
	}
	// Defaults preserved when not specified.
	if cc.Policy.Major != types.RiskBreaking {
		t.Errorf("classifier major = %v, want RiskBreaking (default)", cc.Policy.Major)
	}
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
