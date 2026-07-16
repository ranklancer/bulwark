package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecureDefaultFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bulwark.yaml")
	doc := `
classification:
  default_risk: review
docker:
  host: tcp://socket-proxy:2375
api:
  auth:
    type: none
    allow_anonymous: true
snapshots:
  backend: none
  allow_apply_without_backend: true
`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Docker.Host != "tcp://socket-proxy:2375" {
		t.Errorf("docker.host = %q, want tcp://socket-proxy:2375", c.Docker.Host)
	}
	if !c.API.Auth.AllowAnonymous {
		t.Error("api.auth.allow_anonymous should parse to true")
	}
	if !c.Snapshots.AllowApplyWithoutBackend {
		t.Error("snapshots.allow_apply_without_backend should parse to true")
	}
}
