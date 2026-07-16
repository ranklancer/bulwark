package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConfigLoad fuzzes the YAML config loader with arbitrary bytes written to a
// file (config files are operator-controlled but may be malformed / hostile).
// Contract: Load must never panic — it returns a *Config or an error.
func FuzzConfigLoad(f *testing.F) {
	f.Add([]byte("classification:\n  default_risk: review\n"))
	f.Add([]byte("verify:\n  enabled: true\n  provenance:\n    mode: block\n"))
	f.Add([]byte("security:\n  enabled: true\n  cve_source:\n    type: trivy\n    trivy:\n      report_dir: /r\n"))
	f.Add([]byte("{}"))
	f.Add([]byte(":\n:\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "bulwark.yaml")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		_, _ = Load(p)
	})
}
