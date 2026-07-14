package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const osvSample = `{
  "results": [{
    "source": {"path": "nginx:1.27", "type": "image"},
    "packages": [{
      "package": {"name": "openssl", "ecosystem": "Debian"},
      "vulnerabilities": [
        {"id": "GHSA-xxxx", "aliases": ["CVE-2024-3000"], "summary": "openssl flaw",
         "database_specific": {"severity": "HIGH"}},
        {"id": "OSV-2024-1", "severity": [{"type": "CVSS_V3", "score": "9.1"}]}
      ]
    }]
  }]
}`

func TestParseOSVResults(t *testing.T) {
	image, vulns, err := ParseOSVResults([]byte(osvSample))
	if err != nil {
		t.Fatal(err)
	}
	if image != "nginx:1.27" {
		t.Fatalf("image: %q", image)
	}
	if len(vulns) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(vulns), vulns)
	}
	// prefers CVE alias over GHSA id; severity from database_specific
	if vulns[0].ID != "CVE-2024-3000" || vulns[0].Severity != SeverityHigh || vulns[0].PkgName != "openssl" {
		t.Fatalf("vuln0: %+v", vulns[0])
	}
	// numeric CVSS score 9.1 -> critical; falls back to OSV id
	if vulns[1].ID != "OSV-2024-1" || vulns[1].Severity != SeverityCritical {
		t.Fatalf("vuln1: %+v", vulns[1])
	}
}

func TestRegistryAdvisoryDirSource_Match(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "osv.json"), []byte(osvSample), 0o644); err != nil {
		t.Fatal(err)
	}
	src := RegistryAdvisoryDirSource{Dir: dir}
	v, err := src.Vulns(context.Background(), "nginx:1.27")
	if err != nil || len(v) != 2 {
		t.Fatalf("match: %d %v", len(v), err)
	}
	v, err = src.Vulns(context.Background(), "other:1")
	if err != nil || len(v) != 0 {
		t.Fatalf("non-match: %d %v", len(v), err)
	}
}

func TestRegistryAdvisoryDirSource_EmptyDir(t *testing.T) {
	if _, err := (RegistryAdvisoryDirSource{}).Vulns(context.Background(), "x"); err == nil {
		t.Fatal("empty dir must error")
	}
}

func FuzzParseOSVResults(f *testing.F) {
	f.Add([]byte(osvSample))
	f.Add([]byte(`{"results":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseOSVResults(data) // must not panic
	})
}
