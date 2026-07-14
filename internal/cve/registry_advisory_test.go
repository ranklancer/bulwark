package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Realistic osv-scanner shape: a GHSA advisory carries database_specific.severity
// (a textual band), while a pure-OSV advisory encodes severity as a CVSS *vector*
// string (not a numeric score) — which cannot be graded and lands as Unknown.
const osvSample = `{
  "results": [{
    "source": {"path": "nginx:1.27", "type": "image"},
    "packages": [{
      "package": {"name": "openssl", "ecosystem": "Debian"},
      "vulnerabilities": [
        {"id": "GHSA-xxxx", "aliases": ["CVE-2024-3000"], "summary": "openssl flaw",
         "database_specific": {"severity": "HIGH"}},
        {"id": "OSV-2024-1",
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
      ]
    }]
  }]
}`

func TestParseOSVResults(t *testing.T) {
	image, vulns, structured, err := ParseOSVResults([]byte(osvSample))
	if err != nil {
		t.Fatal(err)
	}
	if !structured || image != "nginx:1.27" {
		t.Fatalf("structured=%v image=%q", structured, image)
	}
	if len(vulns) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(vulns), vulns)
	}
	// prefers CVE alias; severity from database_specific band.
	if vulns[0].ID != "CVE-2024-3000" || vulns[0].Severity != SeverityHigh || vulns[0].PkgName != "openssl" {
		t.Fatalf("vuln0: %+v", vulns[0])
	}
	// osv-scanner encodes CVSS as a VECTOR string, not a numeric score -> the
	// severity cannot be graded and is Unknown (fails closed at the gate).
	if vulns[1].ID != "OSV-2024-1" || vulns[1].Severity != SeverityUnknown {
		t.Fatalf("CVSS-vector severity must be Unknown, got: %+v", vulns[1])
	}
}

func TestOSVDedupKeepsMaxSeverity(t *testing.T) {
	// same advisory across two packages: LOW then CRITICAL -> keep Critical.
	body := `{"results":[{"source":{"path":"img:1","type":"image"},"packages":[
	  {"package":{"name":"a"},"vulnerabilities":[{"id":"CVE-9","database_specific":{"severity":"LOW"}}]},
	  {"package":{"name":"b"},"vulnerabilities":[{"id":"CVE-9","database_specific":{"severity":"CRITICAL"}}]}
	]}]}`
	_, vulns, _, err := ParseOSVResults([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].Severity != SeverityCritical {
		t.Fatalf("dedup must keep MAX (critical): %+v", vulns)
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

func TestRegistryAdvisoryDirSource_CleanVsTruncated(t *testing.T) {
	// osv-scanner clean output is {"results":[]} (key present) -> a filename match
	// is a legitimate clean image. But {} (key absent) is truncated -> UNKNOWN.
	cleanDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cleanDir, "nginx_1.27.json"), []byte(`{"results":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := (RegistryAdvisoryDirSource{Dir: cleanDir}).Vulns(context.Background(), "nginx:1.27"); err != nil || len(v) != 0 {
		t.Fatalf("{\"results\":[]} is a clean scan, not unknown: %d %v", len(v), err)
	}
	truncDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(truncDir, "nginx_1.27.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (RegistryAdvisoryDirSource{Dir: truncDir}).Vulns(context.Background(), "nginx:1.27"); err == nil {
		t.Fatal("{} (no results key) is truncated -> must be UNKNOWN (error)")
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
		_, _, _, _ = ParseOSVResults(data) // must not panic
	})
}
