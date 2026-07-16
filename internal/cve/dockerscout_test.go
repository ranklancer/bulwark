package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const scoutSARIFSample = `{
  "runs": [{
    "tool": {"driver": {"rules": [
      {"id": "CVE-2023-1111", "shortDescription": {"text": "bad thing"},
       "properties": {"cvssV3_severity": "critical"}},
      {"id": "CVE-2023-2222", "properties": {"security-severity": "7.5"}},
      {"id": "CVE-2023-1111", "properties": {"cvssV3_severity": "critical"}}
    ]}},
    "automationDetails": {"id": "nginx@sha256:abc"},
    "properties": {"imageName": "nginx:1.27"}
  }]
}`

func TestParseDockerScoutSARIF(t *testing.T) {
	image, vulns, structured, err := ParseDockerScoutSARIF([]byte(scoutSARIFSample))
	if err != nil {
		t.Fatal(err)
	}
	if !structured {
		t.Fatal("a report with runs must be structured")
	}
	if image != "nginx:1.27" {
		t.Fatalf("image: got %q", image)
	}
	if len(vulns) != 2 {
		t.Fatalf("want 2 deduped vulns, got %d: %+v", len(vulns), vulns)
	}
	if vulns[0].ID != "CVE-2023-1111" || vulns[0].Severity != SeverityCritical {
		t.Fatalf("vuln0: %+v", vulns[0])
	}
	if vulns[1].Severity != SeverityHigh { // 7.5 -> high
		t.Fatalf("score->severity wrong: %+v", vulns[1])
	}
}

func TestScoutDedupKeepsMaxSeverity(t *testing.T) {
	// same CVE appears LOW first then CRITICAL (multi-arch runs / repeated rule):
	// the deduped severity MUST be Critical, never the earlier Low.
	body := `{"runs":[{"tool":{"driver":{"rules":[
	  {"id":"CVE-2024-1","properties":{"cvssV3_severity":"low"}},
	  {"id":"CVE-2024-1","properties":{"cvssV3_severity":"critical"}}
	]}}}]}`
	_, vulns, _, err := ParseDockerScoutSARIF([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].Severity != SeverityCritical {
		t.Fatalf("dedup must keep MAX (critical): %+v", vulns)
	}
}

func TestDockerScoutDirSource_Match(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.sarif.json"), []byte(scoutSARIFSample), 0o644); err != nil {
		t.Fatal(err)
	}
	src := DockerScoutDirSource{Dir: dir}
	v, err := src.Vulns(context.Background(), "nginx:1.27")
	if err != nil || len(v) != 2 {
		t.Fatalf("content match: %d %v", len(v), err)
	}
	v, err = src.Vulns(context.Background(), "redis:7")
	if err != nil || len(v) != 0 {
		t.Fatalf("non-match should be empty: %d %v", len(v), err)
	}
}

func TestDockerScoutDirSource_FilenameFallback(t *testing.T) {
	dir := t.TempDir()
	body := `{"runs":[{"tool":{"driver":{"rules":[{"id":"CVE-2024-9","properties":{"cvssV3_severity":"high"}}]}}}]}`
	if err := os.WriteFile(filepath.Join(dir, "nginx_1.27.sarif.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := DockerScoutDirSource{Dir: dir}.Vulns(context.Background(), "nginx:1.27")
	if err != nil || len(v) != 1 {
		t.Fatalf("filename fallback: %d %v", len(v), err)
	}
}

func TestDockerScoutDirSource_EmptyReportIsUnknown(t *testing.T) {
	// A truncated report ({} or {"runs":[]}) matched by filename must be UNKNOWN
	// (error -> gate fails closed), never read as a clean image.
	for _, body := range []string{`{}`, `{"runs":[]}`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "nginx_1.27.sarif.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		v, err := DockerScoutDirSource{Dir: dir}.Vulns(context.Background(), "nginx:1.27")
		if err == nil {
			t.Fatalf("structurally-empty report %q must return an error (unknown), got clean %v", body, v)
		}
	}
}

func TestDockerScoutDirSource_EmptyDir(t *testing.T) {
	if _, err := (DockerScoutDirSource{}).Vulns(context.Background(), "x"); err == nil {
		t.Fatal("empty dir must error")
	}
}

func FuzzParseDockerScoutSARIF(f *testing.F) {
	f.Add([]byte(scoutSARIFSample))
	f.Add([]byte(`{"runs":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = ParseDockerScoutSARIF(data) // must not panic
	})
}
