package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ranklancer/bulwark/pkg/types"
)

const grypeCurrent = `{
  "matches": [
    {"vulnerability": {"id": "CVE-2024-0001", "severity": "Critical"}, "artifact": {"name": "openssl"}},
    {"vulnerability": {"id": "CVE-2024-0002", "severity": "High"}, "artifact": {"name": "zlib"}}
  ],
  "source": {"target": {"userInput": "ghcr.io/owner/app:1.2.3", "repoDigests": ["ghcr.io/owner/app@sha256:cur"]}}
}`

const grypeCandidate = `{
  "matches": [
    {"vulnerability": {"id": "CVE-2024-0002", "severity": "High"}, "artifact": {"name": "zlib"}}
  ],
  "source": {"target": {"userInput": "ghcr.io/owner/app:1.2.4", "repoDigests": ["ghcr.io/owner/app@sha256:cand"]}}
}`

func TestParseGrypeReport(t *testing.T) {
	art, vulns, err := ParseGrypeReport([]byte(grypeCurrent))
	if err != nil {
		t.Fatal(err)
	}
	if art != "ghcr.io/owner/app:1.2.3" {
		t.Errorf("artifact = %q", art)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2", len(vulns))
	}
}

func TestGrypeDirSource_AndUrgencyDiff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cur.json"), []byte(grypeCurrent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cand.json"), []byte(grypeCandidate), 0o600); err != nil {
		t.Fatal(err)
	}
	src := GrypeDirSource{Dir: dir}
	ctx := context.Background()
	cur, err := src.Vulns(ctx, "ghcr.io/owner/app:1.2.3@sha256:cur")
	if err != nil || len(cur) != 2 {
		t.Fatalf("current: got %d err=%v, want 2", len(cur), err)
	}
	cand, err := src.Vulns(ctx, "ghcr.io/owner/app:1.2.3@sha256:cand")
	if err != nil || len(cand) != 1 {
		t.Fatalf("candidate: got %d err=%v, want 1", len(cand), err)
	}
	sa := AssessUpgrade(cur, cand, SeverityCritical)
	if sa.Urgency != types.UrgencyUrgent || sa.CriticalClosed != 1 {
		t.Errorf("AssessUpgrade via grype = %+v, want urgent/1crit", sa)
	}
}
