package cve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/pkg/types"
)

func TestSeverityOrderingAndParse(t *testing.T) {
	if !(SeverityCritical > SeverityHigh && SeverityHigh > SeverityMedium &&
		SeverityMedium > SeverityLow && SeverityLow > SeverityUnknown) {
		t.Fatal("severity ordering is wrong")
	}
	if ParseSeverity("critical") != SeverityCritical ||
		ParseSeverity(" HIGH ") != SeverityHigh ||
		ParseSeverity("nonsense") != SeverityUnknown {
		t.Fatal("ParseSeverity mismatch")
	}
}

const trivyCurrent = `{
  "ArtifactName": "ghcr.io/owner/app:1.2.3",
  "Metadata": {"RepoDigests": ["ghcr.io/owner/app@sha256:cur"]},
  "Results": [
    {"Target":"app","Vulnerabilities":[
      {"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","Severity":"CRITICAL","Title":"RCE"},
      {"VulnerabilityID":"CVE-2024-0002","PkgName":"zlib","Severity":"HIGH","Title":"overflow"},
      {"VulnerabilityID":"CVE-2024-0003","PkgName":"curl","Severity":"LOW","Title":"info"}
    ]}
  ]
}`

const trivyCandidate = `{
  "ArtifactName": "ghcr.io/owner/app:1.2.4",
  "Metadata": {"RepoDigests": ["ghcr.io/owner/app@sha256:cand"]},
  "Results": [
    {"Target":"app","Vulnerabilities":[
      {"VulnerabilityID":"CVE-2024-0002","PkgName":"zlib","Severity":"HIGH","Title":"overflow"}
    ]}
  ]
}`

func TestParseTrivyReport(t *testing.T) {
	art, vulns, err := ParseTrivyReport([]byte(trivyCurrent))
	if err != nil {
		t.Fatal(err)
	}
	if art != "ghcr.io/owner/app:1.2.3" {
		t.Errorf("artifact = %q", art)
	}
	if len(vulns) != 3 {
		t.Fatalf("got %d vulns, want 3", len(vulns))
	}
}

func TestTrivyDirSource_MatchesByDigest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cur.json"), []byte(trivyCurrent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cand.json"), []byte(trivyCandidate), 0o600); err != nil {
		t.Fatal(err)
	}
	src := TrivyDirSource{Dir: dir}
	ctx := context.Background()

	cur, err := src.Vulns(ctx, "ghcr.io/owner/app:1.2.3@sha256:cur")
	if err != nil || len(cur) != 3 {
		t.Fatalf("current digest: got %d vulns err=%v, want 3", len(cur), err)
	}
	cand, err := src.Vulns(ctx, "ghcr.io/owner/app:1.2.3@sha256:cand")
	if err != nil || len(cand) != 1 {
		t.Fatalf("candidate digest: got %d vulns err=%v, want 1", len(cand), err)
	}
	none, err := src.Vulns(ctx, "ghcr.io/owner/app:1.2.3@sha256:nope")
	if err != nil || none != nil {
		t.Errorf("unknown digest: want (nil,nil), got (%v,%v)", none, err)
	}
}

func TestAssessUpgrade_Urgency(t *testing.T) {
	cur := []Vuln{
		{ID: "C1", Severity: SeverityCritical},
		{ID: "H1", Severity: SeverityHigh},
		{ID: "L1", Severity: SeverityLow},
	}
	// candidate keeps the critical, closes the high+low
	keepCrit := []Vuln{{ID: "C1", Severity: SeverityCritical}}
	// candidate closes the critical, keeps the high
	closeCrit := []Vuln{{ID: "H1", Severity: SeverityHigh}}

	if sa := AssessUpgrade(cur, closeCrit, SeverityCritical); sa.Urgency != types.UrgencyUrgent || sa.CriticalClosed != 1 || sa.ClosedCount != 1 {
		t.Errorf("closeCrit@critical: %+v, want urgent/1crit/1", sa)
	}
	if sa := AssessUpgrade(cur, keepCrit, SeverityHigh); sa.Urgency != types.UrgencyRecommended || sa.HighClosed != 1 {
		t.Errorf("keepCrit@high: %+v, want recommended/1high", sa)
	}
	// threshold critical filters out the HIGH-only closure entirely
	if sa := AssessUpgrade(cur, keepCrit, SeverityCritical); sa.Urgency != types.UrgencyNone || sa.ClosedCount != 0 {
		t.Errorf("keepCrit@critical: %+v, want none/0", sa)
	}
}

func TestSecurityAssessmentSummary(t *testing.T) {
	sa := AssessUpgrade(
		[]Vuln{{ID: "C1", Severity: SeverityCritical}, {ID: "H1", Severity: SeverityHigh}},
		nil, SeverityHigh)
	sa.Source = "trivy"
	got := sa.Summary()
	if !strings.Contains(got, "security-urgent") || !strings.Contains(got, "1 CRITICAL") || !strings.Contains(got, "1 HIGH") || !strings.Contains(got, "trivy") {
		t.Errorf("summary = %q", got)
	}
	empty := (&types.SecurityAssessment{}).Summary()
	if empty != "" {
		t.Errorf("empty summary = %q, want \"\"", empty)
	}
}
