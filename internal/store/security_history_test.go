package store

import (
	"testing"
	"time"

	"github.com/ranklancer/bulwark/pkg/types"
)

// TestScanRecord_PersistsSecurityAssessment proves the security-urgency verdict
// survives a store round-trip so the API/dashboard can read it back.
func TestScanRecord_PersistsSecurityAssessment(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sec := &types.SecurityAssessment{
		Urgency:         types.UrgencyUrgent,
		ClosedCount:     2,
		CriticalClosed:  1,
		HighClosed:      1,
		HighestSeverity: "critical",
		Source:          "trivy",
		Closed: []types.ClosedVuln{
			{ID: "CVE-2026-0001", Severity: "critical", PkgName: "openssl"},
		},
	}
	rec := ScanRecord{
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Results: []ScanResultRecord{{
			ContainerName:   "sonarr",
			Image:           "img:1",
			UpdateAvailable: true,
			Level:           types.RiskSafe,
			Security:        sec,
		}},
	}
	saved, err := st.RecordScan(rec)
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	got, err := st.GetScan(saved.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if len(got.Results) != 1 || got.Results[0].Security == nil {
		t.Fatalf("Security not persisted: %+v", got.Results)
	}
	g := got.Results[0].Security
	if g.Urgency != types.UrgencyUrgent || g.ClosedCount != 2 || len(g.Closed) != 1 || g.Closed[0].ID != "CVE-2026-0001" {
		t.Fatalf("Security round-trip mismatch: %+v", g)
	}
}
