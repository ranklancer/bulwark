package api

import (
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/pkg/types"
)

// TestBuildAPIQueueRows_IncludesSecurity proves the queue DTO surfaces the
// security-urgency verdict so the dashboard can render a badge + CVE breakdown.
func TestBuildAPIQueueRows_IncludesSecurity(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := st.RecordScan(store.ScanRecord{
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Results: []store.ScanResultRecord{{
			ContainerName:   "sonarr",
			Image:           "img:1",
			RegistryDigest:  "sha256:new",
			UpdateAvailable: true,
			Level:           types.RiskSafe,
			Security: &types.SecurityAssessment{
				Urgency:         types.UrgencyUrgent,
				ClosedCount:     1,
				CriticalClosed:  1,
				HighestSeverity: "critical",
			},
		}},
	}); err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	rows, err := buildAPIQueueRows(st)
	if err != nil {
		t.Fatalf("buildAPIQueueRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 queue row, got %d", len(rows))
	}
	if rows[0].Security == nil || rows[0].Security.Urgency != types.UrgencyUrgent {
		t.Fatalf("queue row missing security urgency: %+v", rows[0])
	}
}
