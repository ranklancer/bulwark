package main

import (
	"testing"

	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

func resultWith(level types.RiskLevel, urgency *types.SecurityUrgency) scanner.Result {
	a := &types.RiskAssessment{Level: level}
	if urgency != nil {
		a.Security = &types.SecurityAssessment{Urgency: *urgency, ClosedCount: 1, CriticalClosed: 1}
	}
	return scanner.Result{Assessment: a}
}

func TestFilterUrgentSafe(t *testing.T) {
	urgent := types.UrgencyUrgent
	recommended := types.UrgencyRecommended
	results := []scanner.Result{
		resultWith(types.RiskSafe, &urgent),      // included
		resultWith(types.RiskSafe, &recommended), // excluded: not urgent
		resultWith(types.RiskSafe, nil),          // excluded: no security signal
		resultWith(types.RiskReview, &urgent),    // excluded: not safe
		resultWith(types.RiskBreaking, &urgent),  // excluded: not safe
	}
	got := filterUrgentSafe(results)
	if len(got) != 1 {
		t.Fatalf("filterUrgentSafe returned %d, want 1", len(got))
	}
	if got[0].Assessment.Level != types.RiskSafe || got[0].Assessment.Security.Urgency != types.UrgencyUrgent {
		t.Errorf("unexpected result kept: %+v", got[0].Assessment)
	}
	if len(filterUrgentSafe(nil)) != 0 {
		t.Error("nil input must yield no results")
	}
}
