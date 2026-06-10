package notifier

import (
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestTitleFor_SecurityPrefix(t *testing.T) {
	urgent := Event{Container: "app", Risk: types.RiskReview, Action: types.ActionNeedsReview,
		Security: &types.SecurityAssessment{Urgency: types.UrgencyUrgent, ClosedCount: 1, CriticalClosed: 1}}
	if got := titleFor(urgent); !strings.HasPrefix(got, "[SECURITY] ") {
		t.Errorf("titleFor = %q, want [SECURITY] prefix", got)
	}
	rec := Event{Container: "app", Risk: types.RiskSafe, Action: types.ActionNeedsReview,
		Security: &types.SecurityAssessment{Urgency: types.UrgencyRecommended, ClosedCount: 1, HighClosed: 1}}
	if got := titleFor(rec); strings.HasPrefix(got, "[SECURITY] ") {
		t.Errorf("recommended must not get [SECURITY] prefix: %q", got)
	}
	none := Event{Container: "app", Risk: types.RiskSafe, Action: types.ActionNeedsReview}
	if got := titleFor(none); strings.HasPrefix(got, "[SECURITY] ") {
		t.Errorf("no security must not get prefix: %q", got)
	}
}

func TestEvent_SecurityLine(t *testing.T) {
	e := Event{Security: &types.SecurityAssessment{Urgency: types.UrgencyUrgent, ClosedCount: 2, CriticalClosed: 2, Source: "trivy"}}
	got := e.SecurityLine()
	if !strings.HasPrefix(got, "security-urgent") || !strings.Contains(got, "2 CRITICAL") {
		t.Errorf("SecurityLine = %q", got)
	}
	if (Event{}).SecurityLine() != "" {
		t.Error("event without security must yield empty SecurityLine")
	}
}

func TestEventsFromScan_CarriesSecurity(t *testing.T) {
	sec := &types.SecurityAssessment{Urgency: types.UrgencyUrgent, ClosedCount: 1, CriticalClosed: 1}
	r := scanner.Result{
		LocalDigest:    "sha256:a",
		RegistryDigest: "sha256:b",
		Assessment:     &types.RiskAssessment{Level: types.RiskSafe, Security: sec},
	}
	evs := EventsFromScan([]scanner.Result{r}, time.Now())
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if evs[0].Security != sec {
		t.Error("Security assessment not carried into the notification event")
	}
}
