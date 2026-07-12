package reconcile

import (
	"testing"

	"github.com/bulwark-docker/bulwark/internal/store"
)

func TestEvaluatePromotion(t *testing.T) {
	cases := []struct {
		name string
		in   PromotionInput
		want PromotionDecision
	}{
		{"healthy enough + trusted promotes", PromotionInput{State: store.CanaryActive, HealthyCycles: 3, RequiredCycles: 3, GateAllowed: true}, PromotePromote},
		{"not enough cycles holds", PromotionInput{State: store.CanaryActive, HealthyCycles: 1, RequiredCycles: 3, GateAllowed: true}, PromoteHold},
		{"unhealthy rolls back", PromotionInput{State: store.CanaryActive, HealthyCycles: 5, RequiredCycles: 3, Unhealthy: true, GateAllowed: true}, PromoteRollback},
		{"trust regressed rolls back", PromotionInput{State: store.CanaryActive, HealthyCycles: 5, RequiredCycles: 3, GateAllowed: false}, PromoteRollback},
		{"non-active canary holds", PromotionInput{State: store.CanaryCandidate, HealthyCycles: 9, RequiredCycles: 1, GateAllowed: true}, PromoteHold},
		{"required<1 defaults to 1", PromotionInput{State: store.CanaryActive, HealthyCycles: 1, RequiredCycles: 0, GateAllowed: true}, PromotePromote},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EvaluatePromotion(c.in); got != c.want {
				t.Fatalf("EvaluatePromotion(%+v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
