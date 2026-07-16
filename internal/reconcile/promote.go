package reconcile

import "github.com/ranklancer/bulwark/internal/store"

// PromotionDecision is the outcome of evaluating whether a canary candidate
// should be promoted, held, or rolled back (the trust engine Phase 3).
type PromotionDecision string

const (
	// PromotePromote: the canary is healthy for the required cycles and still
	// passes the trust gate — promote it.
	PromotePromote PromotionDecision = "promote"
	// PromoteHold: not enough healthy cycles yet — keep observing.
	PromoteHold PromotionDecision = "hold"
	// PromoteRollback: the canary is unhealthy or trust regressed — roll back.
	PromoteRollback PromotionDecision = "rollback"
)

// PromotionInput is the observed state for one promotion evaluation.
type PromotionInput struct {
	State          string // current canary state (only CanaryActive is evaluable)
	HealthyCycles  int    // consecutive health-stable cycles observed so far
	RequiredCycles int    // cycles required before promotion (<1 is treated as 1)
	Unhealthy      bool   // the canary is currently failing its health check
	GateAllowed    bool   // a re-evaluated trust verdict still allows the pinned image
}

// EvaluatePromotion is the pure decision for the canary promotion loop. It is
// fail-safe: an unhealthy canary or a regressed trust verdict rolls back; only a
// canary healthy for the required cycles AND still trusted promotes. Anything
// that is not an active canary holds (the loop only acts on active canaries).
func EvaluatePromotion(in PromotionInput) PromotionDecision {
	if in.State != store.CanaryActive {
		return PromoteHold
	}
	if in.Unhealthy {
		return PromoteRollback
	}
	if !in.GateAllowed {
		return PromoteRollback
	}
	req := in.RequiredCycles
	if req < 1 {
		req = 1
	}
	if in.HealthyCycles >= req {
		return PromotePromote
	}
	return PromoteHold
}
