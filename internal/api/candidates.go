package api

import (
	"net/http"
	"sort"

	"github.com/ranklancer/bulwark/internal/store"
)

// candidateView is the dashboard projection of an in-flight the trust engine pin: a captured,
// gated update awaiting (or undergoing) canary promotion. It carries no secrets.
type candidateView struct {
	Key         string `json:"key"`
	Ref         string `json:"ref"`
	IndexDigest string `json:"index_digest"`
	CanaryState string `json:"canary_state"`
	Service     string `json:"service,omitempty"`
	ComposePath string `json:"compose_path,omitempty"`
	CapturedAt  string `json:"captured_at,omitempty"`
}

// listCandidates surfaces pins in a candidate or canary state (the trust engine items a
// verified update produced), sorted by key for stable rendering. Promoted and
// rolled-back terminal states are omitted — the dashboard shows only in-flight
// work awaiting an operator's promotion decision.
func (h *StateHandler) listCandidates(w http.ResponseWriter, _ *http.Request) {
	pins, err := h.Pins.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	out := []candidateView{}
	for key, p := range pins {
		state := p.CanaryState
		if state == "" {
			state = store.CanaryCandidate
		}
		if state != store.CanaryCandidate && state != store.CanaryActive {
			continue
		}
		out = append(out, candidateView{
			Key:         key,
			Ref:         p.Ref,
			IndexDigest: p.IndexDigest,
			CanaryState: state,
			Service:     p.Service,
			ComposePath: p.ComposePath,
			CapturedAt:  p.CapturedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	writeJSON(w, http.StatusOK, out)
}
