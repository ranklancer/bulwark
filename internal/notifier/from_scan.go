package notifier

import (
	"time"

	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// EventsFromScan converts scan results into notification events. Skipped
// containers and errors do not produce events; only entries with an actual
// pending update are notification-worthy.
//
// The current Action is always ActionNeedsReview / ActionBlocked / nothing —
// scan is read-only, so it never emits AutoUpdated or RolledBack. Those will
// come from the daemon's update orchestrator in a later phase.
func EventsFromScan(results []scanner.Result, ts time.Time) []Event {
	out := make([]Event, 0)
	for _, r := range results {
		if r.Skipped || r.Err != nil || !r.HasUpdate() || r.Assessment == nil {
			continue
		}
		out = append(out, Event{
			Container:      r.Container.Name,
			ContainerID:    r.Container.ID,
			Image:          r.Container.Image,
			ComposeProject: r.Container.ComposeProject(),
			Risk:           r.Assessment.Level,
			Action:         actionFromRisk(r.Assessment.Level),
			From:           r.Assessment.Delta.From,
			To:             r.Assessment.Delta.To,
			Kind:           r.Assessment.Delta.Kind,
			Confidence:     r.Assessment.Confidence,
			Rationale:      r.Assessment.Rationale,
			ReleaseURL:     r.Assessment.ReleaseURL,
			Changelog:      r.Assessment.Changelog,
			NotesSource:    r.NotesSource,
			LocalDigest:    r.LocalDigest,
			RegistryDigest: r.RegistryDigest,
			Timestamp:      ts,
			Security:       r.Assessment.Security,
		})
	}
	return out
}

func actionFromRisk(r types.RiskLevel) types.UpdateAction {
	switch r {
	case types.RiskBreaking:
		return types.ActionBlocked
	case types.RiskReview:
		return types.ActionNeedsReview
	default:
		// SAFE updates from `scan` are still pending — scan doesn't apply
		// updates, so even SAFE shows up as "needs review" until the daemon
		// is wired in.
		return types.ActionNeedsReview
	}
}
