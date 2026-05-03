package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/updater"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// applyOutcome records the result of a single auto-apply attempt. It's
// keyed by container name in applyEligibleUpdates' returned map.
type applyOutcome struct {
	Success     bool
	RolledBack  bool
	Err         error
	NewImage    string
	OldImage    string
}

// applyEligibleUpdates walks scan results and runs the updater for those
// that qualify for auto-apply.
//
// Eligibility rules (conservative — opt-in, never aggressive):
//   - The result must have a pending update.
//   - SAFE updates auto-apply automatically.
//   - REVIEW updates auto-apply when the user has recorded an explicit
//     "approve" decision.
//   - BREAKING updates *never* auto-apply, even when approved. The whole
//     point of the BREAKING tier is "manual intervention required".
//
// Returns a map keyed by container name. Containers without an outcome key
// were not considered eligible.
func applyEligibleUpdates(ctx context.Context, results []scanner.Result, u *updater.Updater, st *store.Store, logger *slog.Logger) map[string]applyOutcome {
	if u == nil {
		return nil
	}
	out := make(map[string]applyOutcome, 0)

	for _, r := range results {
		if r.Skipped || r.Err != nil || !r.HasUpdate() || r.Assessment == nil {
			continue
		}
		if !eligibleForApply(r, st) {
			continue
		}
		opts := updater.ApplyOptions{}
		// The bulwark.snapshot.dataset label tells us which filesystem
		// path/dataset to snapshot. Without a label the snapshot step is
		// skipped — only container-level rollback applies.
		if ds := r.Container.Labels["bulwark.snapshot.dataset"]; ds != "" {
			opts.SnapshotTarget = ds
			opts.SnapshotLabel = r.Container.Name
		}
		// Pre/post/rollback hook paths from the container's labels.
		// Empty paths disable the corresponding hook.
		opts.PreUpdateHook = r.Container.Labels["bulwark.hook.pre-update"]
		opts.PostUpdateHook = r.Container.Labels["bulwark.hook.post-update"]
		opts.RollbackHook = r.Container.Labels["bulwark.hook.rollback"]
		logger.Info("apply: starting", "container", r.Container.Name, "image", r.Container.Image, "level", r.Assessment.Level.String(), "snapshot_target", opts.SnapshotTarget)
		res := u.ApplyWithOptions(ctx, r.Container.ID, r.Reference.String(), opts)
		oc := applyOutcome{
			NewImage:   res.NewImage,
			OldImage:   res.OldImage,
			Success:    res.Err == nil && !res.RolledBack,
			RolledBack: res.RolledBack,
			Err:        res.Err,
		}
		ev := store.AuditEvent{
			Container: r.Container.Name,
			Image:     r.Container.Image,
			Level:     r.Assessment.Level,
			Digest:    r.RegistryDigest,
		}
		switch {
		case oc.Success:
			ev.Action = store.ActionApplied
			ev.Detail = fmt.Sprintf("%s → %s", res.OldImage, res.NewImage)
			logger.Info("apply: success", "container", r.Container.Name, "new_id", res.NewContainerID)
		case oc.RolledBack:
			ev.Action = store.ActionRolledBack
			if res.Err != nil {
				ev.Detail = res.Err.Error()
			}
			logger.Warn("apply: rolled back", "container", r.Container.Name, "err", res.Err)
		default:
			ev.Action = store.ActionAppliedFailed
			if res.Err != nil {
				ev.Detail = res.Err.Error()
			}
			logger.Error("apply: failed", "container", r.Container.Name, "err", res.Err)
		}
		st.Audit(ev)
		out[r.Container.Name] = oc
	}
	return out
}

// applyEligibleDryRun mirrors applyEligibleUpdates but never invokes the
// updater. It returns a synthetic Success outcome for every eligible
// container so the cycle's notification rendering reflects "would be
// applied" without making any system mutation. Audit log records each
// dry-run as `apply.success` with a `dry-run` Detail tag so operators
// can grep for what would have happened.
func applyEligibleDryRun(results []scanner.Result, st *store.Store, logger *slog.Logger) map[string]applyOutcome {
	out := make(map[string]applyOutcome)
	for _, r := range results {
		if r.Skipped || r.Err != nil || !r.HasUpdate() || r.Assessment == nil {
			continue
		}
		if !eligibleForApply(r, st) {
			continue
		}
		oc := applyOutcome{
			Success:  true,
			NewImage: r.Reference.String(),
			OldImage: r.Container.Image,
		}
		out[r.Container.Name] = oc
		logger.Info("apply (dry-run): would apply",
			"container", r.Container.Name,
			"image", r.Container.Image,
			"level", r.Assessment.Level.String())
		st.Audit(store.AuditEvent{
			Action:    store.ActionApplied,
			Container: r.Container.Name,
			Image:     r.Container.Image,
			Level:     r.Assessment.Level,
			Digest:    r.RegistryDigest,
			Detail:    "dry-run",
		})
	}
	return out
}

// eligibleForApply implements the SAFE-or-approved-REVIEW rule. A nil store
// disables the approval lookup, which means only SAFE updates qualify.
func eligibleForApply(r scanner.Result, st *store.Store) bool {
	switch r.Assessment.Level {
	case types.RiskSafe:
		return true
	case types.RiskReview:
		if st == nil {
			return false
		}
		// Primary key uses Container.ID (stable across Compose recreates).
		// Legacy fallback honours pre-Phase-10 records keyed on
		// Container.Name so an existing approval doesn't silently become
		// "no decision recorded" the moment a user upgrades Bulwark.
		primary := store.ApprovalKey{ContainerID: r.Container.ID, RegistryDigest: r.RegistryDigest}
		legacy := store.ApprovalKey{ContainerID: r.Container.Name, RegistryDigest: r.RegistryDigest}
		if r.Container.ID == "" {
			primary = legacy
		}
		dec, err := st.LookupDecisionOrLegacy(primary, legacy)
		if err != nil || dec == nil {
			return false
		}
		return dec.Decision == store.DecisionApproved
	default:
		// BREAKING (and anything unknown) never auto-applies.
		return false
	}
}

// adjustEventActions overrides the Action field on events for which an
// auto-apply attempt was made, so notifications show "Auto-updated" or
// "ROLLBACK" instead of the default "Review needed".
func adjustEventActions(events []notifier.Event, applyMap map[string]applyOutcome) {
	for i, e := range events {
		oc, ok := applyMap[e.Container]
		if !ok {
			continue
		}
		switch {
		case oc.RolledBack:
			events[i].Action = types.ActionRolledBack
		case oc.Success:
			events[i].Action = types.ActionAutoUpdated
		}
	}
}
