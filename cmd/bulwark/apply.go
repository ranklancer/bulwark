package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ranklancer/bulwark/internal/api"
	"github.com/ranklancer/bulwark/internal/configstore"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/scanner"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/updater"
	"github.com/ranklancer/bulwark/internal/verify"
	"github.com/ranklancer/bulwark/pkg/types"
)

// applyOutcome records the result of a single auto-apply attempt. It's
// keyed by container name in applyEligibleUpdates' returned map.
type applyOutcome struct {
	Success      bool
	RolledBack   bool
	StackSkipped bool   // eligible, but a peer in the same compose project failed first
	StackPeer    string // when StackSkipped, the peer container whose failure triggered the skip
	Blocked      bool   // held by the deploy-time trust gate (verdict=block)
	BreakGlass   bool   // trust gate failed but an audited break-glass override applied
	Err          error
	NewImage     string
	OldImage     string
}

// snapshotOverrideLookup yields the per-container override for the
// given container name. nil-safe: a daemon running without a
// configstore returns a zero override and the apply pipeline falls
// back to label-driven precedence.
type snapshotOverrideLookup func(name string) configstore.ContainerOverride

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
func applyEligibleUpdates(ctx context.Context, results []scanner.Result, u *updater.Updater, st *store.Store, bus *api.EventBus, logger *slog.Logger, gate *verify.Gate, metrics *api.Metrics, overrides snapshotOverrideLookup) map[string]applyOutcome {
	if u == nil {
		return nil
	}
	// Apply in dependency-first order within each Compose project so
	// services come up after the things they depend on are already on
	// their new image. Containers without a Compose project pass through
	// in scan order — they have no ordering relationship to anything else.
	ordered := scanner.SortByDependencies(results, logger)
	out := make(map[string]applyOutcome, 0)
	// failedStacks tracks compose projects where an apply has already
	// failed (or rolled back) in this cycle. Subsequent eligible
	// containers in the same project are NOT applied — instead they're
	// recorded as StackSkipped so operators see they were intentionally
	// held back rather than silently ignored. Auto-rollback of already-
	// applied peers is deliberately out of scope for this v1; operators
	// inspect the audit log and decide whether to manually roll back.
	failedStacks := make(map[string]string) // project → name of the peer that failed first

	for _, r := range ordered {
		if r.Skipped || r.Err != nil || !r.HasUpdate() || r.Assessment == nil {
			continue
		}
		if !eligibleForApply(r, st) {
			continue
		}
		project := r.Container.ComposeProject()
		if project != "" {
			if peer, blocked := failedStacks[project]; blocked {
				oc := applyOutcome{
					StackSkipped: true,
					StackPeer:    peer,
					OldImage:     r.Container.Image,
					NewImage:     r.Reference.String(),
				}
				out[r.Container.Name] = oc
				logger.Warn("apply: stack-skipped",
					"container", r.Container.Name,
					"project", project,
					"failed_peer", peer)
				detail := fmt.Sprintf("compose project %q: peer %q failed earlier in this cycle", project, peer)
				st.Audit(store.AuditEvent{
					Action:    store.ActionStackSkipped,
					Container: r.Container.Name,
					Image:     r.Container.Image,
					Level:     r.Assessment.Level,
					Digest:    r.RegistryDigest,
					Detail:    detail,
				})
				bus.Publish(api.Event{
					Type:      api.EventApplyStackSkipped,
					Container: r.Container.Name,
					Image:     r.Container.Image,
					Detail:    detail,
				})
				continue
			}
		}
		// --- deploy-time trust gate (P0): the trust engine that lets safe
		// automation flow. A passing verdict lets this already-eligible update
		// apply with confidence; only a failing block-mode verdict holds it.
		// A nil or disabled gate is a no-op (zero behavior change).
		if gate != nil && gate.Policy.Enabled {
			verdict := gate.Evaluate(ctx, verify.Input{PinnedRef: pinnedRef(r), Labels: r.Container.Labels})
			metrics.IncVerdict(string(verdict.Decision))
			switch verdict.Decision {
			case verify.DecisionBlock:
				detail := verdict.Summary()
				logger.Warn("apply: blocked by trust gate", "container", r.Container.Name, "image", r.Container.Image, "reason", detail)
				st.Audit(store.AuditEvent{Action: store.ActionApplyBlocked, Container: r.Container.Name, Image: r.Container.Image, Level: r.Assessment.Level, Digest: r.RegistryDigest, Detail: detail})
				bus.Publish(api.Event{Type: api.EventApplyBlocked, Container: r.Container.Name, Image: r.Container.Image, Detail: detail})
				out[r.Container.Name] = applyOutcome{Blocked: true, OldImage: r.Container.Image, NewImage: r.Reference.String()}
				continue
			case verify.DecisionBreakGlass:
				reason := ""
				if verdict.BreakGlass != nil {
					reason = verdict.BreakGlass.Reason
				}
				detail := "break-glass: " + reason + " - " + verdict.Summary()
				logger.Warn("apply: trust gate overridden by break-glass", "container", r.Container.Name, "image", r.Container.Image, "reason", reason)
				st.Audit(store.AuditEvent{Action: store.ActionApplyBreakGlass, Container: r.Container.Name, Image: r.Container.Image, Level: r.Assessment.Level, Digest: r.RegistryDigest, Detail: detail})
				bus.Publish(api.Event{Type: api.EventApplyBreakGlass, Container: r.Container.Name, Image: r.Container.Image, Detail: detail})
			case verify.DecisionWarn:
				// the design notes warn/observe: surface what WOULD block, then let the
				// apply proceed (warn never holds). Previously this verdict was
				// silent apart from the metric counter; now record a structured
				// log, an audit entry and a bus event so operators can see the
				// would-block set and progress warn -> identities -> block.
				warnDetail := "would-block (warn mode) [" + string(verdict.Remediation()) + "]: " + verdict.Summary()
				logger.Warn("apply: trust-gate would-block (warn mode)", "container", r.Container.Name, "image", r.Container.Image, "remediation", string(verdict.Remediation()), "reason", verdict.Summary())
				st.Audit(store.AuditEvent{Action: store.ActionApplyWouldBlock, Container: r.Container.Name, Image: r.Container.Image, Level: r.Assessment.Level, Digest: r.RegistryDigest, Detail: warnDetail})
				bus.Publish(api.Event{Type: api.EventApplyWouldBlock, Container: r.Container.Name, Image: r.Container.Image, Detail: warnDetail})
			}
		}
		opts := updater.ApplyOptions{}
		// Snapshot precedence: a UI-set override (configstore) wins over
		// container labels. Within each tier, explicit dataset wins over
		// "auto-infer" so an operator can pin a specific dataset even
		// when the host mount table is misleading.
		var override configstore.ContainerOverride
		if overrides != nil {
			override = overrides(r.Container.Name)
		}
		plan := configstore.ComputeEffectiveSnapshot(r.Container.Labels, override)
		switch {
		case plan.Dataset != "":
			opts.SnapshotTarget = plan.Dataset
			opts.SnapshotLabel = r.Container.Name
		case plan.Auto:
			opts.SnapshotAutoInfer = true
			opts.SnapshotLabel = r.Container.Name
		}
		// Pre/post/rollback hook paths from the container's labels.
		// Empty paths disable the corresponding hook.
		opts.PreUpdateHook = r.Container.Labels["bulwark.hook.pre-update"]
		opts.PostUpdateHook = r.Container.Labels["bulwark.hook.post-update"]
		opts.RollbackHook = r.Container.Labels["bulwark.hook.rollback"]
		logger.Info("apply: starting", "container", r.Container.Name, "image", r.Container.Image, "level", r.Assessment.Level.String(), "snapshot_target", opts.SnapshotTarget, "project", project)
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
		var liveType string
		switch {
		case oc.Success:
			ev.Action = store.ActionApplied
			ev.Detail = fmt.Sprintf("%s → %s", res.OldImage, res.NewImage)
			liveType = api.EventApplySuccess
			logger.Info("apply: success", "container", r.Container.Name, "new_id", res.NewContainerID)
		case oc.RolledBack:
			ev.Action = store.ActionRolledBack
			if res.Err != nil {
				ev.Detail = res.Err.Error()
			}
			liveType = api.EventApplyRolledBack
			logger.Warn("apply: rolled back", "container", r.Container.Name, "err", res.Err)
		default:
			ev.Action = store.ActionAppliedFailed
			if res.Err != nil {
				ev.Detail = res.Err.Error()
			}
			liveType = api.EventApplyFailed
			logger.Error("apply: failed", "container", r.Container.Name, "err", res.Err)
		}
		st.Audit(ev)
		bus.Publish(api.Event{
			Type:      liveType,
			Container: r.Container.Name,
			Image:     r.Container.Image,
			Detail:    ev.Detail,
		})
		out[r.Container.Name] = oc
		if !oc.Success && project != "" {
			// Record this stack as failed so subsequent peers in the
			// same compose project will be skipped — even rolled-back
			// outcomes count, since a rollback means the new image was
			// rejected and applying its dependents would mismatch their
			// expectations.
			failedStacks[project] = r.Container.Name
		}
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
	// Sort dry-run output the same way real apply would, so operators
	// inspecting the log see the order updates would actually be
	// attempted. Dry-run can't fail, so there's no stack-skip path here.
	ordered := scanner.SortByDependencies(results, logger)
	out := make(map[string]applyOutcome)
	for _, r := range ordered {
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
		case oc.Blocked:
			events[i].Action = types.ActionBlocked
		case oc.StackSkipped:
			events[i].Action = types.ActionStackSkipped
		case oc.RolledBack:
			events[i].Action = types.ActionRolledBack
		case oc.Success:
			events[i].Action = types.ActionAutoUpdated
		}
	}
}

// pinnedRef returns the digest-pinned reference the daemon will deploy, so the
// trust gate verifies exactly the artifact being applied. When a registry
// digest is known it is appended (repo:tag@sha256:...); cosign resolves by
// digest regardless of the tag.
func pinnedRef(r scanner.Result) string {
	ref := r.Reference.String()
	if r.RegistryDigest != "" && !strings.Contains(ref, "@") {
		return ref + "@" + r.RegistryDigest
	}
	return ref
}
