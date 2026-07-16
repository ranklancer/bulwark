package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ranklancer/bulwark/internal/api"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/scanner"
	"github.com/ranklancer/bulwark/internal/scheduler"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/updater"
	"github.com/ranklancer/bulwark/internal/verify"
	"github.com/ranklancer/bulwark/pkg/types"
)

// scanCycleConfig bundles the shared inputs for one full scan + dispatch +
// record cycle. It's the union of what `bulwark scan` and `bulwark run`
// both need to drive a single iteration of the pipeline.
type scanCycleConfig struct {
	Scanner    *scanner.Scanner
	Dispatcher *notifier.Dispatcher // nil disables notification dispatch
	Store      *store.Store         // nil disables dedup + history
	DedupTTL   time.Duration        // 0 disables dedup silencing
	Updater    *updater.Updater     // nil disables auto-apply
	Apply      bool                 // true to enable auto-apply; requires Updater
	DryRun     bool                 // true to log what would be applied without touching containers
	// MaintenanceWindows, when non-empty, gates the apply phase. The
	// scan + notification pipeline always runs; only mutating the
	// containers is constrained. When the slice is empty, apply runs
	// whenever the rest of the gates allow it (scheduler defaults).
	MaintenanceWindows []scheduler.Window
	// DigestBuffer, when non-nil, enables digest mode: non-urgent
	// notifications (everything except BREAKING / rolled-back /
	// stack-skipped / synthetic) are queued for later flush instead of
	// being dispatched immediately. The flush runs out-of-band via
	// flushDigest on its own cron schedule.
	DigestBuffer *notifier.DigestBuffer
	// Events, when set, drives the dashboard's live-updates SSE
	// stream. nil disables event publication entirely (no event
	// bus, no SSE endpoint — same as a deployment that hasn't yet
	// had Phase 16f wired into its run.go).
	Events *api.EventBus
	// SnapshotOverrides is the per-container UI-set override lookup
	// used by the apply pipeline. nil-safe; a daemon without a
	// configstore falls back to label-driven precedence.
	SnapshotOverrides snapshotOverrideLookup
	// Gate is the deploy-time trust gate. nil disables verification (zero
	// behavior change); a passing verdict lets eligible updates apply.
	Gate *verify.Gate
	// Metrics receives verdict counters; nil-safe.
	Metrics *api.Metrics
	Now     func() time.Time // injected for deterministic tests
	Logger  *slog.Logger
	All     bool // include stopped containers
}

// scanCycleResult holds everything callers want to render afterwards. We
// expose it as a struct (not just (results, dispatch) tuples) so the daemon
// loop can also surface a digest in its periodic log lines.
type scanCycleResult struct {
	Results          []scanner.Result
	Dispatch         []notifier.DispatchResult
	DedupSilenced    int                     // events suppressed by TTL silencing
	ApprovalSilenced int                     // events suppressed by an existing user decision
	DigestQueued     int                     // events buffered for later digest flush
	Applies          map[string]applyOutcome // keyed by container name
	// ApplyGated is true when --apply was set but the maintenance-window
	// filter blocked the apply phase. Surfaced so callers can render a
	// clear "outside window" message instead of "nothing eligible".
	ApplyGated bool
	StartedAt  time.Time
	FinishedAt time.Time
}

// runScanCycle executes one full pipeline iteration: scan → events → dedup
// filter → dispatch → mark sent → record history. Used by both the one-shot
// `bulwark scan` command and the recurring scheduler driven by `bulwark run`.
//
// Errors from scan are returned (the caller decides whether to log and
// continue, or fail the process). Notification and history failures are
// logged but never returned — they must not block the next scan from running.
func runScanCycle(ctx context.Context, cfg scanCycleConfig) (scanCycleResult, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	res := scanCycleResult{StartedAt: now()}
	results, err := cfg.Scanner.Scan(ctx, cfg.All)
	if err != nil {
		return res, err
	}
	res.Results = results
	res.FinishedAt = now()

	// Auto-apply qualifying updates BEFORE notifications. This lets us
	// surface "Auto-updated" / "ROLLBACK" notifications instead of
	// double-notifying ("update available" then "applied").
	if cfg.Apply && cfg.Updater != nil {
		// Maintenance-window gate: when configured, only mutate
		// containers during a permitted window. Scans still run
		// (read-only); notifications still fire so operators see
		// pending work even outside the window.
		applyResults := results
		if len(cfg.MaintenanceWindows) > 0 && !scheduler.AnyActive(now(), cfg.MaintenanceWindows) {
			// Outside the window we normally skip all mutation. Exception:
			// with AutoApplyUrgentSafe, security-urgent SAFE updates (those
			// closing CRITICAL CVEs) may apply on this tighter schedule —
			// surfacing the security signal is the whole point. Everything
			// else still waits for the window.
			// auto_apply_urgent_safe is read from the scanner's loaded config
			// (opt-in, off by default).
			autoUrgent := cfg.Scanner != nil && cfg.Scanner.Config != nil && cfg.Scanner.Config.Security.AutoApplyUrgentSafe
			urgent := filterUrgentSafe(results)
			if autoUrgent && len(urgent) > 0 {
				logger.Info("apply: outside maintenance window; applying security-urgent SAFE updates only (auto_apply_urgent_safe)",
					"now", now().Format(time.RFC3339),
					"urgent_safe", len(urgent))
				applyResults = urgent
			} else {
				res.ApplyGated = true
				logger.Info("apply: outside maintenance window; skipping apply phase",
					"now", now().Format(time.RFC3339),
					"windows", len(cfg.MaintenanceWindows))
				applyResults = nil
			}
		}
		switch {
		case applyResults == nil:
			// gated — nothing to apply this cycle
		case cfg.DryRun:
			// Dry-run: log what would be applied; produce synthetic
			// success outcomes so the notification path renders the
			// "Auto-updated" framing operators expect to inspect.
			res.Applies = applyEligibleDryRun(applyResults, cfg.Store, logger)
		default:
			res.Applies = applyEligibleUpdates(ctx, applyResults, cfg.Updater, cfg.Store, cfg.Events, logger, cfg.Gate, cfg.Metrics, cfg.SnapshotOverrides)
		}
	}

	if cfg.Dispatcher != nil && len(cfg.Dispatcher.Notifiers()) > 0 {
		allEvents := notifier.EventsFromScan(results, res.FinishedAt.UTC())
		if len(res.Applies) > 0 {
			adjustEventActions(allEvents, res.Applies)
		}

		// Approval decisions take priority — they silence forever, not just
		// within the TTL window. We filter them out first so subsequent steps
		// only see still-pending events.
		afterApproval, approvalSilenced := filterByApproval(cfg.Store, allEvents, logger)
		res.ApprovalSilenced = approvalSilenced

		afterDedup, dedupSilenced := filterByDedup(cfg.Store, afterApproval, res.FinishedAt, cfg.DedupTTL, logger)
		res.DedupSilenced = dedupSilenced

		if len(afterDedup) > 0 {
			toDispatch := afterDedup
			if cfg.DigestBuffer != nil {
				urgent, buffered := notifier.SplitForDigest(afterDedup)
				if len(buffered) > 0 {
					cfg.DigestBuffer.Add(buffered)
					res.DigestQueued = len(buffered)
					logger.Info("digest: events buffered for next flush",
						"count", len(buffered),
						"queue_size", cfg.DigestBuffer.Len())
				}
				toDispatch = urgent
			}
			if len(toDispatch) > 0 {
				res.Dispatch = cfg.Dispatcher.Dispatch(ctx, toDispatch)
				markSentEvents(cfg.Store, toDispatch, res.Dispatch, res.FinishedAt, logger)
			}
		}
	}

	var scanID string
	if cfg.Store != nil {
		rec := buildScanRecord(results, res.Dispatch, res.StartedAt, res.FinishedAt)
		recorded, err := cfg.Store.RecordScan(rec)
		if err != nil {
			logger.Warn("could not persist scan record", "err", err)
		} else {
			scanID = recorded.ID
		}
	}

	cfg.Events.Publish(api.Event{
		Type:   api.EventScanCompleted,
		ScanID: scanID,
		Detail: scanCompletionDetail(res),
	})

	return res, nil
}

// scanCompletionDetail summarises the cycle's outcome as a one-line
// SSE toast: e.g. "3 pending (1 breaking, 2 review)" or
// "no pending updates".
func scanCompletionDetail(res scanCycleResult) string {
	pending, breaking, review, safe := 0, 0, 0, 0
	for _, r := range res.Results {
		if r.Skipped || r.Err != nil || !r.HasUpdate() || r.Assessment == nil {
			continue
		}
		pending++
		switch r.Assessment.Level.String() {
		case "breaking":
			breaking++
		case "review":
			review++
		case "safe":
			safe++
		}
	}
	if pending == 0 {
		return "no pending updates"
	}
	parts := []string{}
	if breaking > 0 {
		parts = append(parts, fmt.Sprintf("%d breaking", breaking))
	}
	if review > 0 {
		parts = append(parts, fmt.Sprintf("%d review", review))
	}
	if safe > 0 {
		parts = append(parts, fmt.Sprintf("%d safe", safe))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d pending", pending)
	}
	return fmt.Sprintf("%d pending (%s)", pending, strings.Join(parts, ", "))
}

// filterUrgentSafe returns the subset of results that are SAFE-classified and
// carry a CRITICAL-closing security urgency. These are the only updates that
// may bypass the maintenance window when auto_apply_urgent_safe is enabled.
func filterUrgentSafe(results []scanner.Result) []scanner.Result {
	var out []scanner.Result
	for _, r := range results {
		a := r.Assessment
		if a == nil || a.Level != types.RiskSafe || a.Security == nil {
			continue
		}
		if a.Security.Urgency == types.UrgencyUrgent {
			out = append(out, r)
		}
	}
	return out
}
