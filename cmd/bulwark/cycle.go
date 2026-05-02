package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/updater"
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
	Now        func() time.Time     // injected for deterministic tests
	Logger     *slog.Logger
	All        bool // include stopped containers
}

// scanCycleResult holds everything callers want to render afterwards. We
// expose it as a struct (not just (results, dispatch) tuples) so the daemon
// loop can also surface a digest in its periodic log lines.
type scanCycleResult struct {
	Results          []scanner.Result
	Dispatch         []notifier.DispatchResult
	DedupSilenced    int                    // events suppressed by TTL silencing
	ApprovalSilenced int                    // events suppressed by an existing user decision
	Applies          map[string]applyOutcome // keyed by container name
	StartedAt        time.Time
	FinishedAt       time.Time
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
		res.Applies = applyEligibleUpdates(ctx, results, cfg.Updater, cfg.Store, logger)
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
			res.Dispatch = cfg.Dispatcher.Dispatch(ctx, afterDedup)
			markSentEvents(cfg.Store, afterDedup, res.Dispatch, res.FinishedAt, logger)
		}
	}

	if cfg.Store != nil {
		rec := buildScanRecord(results, res.Dispatch, res.StartedAt, res.FinishedAt)
		if _, err := cfg.Store.RecordScan(rec); err != nil {
			logger.Warn("could not persist scan record", "err", err)
		}
	}

	return res, nil
}
