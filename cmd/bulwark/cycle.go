package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// scanCycleConfig bundles the shared inputs for one full scan + dispatch +
// record cycle. It's the union of what `bulwark scan` and `bulwark run`
// both need to drive a single iteration of the pipeline.
type scanCycleConfig struct {
	Scanner    *scanner.Scanner
	Dispatcher *notifier.Dispatcher // nil disables notification dispatch
	Store      *store.Store         // nil disables dedup + history
	DedupTTL   time.Duration        // 0 disables dedup silencing
	Now        func() time.Time     // injected for deterministic tests
	Logger     *slog.Logger
	All        bool // include stopped containers
}

// scanCycleResult holds everything callers want to render afterwards. We
// expose it as a struct (not just (results, dispatch) tuples) so the daemon
// loop can also surface a digest in its periodic log lines.
type scanCycleResult struct {
	Results        []scanner.Result
	Dispatch       []notifier.DispatchResult
	DedupSilenced  int
	StartedAt      time.Time
	FinishedAt     time.Time
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

	if cfg.Dispatcher != nil && len(cfg.Dispatcher.Notifiers()) > 0 {
		allEvents := notifier.EventsFromScan(results, res.FinishedAt.UTC())
		events, silenced := filterByDedup(cfg.Store, allEvents, res.FinishedAt, cfg.DedupTTL, logger)
		res.DedupSilenced = silenced
		if len(events) > 0 {
			res.Dispatch = cfg.Dispatcher.Dispatch(ctx, events)
			markSentEvents(cfg.Store, events, res.Dispatch, res.FinishedAt, logger)
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
