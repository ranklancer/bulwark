package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// digestFlushResult summarises one flush. Surfaced so the daemon can log
// per-tick activity ("flush dispatched 7 events") rather than silently
// firing notifications.
type digestFlushResult struct {
	Drained  int
	Dispatch []notifier.DispatchResult
}

// flushDigest drains the buffer and dispatches everything in it as a
// single batch. The dedup store is updated for every drained event so
// the next cycle's dedup filter doesn't re-queue the same notification.
//
// Safe to call when buf is nil (no-op) or when the buffer is empty
// (no-op + zero result). Intended to be invoked on a cron tick from
// `bulwark run`.
func flushDigest(
	ctx context.Context,
	buf *notifier.DigestBuffer,
	dispatcher *notifier.Dispatcher,
	st *store.Store,
	when time.Time,
	logger *slog.Logger,
) digestFlushResult {
	if buf == nil || dispatcher == nil {
		return digestFlushResult{}
	}
	events := buf.Drain()
	if len(events) == 0 {
		return digestFlushResult{}
	}
	if logger != nil {
		logger.Info("digest: flushing", "count", len(events))
	}
	dispatch := dispatcher.Dispatch(ctx, events)
	markSentEvents(st, events, dispatch, when, logger)
	return digestFlushResult{Drained: len(events), Dispatch: dispatch}
}
