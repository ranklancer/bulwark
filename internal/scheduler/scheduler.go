// Package scheduler runs a single recurring job at a fixed interval, with
// graceful shutdown via context cancellation. It deliberately avoids cron
// syntax: an interval is sufficient for the daemon's "scan every N hours"
// use case, and cron parsers add a meaningful dependency for marginal value.
//
// When users want richer scheduling (specific times of day, day-of-week
// constraints, maintenance windows), the daemon will gain a higher-level
// scheduler that wraps this one.
package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Job is the function the scheduler invokes on each tick. The scheduler
// passes through its own context so a shutdown mid-job propagates immediately.
type Job func(ctx context.Context) error

// Scheduler runs a Job at Interval. Optionally fires the Job once at startup
// before the first interval elapses (RunImmediately, default true) so the
// daemon doesn't sit idle for the full Interval after launch.
type Scheduler struct {
	Interval        time.Duration
	Job             Job
	Logger          *slog.Logger
	RunImmediately  bool
	Name            string // appears in log lines; defaults to "scheduler"
	OnError         func(err error)
}

// Run executes the job loop until ctx is cancelled. The error returned from
// the job is logged but never propagated — a transient scan failure must not
// take the daemon down.
//
// Returns ctx.Err() when the context is cancelled, or nil if Interval is
// non-positive (which we treat as "no schedule, exit immediately" rather
// than as an error, since callers may legitimately disable scheduling at
// runtime via a --interval=0 flag).
func (s *Scheduler) Run(ctx context.Context) error {
	if s == nil || s.Job == nil {
		return errors.New("scheduler: nil scheduler or job")
	}
	if s.Interval <= 0 {
		return nil
	}
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	name := s.Name
	if name == "" {
		name = "scheduler"
	}

	if s.RunImmediately {
		s.invoke(ctx, logger, name)
	}

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info(name+": stopping", "reason", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			s.invoke(ctx, logger, name)
		}
	}
}

func (s *Scheduler) invoke(ctx context.Context, logger *slog.Logger, name string) {
	start := time.Now()
	err := s.Job(ctx)
	if err != nil {
		// Don't log canceled errors loudly — that's just the daemon
		// shutting down mid-tick.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			logger.Debug(name+": job interrupted", "duration", time.Since(start))
			return
		}
		logger.Error(name+": job failed", "duration", time.Since(start), "err", err)
		if s.OnError != nil {
			s.OnError(err)
		}
		return
	}
	logger.Info(name+": tick complete", "duration", time.Since(start))
}
