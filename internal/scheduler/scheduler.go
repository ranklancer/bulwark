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

// Scheduler runs a Job on a recurring schedule. The schedule is either a
// fixed Interval or a Cron expression — Cron takes precedence when set.
//
// RunImmediately fires the Job once at startup before the first interval /
// cron tick, so the daemon doesn't sit idle waiting for the next firing
// after launch.
type Scheduler struct {
	Interval       time.Duration  // simple form; ignored when Cron is set
	Cron           *CronSchedule  // optional; takes precedence over Interval
	Job            Job
	Logger         *slog.Logger
	RunImmediately bool
	Name           string // appears in log lines; defaults to "scheduler"
	OnError        func(err error)

	// Now is overrideable for tests that need deterministic next-tick
	// computation. Defaults to time.Now.
	Now func() time.Time
}

// Run executes the job loop until ctx is cancelled. The error returned from
// the job is logged but never propagated — a transient scan failure must not
// take the daemon down.
//
// Returns ctx.Err() when the context is cancelled. Returns nil immediately
// (without firing) when no schedule is configured (Interval <= 0 and Cron
// is nil) — callers can legitimately disable scheduling via flags without
// it being an error.
func (s *Scheduler) Run(ctx context.Context) error {
	if s == nil || s.Job == nil {
		return errors.New("scheduler: nil scheduler or job")
	}
	if s.Cron == nil && s.Interval <= 0 {
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

	if s.Cron != nil {
		return s.runCron(ctx, logger, name)
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

// runCron is the cron-driven loop. We compute the time to the next match,
// sleep that long via a timer (so context cancellation interrupts cleanly),
// fire, then recompute. A cron schedule that never matches (e.g. Feb 30)
// returns nil after logging — better than spin-waiting forever.
func (s *Scheduler) runCron(ctx context.Context, logger *slog.Logger, name string) error {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	for {
		next := s.Cron.Next(now())
		if next.IsZero() {
			logger.Warn(name+": cron schedule has no future matches; stopping", "expr", s.Cron.String())
			return nil
		}
		wait := next.Sub(now())
		if wait < 0 {
			// Clock skew or sub-minute precision: fire now and recompute.
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			logger.Info(name+": stopping", "reason", ctx.Err())
			return ctx.Err()
		case <-timer.C:
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
