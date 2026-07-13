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
	"sync"
	"sync/atomic"
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
	Interval       time.Duration // simple form; ignored when Cron is set
	Cron           *CronSchedule // optional; takes precedence over Interval
	Job            Job
	Logger         *slog.Logger
	RunImmediately bool
	Name           string // appears in log lines; defaults to "scheduler"
	OnError        func(err error)

	// Now is overrideable for tests that need deterministic next-tick
	// computation. Defaults to time.Now.
	Now func() time.Time

	// liveCron holds the currently-active cron pointer; SetCron swaps
	// it atomically and signals the running loop via reloadCh. nil
	// until Run() copies in s.Cron at start.
	liveCron atomic.Pointer[CronSchedule]

	// reloadCh is the buffered channel of size 1 the cron loop selects
	// on; SetCron does a non-blocking send. Initialised exactly once
	// via reloadOnce so concurrent SetCron + Run() callers don't race
	// on the chan field assignment.
	reloadOnce sync.Once
	reloadCh   chan struct{}

	// newTicker builds the fixed-interval tick source. Overrideable in tests to
	// drive interval ticks deterministically instead of via the wall clock; nil
	// uses a real time.Ticker. Kept unexported so it is a test-only seam.
	newTicker func(d time.Duration) (ch <-chan time.Time, stop func())
}

// reload returns the reload signalling channel, lazy-initialising it
// the first time it's needed. Safe to call concurrently.
func (s *Scheduler) reload() chan struct{} {
	s.reloadOnce.Do(func() {
		s.reloadCh = make(chan struct{}, 1)
	})
	return s.reloadCh
}

// tickSource returns the fixed-interval tick channel and its stop function.
// Production uses a real time.Ticker; tests inject newTicker to feed ticks
// deterministically (a real ticker also silently DROPS ticks when the receiver
// is slow, which is exactly what made the interval test wall-clock-flaky).
func (s *Scheduler) tickSource(d time.Duration) (<-chan time.Time, func()) {
	if s.newTicker != nil {
		return s.newTicker(d)
	}
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// SetCron atomically replaces the cron expression the scheduler uses
// for next-tick calculation. Safe to call concurrently with Run().
// The running loop (if any) wakes up on the next reload signal and
// recomputes its next match against the new schedule. Passing nil
// switches the scheduler to "no cron"; the loop then falls back to
// Interval (or exits if Interval is also unset).
//
// Hot-reload contract: SetCron does not run the job immediately —
// the new cron decides when the next firing happens. If the operator
// wants an immediate run after a schedule change, they can fire
// POST /api/v1/scans.
func (s *Scheduler) SetCron(c *CronSchedule) {
	s.liveCron.Store(c)
	// Non-blocking send: the cron loop only needs one reload signal
	// to recompute. A second SetCron while the loop is already woken
	// is a no-op (it would recompute against the latest pointer
	// anyway).
	select {
	case s.reload() <- struct{}{}:
	default:
	}
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
	// Seed the atomic from the construction-time field. SetCron can
	// flip the pointer at any time after Run starts.
	s.liveCron.Store(s.Cron)
	// Touch reload() so the channel is allocated before any concurrent
	// SetCron tries to signal it. (SetCron also uses reload() to
	// initialise, but doing it here makes the race detector happy
	// regardless of call order.)
	_ = s.reload()
	if s.liveCron.Load() == nil && s.Interval <= 0 {
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

	if s.liveCron.Load() != nil {
		return s.runCron(ctx, logger, name)
	}

	tick, stop := s.tickSource(s.Interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info(name+": stopping", "reason", ctx.Err())
			return ctx.Err()
		case <-tick:
			s.invoke(ctx, logger, name)
		}
	}
}

// runCron is the cron-driven loop. We compute the time to the next match,
// sleep that long via a timer (so context cancellation interrupts cleanly),
// fire, then recompute. A cron schedule that never matches (e.g. Feb 30)
// returns nil after logging — better than spin-waiting forever.
//
// Hot reload: liveCron is reread at the top of every iteration, so a
// SetCron call mid-sleep wakes the loop via the reload channel and the
// next iteration picks up the new schedule. If SetCron is called with
// nil while running, the loop exits gracefully.
func (s *Scheduler) runCron(ctx context.Context, logger *slog.Logger, name string) error {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	for {
		cron := s.liveCron.Load()
		if cron == nil {
			logger.Info(name + ": cron disabled via SetCron(nil); stopping")
			return nil
		}
		next := cron.Next(now())
		if next.IsZero() {
			logger.Warn(name+": cron schedule has no future matches; stopping", "expr", cron.String())
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
		case <-s.reload():
			// Schedule changed mid-sleep — recompute against the new
			// expression on the next iteration. Drain the timer so it
			// doesn't fire spuriously.
			timer.Stop()
			if newCron := s.liveCron.Load(); newCron != nil {
				logger.Info(name+": cron reloaded", "expr", newCron.String())
			} else {
				logger.Info(name + ": cron reloaded (cleared)")
			}
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
