package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduler_RunsImmediatelyAndOnInterval(t *testing.T) {
	var calls int32
	s := &Scheduler{
		Interval:       30 * time.Millisecond,
		RunImmediately: true,
		Job: func(ctx context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	// Expect: 1 immediate + at least 2 ticks at 30ms inside a 100ms window.
	got := atomic.LoadInt32(&calls)
	if got < 3 {
		t.Errorf("calls = %d, want >= 3", got)
	}
}

func TestScheduler_NoImmediate(t *testing.T) {
	var calls int32
	s := &Scheduler{
		Interval: 200 * time.Millisecond,
		Job: func(ctx context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("RunImmediately=false should not run before first tick; got %d calls", got)
	}
}

func TestScheduler_StopsOnContextCancel(t *testing.T) {
	var calls int32
	s := &Scheduler{
		Interval:       10 * time.Millisecond,
		RunImmediately: true,
		Job: func(ctx context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	time.Sleep(40 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Run did not return after cancel")
	}
}

func TestScheduler_JobErrorIsLoggedNotPropagated(t *testing.T) {
	var jobErrCount int32
	s := &Scheduler{
		Interval:       10 * time.Millisecond,
		RunImmediately: true,
		Job: func(_ context.Context) error {
			return errors.New("oh no")
		},
		OnError: func(_ error) { atomic.AddInt32(&jobErrCount, 1) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if got := atomic.LoadInt32(&jobErrCount); got == 0 {
		t.Errorf("OnError never invoked; got %d", got)
	}
}

func TestScheduler_ZeroIntervalIsNoOp(t *testing.T) {
	s := &Scheduler{Interval: 0, Job: func(_ context.Context) error { return nil }}
	if err := s.Run(context.Background()); err != nil {
		t.Errorf("zero-interval Run returned %v, want nil", err)
	}
}

func TestScheduler_NilJobIsError(t *testing.T) {
	s := &Scheduler{Interval: time.Hour}
	if err := s.Run(context.Background()); err == nil {
		t.Error("nil job should error")
	}
}

func TestScheduler_CronTakesPrecedenceOverInterval(t *testing.T) {
	// Cron set with a non-matching schedule (Feb 30 — never fires) plus a
	// fast Interval that *would* fire if precedence were inverted.
	cron, err := ParseCron("0 0 30 2 *")
	if err != nil {
		t.Fatal(err)
	}
	var calls int32
	s := &Scheduler{
		Interval:       5 * time.Millisecond,
		Cron:           cron,
		RunImmediately: false,
		Job: func(_ context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	// Cron never matches, so the job should not have run via the interval path.
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("calls = %d, want 0 (cron precedence over interval)", got)
	}
}

func TestScheduler_CronFiresAtComputedTime(t *testing.T) {
	cron, _ := ParseCron("* * * * *") // every minute
	var calls int32
	// Frozen-clock test: each Now() call returns a value far enough ahead
	// that Cron.Next yields a tiny wait (next minute boundary).
	start := time.Now().Truncate(time.Minute).Add(time.Minute - 50*time.Millisecond)
	s := &Scheduler{
		Cron:           cron,
		RunImmediately: false,
		Now:            func() time.Time { return start },
		Job: func(_ context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if got := atomic.LoadInt32(&calls); got < 1 {
		t.Errorf("cron tick did not fire within window (calls=%d)", got)
	}
}

func TestScheduler_SetCron_RecomputesNext(t *testing.T) {
	// Schedule starts with a far-future cron expression, then SetCron
	// swaps in one that's about to fire. The loop must wake on
	// reload and use the new schedule.
	farFuture, _ := ParseCron("0 0 1 1 *") // Jan 1, ~once a year
	soon, _ := ParseCron("* * * * *")      // every minute
	var calls int32
	// Now() returns a time near a minute boundary so soon's Next() is
	// only ~50ms away once we swap.
	start := time.Now().Truncate(time.Minute).Add(time.Minute - 50*time.Millisecond)
	s := &Scheduler{
		Cron:           farFuture,
		RunImmediately: false,
		Now:            func() time.Time { return start },
		Job: func(_ context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Give Run a beat to enter runCron and start sleeping against
	// farFuture's next firing.
	time.Sleep(50 * time.Millisecond)
	s.SetCron(soon)

	<-done
	if atomic.LoadInt32(&calls) == 0 {
		t.Error("expected job to fire after SetCron swap; did not")
	}
}

func TestScheduler_SetCron_NilStopsLoop(t *testing.T) {
	cron, _ := ParseCron("* * * * *")
	start := time.Now().Truncate(time.Minute).Add(2 * time.Hour) // far enough away that the loop is sleeping
	s := &Scheduler{
		Cron: cron,
		Now:  func() time.Time { return start },
		Job:  func(_ context.Context) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	s.SetCron(nil)
	// Loop should exit on its own (not via context timeout). Use a
	// shorter wait than the ctx timeout to confirm.
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected clean nil exit, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("loop did not exit after SetCron(nil)")
	}
}

func TestScheduler_NoScheduleIsNoop(t *testing.T) {
	s := &Scheduler{Job: func(_ context.Context) error { return nil }}
	if err := s.Run(context.Background()); err != nil {
		t.Errorf("no-schedule run returned %v", err)
	}
}

func TestScheduler_CanceledJobErrorNotEscalated(t *testing.T) {
	var onError int32
	s := &Scheduler{
		Interval:       10 * time.Millisecond,
		RunImmediately: true,
		Job:            func(_ context.Context) error { return context.Canceled },
		OnError:        func(_ error) { atomic.AddInt32(&onError, 1) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_ = s.Run(ctx)
	if got := atomic.LoadInt32(&onError); got != 0 {
		t.Errorf("context.Canceled inside job should not trigger OnError; got %d", got)
	}
}
