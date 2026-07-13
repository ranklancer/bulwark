package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// tickerReturning builds a newTicker override handing back a fixed channel so
// the interval-driven tests are deterministic (no wall-clock dependency): the
// test either feeds ticks explicitly or never feeds them to keep the loop parked.
func tickerReturning(ch <-chan time.Time) func(time.Duration) (<-chan time.Time, func()) {
	return func(time.Duration) (<-chan time.Time, func()) { return ch, func() {} }
}

func TestScheduler_RunsImmediatelyAndOnInterval(t *testing.T) {
	// Deterministic: interval ticks are delivered through an injected channel and
	// the test synchronises on job completion, so there is no wall-clock timing
	// dependency (the old version relied on a 30ms ticker firing >=2 times inside
	// a 100ms window, which a real time.Ticker may not do under load — it drops
	// ticks when the receiver is slow). This asserts both behaviours precisely:
	// exactly one immediate run at start, then exactly one run per interval tick.
	ticks := make(chan time.Time)
	ran := make(chan struct{}, 8)
	var calls int32
	s := &Scheduler{
		Interval:       time.Hour, // > 0 so Run proceeds; newTicker overrides the source
		RunImmediately: true,
		newTicker: func(time.Duration) (<-chan time.Time, func()) {
			return ticks, func() {}
		},
		Job: func(ctx context.Context) error {
			atomic.AddInt32(&calls, 1)
			ran <- struct{}{}
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()

	// 1) Immediate run fires before any interval tick.
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("immediate run did not fire")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("after immediate run: calls = %d, want 1", got)
	}

	// 2) Each delivered tick produces exactly one run (on-interval behaviour).
	// The unbuffered send blocks until the loop is in its select, so there is no
	// race and no dropped tick.
	for want := int32(2); want <= 4; want++ {
		ticks <- time.Now()
		select {
		case <-ran:
		case <-time.After(2 * time.Second):
			t.Fatalf("tick did not produce a run (want %d)", want)
		}
		if got := atomic.LoadInt32(&calls); got != want {
			t.Fatalf("after tick: calls = %d, want %d", got, want)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop after context cancel")
	}
}

func TestScheduler_NoImmediate(t *testing.T) {
	// Deterministic: no ticks are ever delivered, so with RunImmediately=false the
	// job must never run before the first (never-delivered) tick.
	ticks := make(chan time.Time)
	var calls int32
	s := &Scheduler{
		Interval:  time.Hour, // > 0 so Run proceeds; newTicker overrides the source
		newTicker: tickerReturning(ticks),
		Job: func(_ context.Context) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("RunImmediately=false must not run before the first tick; got %d calls", got)
	}
}

func TestScheduler_StopsOnContextCancel(t *testing.T) {
	ticks := make(chan time.Time)
	ran := make(chan struct{}, 1)
	s := &Scheduler{
		Interval:       time.Hour,
		RunImmediately: true,
		newTicker:      tickerReturning(ticks),
		Job: func(_ context.Context) error {
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	// Immediate run fired and the loop is now parked in its select.
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("immediate run did not fire")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestScheduler_JobErrorIsLoggedNotPropagated(t *testing.T) {
	ticks := make(chan time.Time)
	errSig := make(chan struct{}, 1)
	var jobErrCount int32
	s := &Scheduler{
		Interval:       time.Hour,
		RunImmediately: true,
		newTicker:      tickerReturning(ticks),
		Job:            func(_ context.Context) error { return errors.New("oh no") },
		OnError: func(_ error) {
			atomic.AddInt32(&jobErrCount, 1)
			select {
			case errSig <- struct{}{}:
			default:
			}
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	select {
	case <-errSig:
	case <-time.After(2 * time.Second):
		t.Fatal("OnError was never invoked for a failing job")
	}
	cancel()
	<-done
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
	ticks := make(chan time.Time)
	ran := make(chan struct{}, 1)
	var onError int32
	s := &Scheduler{
		Interval:       time.Hour,
		RunImmediately: true,
		newTicker:      tickerReturning(ticks),
		Job: func(_ context.Context) error {
			select {
			case ran <- struct{}{}:
			default:
			}
			return context.Canceled
		},
		OnError: func(_ error) { atomic.AddInt32(&onError, 1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("immediate run did not fire")
	}
	// The immediate invoke completes before Run enters its select; cancel + drain
	// guarantees it finished, after which OnError must NOT have been called.
	cancel()
	<-done
	if got := atomic.LoadInt32(&onError); got != 0 {
		t.Errorf("context.Canceled inside a job must not trigger OnError; got %d", got)
	}
}
