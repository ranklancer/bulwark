package notifier

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// fakeNotifier is a programmable Notifier for Dispatcher tests.
type fakeNotifier struct {
	name    string
	min     types.RiskLevel
	err     error
	gotMu   sync.Mutex
	gotEvts []Event
	calls   int32
	delay   time.Duration
}

func (f *fakeNotifier) Name() string              { return f.name }
func (f *fakeNotifier) MinLevel() types.RiskLevel { return f.min }
func (f *fakeNotifier) Notify(ctx context.Context, events []Event) error {
	atomic.AddInt32(&f.calls, 1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.gotMu.Lock()
	defer f.gotMu.Unlock()
	f.gotEvts = append(f.gotEvts, events...)
	return f.err
}

func TestDispatcher_FiltersBelowMinLevel(t *testing.T) {
	a := &fakeNotifier{name: "low", min: types.RiskSafe}
	b := &fakeNotifier{name: "review-and-up", min: types.RiskReview}
	c := &fakeNotifier{name: "breaking-only", min: types.RiskBreaking}
	d := NewDispatcher([]Notifier{a, b, c}, nil, 0)

	events := []Event{
		{Container: "x", Risk: types.RiskSafe},
		{Container: "y", Risk: types.RiskReview},
		{Container: "z", Risk: types.RiskBreaking},
	}
	results := d.Dispatch(context.Background(), events)
	if len(results) != 3 {
		t.Fatalf("len(results) = %d", len(results))
	}
	if results[0].Sent != 3 || results[0].Skipped != 0 {
		t.Errorf("low-threshold: sent=%d skipped=%d, want 3/0", results[0].Sent, results[0].Skipped)
	}
	if results[1].Sent != 2 || results[1].Skipped != 1 {
		t.Errorf("review-threshold: sent=%d skipped=%d, want 2/1", results[1].Sent, results[1].Skipped)
	}
	if results[2].Sent != 1 || results[2].Skipped != 2 {
		t.Errorf("breaking-threshold: sent=%d skipped=%d, want 1/2", results[2].Sent, results[2].Skipped)
	}
}

func TestDispatcher_SkipsHTTPCallWhenNothingToSend(t *testing.T) {
	n := &fakeNotifier{name: "high-bar", min: types.RiskBreaking}
	d := NewDispatcher([]Notifier{n}, nil, 0)
	results := d.Dispatch(context.Background(), []Event{
		{Container: "x", Risk: types.RiskSafe},
	})
	if results[0].Sent != 0 {
		t.Errorf("Sent = %d, want 0", results[0].Sent)
	}
	if atomic.LoadInt32(&n.calls) != 0 {
		t.Errorf("Notify called %d times despite empty filtered set", n.calls)
	}
}

func TestDispatcher_SyntheticBypassesMinLevel(t *testing.T) {
	n := &fakeNotifier{name: "high-bar", min: types.RiskBreaking}
	d := NewDispatcher([]Notifier{n}, nil, 0)
	results := d.Dispatch(context.Background(), []Event{
		{Container: "test", Risk: types.RiskSafe, Synthetic: true},
	})
	if results[0].Sent != 1 {
		t.Errorf("Sent = %d, want 1 (synthetic bypasses MinLevel)", results[0].Sent)
	}
	if atomic.LoadInt32(&n.calls) != 1 {
		t.Errorf("Notify called %d times, want 1", n.calls)
	}
}

func TestDispatcher_PerChannelErrorIsolation(t *testing.T) {
	good := &fakeNotifier{name: "ok", min: types.RiskSafe}
	bad := &fakeNotifier{name: "broken", min: types.RiskSafe, err: errors.New("kaboom")}
	d := NewDispatcher([]Notifier{good, bad}, nil, 0)
	results := d.Dispatch(context.Background(), []Event{
		{Container: "x", Risk: types.RiskReview},
	})
	if !results[0].Ok() {
		t.Errorf("good channel should be Ok, got err=%v", results[0].Err)
	}
	if results[1].Ok() {
		t.Error("bad channel should report Err")
	}
	if atomic.LoadInt32(&good.calls) != 1 || atomic.LoadInt32(&bad.calls) != 1 {
		t.Errorf("expected both channels invoked once: good=%d bad=%d", good.calls, bad.calls)
	}
}

func TestDispatcher_TimeoutEnforced(t *testing.T) {
	slow := &fakeNotifier{name: "slow", min: types.RiskSafe, delay: 100 * time.Millisecond}
	d := NewDispatcher([]Notifier{slow}, nil, 10*time.Millisecond)
	results := d.Dispatch(context.Background(), []Event{
		{Container: "x", Risk: types.RiskReview},
	})
	if results[0].Err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", results[0].Err)
	}
}

func TestDispatcher_NilSafe(t *testing.T) {
	var d *Dispatcher
	if got := d.Dispatch(context.Background(), nil); got != nil {
		t.Errorf("nil dispatcher should return nil, got %+v", got)
	}
	d2 := NewDispatcher(nil, nil, 0)
	if got := d2.Dispatch(context.Background(), []Event{{}}); got != nil {
		t.Errorf("dispatcher with no notifiers should return nil, got %+v", got)
	}
}

func TestTitleFor_VariesByRiskAndAction(t *testing.T) {
	cases := []struct {
		name string
		e    Event
		want string
	}{
		{"breaking", Event{Container: "x", Risk: types.RiskBreaking}, "BREAKING update blocked: x"},
		{"review", Event{Container: "x", Risk: types.RiskReview}, "Review needed: x"},
		{"safe", Event{Container: "x", Risk: types.RiskSafe}, "Update available: x"},
		{"action-rollback-overrides-risk", Event{Container: "x", Risk: types.RiskSafe, Action: types.ActionRolledBack}, "ROLLBACK: x"},
		{"synthetic-prefixed", Event{Container: "x", Risk: types.RiskSafe, Synthetic: true}, "[test] Update available: x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := titleFor(tc.e); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
