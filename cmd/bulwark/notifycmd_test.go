package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

type alwaysOK struct {
	name string
	calls int32
	got  []notifier.Event
}

func (a *alwaysOK) Name() string                { return a.name }
func (a *alwaysOK) MinLevel() types.RiskLevel   { return types.RiskBreaking } // high bar
func (a *alwaysOK) Notify(_ context.Context, e []notifier.Event) error {
	atomic.AddInt32(&a.calls, 1)
	a.got = append(a.got, e...)
	return nil
}

type alwaysFail struct{ name string }

func (f *alwaysFail) Name() string                { return f.name }
func (f *alwaysFail) MinLevel() types.RiskLevel   { return types.RiskSafe }
func (f *alwaysFail) Notify(_ context.Context, _ []notifier.Event) error {
	return errors.New("simulated failure")
}

func TestCmdNotifyTest_SyntheticBypassesMinLevel(t *testing.T) {
	rec := &alwaysOK{name: "ha"}
	var stdout, stderr bytes.Buffer
	err := cmdNotifyTestWith(nil, &stdout, &stderr,
		notifyTestDeps{Notifiers: []notifier.Notifier{rec}})
	if err != nil {
		t.Fatalf("cmdNotifyTest: %v\nstderr: %s", err, stderr.String())
	}
	// Default --level is "review" but the notifier's MinLevel is Breaking;
	// only the Synthetic flag should let the event through.
	if atomic.LoadInt32(&rec.calls) != 1 {
		t.Fatalf("notifier calls = %d, want 1 (synthetic must bypass MinLevel)", rec.calls)
	}
	if len(rec.got) != 1 || !rec.got[0].Synthetic {
		t.Errorf("expected one synthetic event, got %+v", rec.got)
	}
	if !strings.Contains(stdout.String(), "ha: ok") {
		t.Errorf("expected 'ha: ok' line, got: %s", stdout.String())
	}
}

func TestCmdNotifyTest_FailureSurfaced(t *testing.T) {
	good := &alwaysOK{name: "good"}
	bad := &alwaysFail{name: "bad"}
	var stdout, stderr bytes.Buffer
	err := cmdNotifyTestWith(nil, &stdout, &stderr,
		notifyTestDeps{Notifiers: []notifier.Notifier{good, bad}})
	if err == nil {
		t.Fatal("expected non-nil error when a channel fails")
	}
	out := stdout.String()
	if !strings.Contains(out, "good: ok") || !strings.Contains(out, "bad: FAIL") {
		t.Errorf("expected per-channel summary lines, got:\n%s", out)
	}
}

func TestCmdNotifyTest_NoChannelsIsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := cmdNotifyTestWith(nil, &stdout, &stderr,
		notifyTestDeps{Notifiers: []notifier.Notifier{}})
	if err == nil {
		t.Fatal("expected error when no channels are configured")
	}
}

func TestCmdNotifyTest_RejectsBadLevel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rec := &alwaysOK{name: "test"}
	err := cmdNotifyTestWith([]string{"--level", "panic-mode"}, &stdout, &stderr,
		notifyTestDeps{Notifiers: []notifier.Notifier{rec}})
	if err == nil || !strings.Contains(err.Error(), "panic-mode") {
		t.Errorf("expected level-validation error, got: %v", err)
	}
}
