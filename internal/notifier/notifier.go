// Package notifier dispatches Bulwark events to external channels (Slack,
// Discord, generic webhooks). The package is intentionally side-effect-only —
// it has no notion of update history, deduplication, or persistence. Those
// concerns belong upstream (or to a future SQLite store).
//
// Channels are independent: a failing webhook never blocks the others, and
// each channel may filter events by minimum risk level.
package notifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// Event is the payload exchanged with notifiers. It collects everything a
// channel implementation might want to render — fields are populated only
// when known, so consumers should test for emptiness before formatting.
type Event struct {
	Container      string
	Image          string
	ComposeProject string
	Risk           types.RiskLevel
	Action         types.UpdateAction
	From           string
	To             string
	Kind           types.ChangeKind
	Confidence     types.Confidence
	Rationale      string
	ReleaseURL     string
	Changelog      string
	NotesSource    string
	LocalDigest    string
	RegistryDigest string
	Timestamp      time.Time
	// Synthetic identifies a test event sent via `bulwark notify-test`.
	// Implementations should make it visually distinct so the recipient
	// knows it isn't a real alert.
	Synthetic bool
}

// Notifier is the contract every channel implementation satisfies. The
// contract is "deliver these events, or don't" — channels handle their own
// formatting, batching, and HTTP errors.
type Notifier interface {
	// Name is a stable, log-friendly channel identifier. Never include
	// secrets (e.g. webhook URLs) in the name — it appears in user-visible
	// error messages.
	Name() string

	// MinLevel returns the lowest risk level this channel cares about.
	// Events below this threshold are filtered out by the Dispatcher
	// before Notify is called.
	MinLevel() types.RiskLevel

	// Notify delivers a batch of events. Implementations may choose to
	// emit one HTTP call per event or a single digest message — that's
	// an implementation detail.
	//
	// Synthetic events (Event.Synthetic == true) must always be sent
	// regardless of any internal filtering, so `notify-test` is reliable.
	Notify(ctx context.Context, events []Event) error
}

// DispatchResult carries the per-channel outcome of a Dispatcher.Dispatch call.
type DispatchResult struct {
	Notifier string
	Sent     int   // number of events forwarded after filtering
	Skipped  int   // number filtered out by MinLevel
	Err      error // non-nil if the channel returned a transport error
}

// Ok reports whether this channel's dispatch succeeded.
func (r DispatchResult) Ok() bool { return r.Err == nil }

// Dispatcher fans events out to a set of registered notifiers. It is safe
// for concurrent use, though each Dispatch call serialises its own work.
type Dispatcher struct {
	notifiers []Notifier
	logger    *slog.Logger
	timeout   time.Duration
}

// NewDispatcher returns a Dispatcher backed by the given notifiers. logger
// may be nil — events are not logged in that case. timeout caps the per-
// channel HTTP budget; pass zero to keep each channel's own client default.
func NewDispatcher(notifiers []Notifier, logger *slog.Logger, timeout time.Duration) *Dispatcher {
	return &Dispatcher{notifiers: notifiers, logger: logger, timeout: timeout}
}

// Notifiers returns the registered notifiers (read-only — do not mutate).
func (d *Dispatcher) Notifiers() []Notifier { return d.notifiers }

// Dispatch routes events to every registered notifier in parallel. The
// returned slice has one entry per notifier in registration order. A nil
// or empty events slice yields a result per notifier with Sent=0; this is
// useful as a no-op probe.
//
// Synthetic events bypass the MinLevel filter so test events are always
// delivered regardless of channel thresholds.
func (d *Dispatcher) Dispatch(ctx context.Context, events []Event) []DispatchResult {
	if d == nil || len(d.notifiers) == 0 {
		return nil
	}
	results := make([]DispatchResult, len(d.notifiers))
	var wg sync.WaitGroup
	for i, n := range d.notifiers {
		i, n := i, n
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = d.dispatchOne(ctx, n, events)
		}()
	}
	wg.Wait()
	return results
}

func (d *Dispatcher) dispatchOne(ctx context.Context, n Notifier, events []Event) DispatchResult {
	r := DispatchResult{Notifier: n.Name()}
	min := n.MinLevel()
	filtered := make([]Event, 0, len(events))
	for _, e := range events {
		if e.Synthetic {
			filtered = append(filtered, e)
			continue
		}
		if e.Risk < min {
			r.Skipped++
			continue
		}
		filtered = append(filtered, e)
	}
	r.Sent = len(filtered)
	if len(filtered) == 0 {
		return r
	}

	callCtx := ctx
	if d.timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	if err := n.Notify(callCtx, filtered); err != nil {
		r.Err = err
		if d.logger != nil {
			// We log the error message but never any URL the channel might
			// have included — it's the implementation's responsibility to
			// keep secrets out of returned errors.
			d.logger.Warn("notifier failed", "channel", n.Name(), "err", err)
		}
		return r
	}
	if d.logger != nil {
		d.logger.Info("notifier dispatched", "channel", n.Name(), "events", len(filtered))
	}
	return r
}

// ErrEmptyURL is returned by webhook constructors when the URL is missing.
// Channels should refuse to construct rather than silently skipping later.
var ErrEmptyURL = errors.New("notifier: webhook URL is required")

// titleFor renders the headline for an event suitable for any channel's
// "subject" field. Centralised so all channels phrase the same situation
// the same way.
func titleFor(e Event) string {
	prefix := "Update available"
	switch e.Risk {
	case types.RiskBreaking:
		prefix = "BREAKING update blocked"
	case types.RiskReview:
		prefix = "Review needed"
	case types.RiskSafe:
		prefix = "Update available"
	}
	switch e.Action {
	case types.ActionAutoUpdated:
		prefix = "Auto-updated"
	case types.ActionRolledBack:
		prefix = "ROLLBACK"
	case types.ActionBlocked:
		prefix = "BREAKING update blocked"
	case types.ActionNeedsReview:
		prefix = "Review needed"
	}
	if e.Synthetic {
		prefix = "[test] " + prefix
	}
	return fmt.Sprintf("%s: %s", prefix, e.Container)
}
