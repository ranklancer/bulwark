package notifier

import (
	"sync"

	"github.com/ranklancer/bulwark/pkg/types"
)

// DigestBuffer holds events that should be coalesced into a single
// scheduled digest dispatch rather than being sent immediately. Safe for
// concurrent use.
//
// Persistence is intentionally NOT provided here — buffered SAFE/REVIEW
// events that survive a daemon restart are tolerable to lose because
// the next scan re-detects them. If we ever add an SLA on "every
// notification reaches its channel exactly once", revisit and persist
// to a JSONL file alongside the rest of the store data.
type DigestBuffer struct {
	mu     sync.Mutex
	events []Event
}

// NewDigestBuffer returns an empty buffer.
func NewDigestBuffer() *DigestBuffer {
	return &DigestBuffer{}
}

// Add appends events to the buffer. Caller must NOT mutate the slice
// after handing it over.
func (b *DigestBuffer) Add(events []Event) {
	if b == nil || len(events) == 0 {
		return
	}
	b.mu.Lock()
	b.events = append(b.events, events...)
	b.mu.Unlock()
}

// Drain returns all buffered events and resets the buffer to empty in a
// single atomic step. Returns nil when the buffer is empty.
func (b *DigestBuffer) Drain() []Event {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) == 0 {
		return nil
	}
	out := b.events
	b.events = nil
	return out
}

// Len reports the current number of buffered events.
func (b *DigestBuffer) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// IsUrgent reports whether an event must be dispatched immediately even
// when digest mode is active. Urgency policy:
//
//   - BREAKING risk: operators expect to know about manual-intervention
//     items in real time; rolling them into a digest defeats the purpose.
//   - Action == ActionRolledBack: a rollback means an apply attempt
//     went sideways — needs eyes now.
//   - Action == ActionStackSkipped: knock-on consequence of a
//     stack-mate failure; same urgency as a rollback.
//   - Synthetic: `bulwark notify-test` events bypass digest queueing
//     so operators can verify their channels without waiting for the
//     next digest tick.
func IsUrgent(e Event) bool {
	if e.Synthetic {
		return true
	}
	if e.Risk == types.RiskBreaking {
		return true
	}
	if e.Action == types.ActionRolledBack || e.Action == types.ActionStackSkipped {
		return true
	}
	return false
}

// SplitForDigest partitions a batch of events into the urgent ones (to
// dispatch immediately) and the non-urgent ones (to buffer for the next
// digest flush). Order within each output slice mirrors the input.
func SplitForDigest(events []Event) (urgent, buffered []Event) {
	for _, e := range events {
		if IsUrgent(e) {
			urgent = append(urgent, e)
		} else {
			buffered = append(buffered, e)
		}
	}
	return urgent, buffered
}
