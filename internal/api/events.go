package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Event types — stable strings the dashboard switches on. Treat as
// part of the public API contract: renaming breaks SPA bundles
// shipping with older binaries during a rolling deployment.
const (
	EventScanCompleted        = "scan.completed"
	EventDecisionRecorded     = "decision.recorded"
	EventDecisionForgot       = "decision.forgot"
	EventApplySuccess         = "apply.success"
	EventApplyFailed          = "apply.failed"
	EventApplyRolledBack      = "apply.rolled_back"
	EventApplyStackSkipped    = "apply.stack_skipped"
	EventApplyBlocked         = "apply.blocked"
	EventApplyWouldBlock      = "apply.would_block"
	EventApplyBreakGlass      = "apply.break_glass"
	EventNotificationsCleared = "notifications.cleared"
	EventNotifierConfig       = "notifier.config_changed"
	EventConfigUpdated        = "config.updated"
)

// Event is one item streamed to subscribed dashboard clients. Time is
// always server-side (UTC) so reconnecting clients can correlate with
// audit-log entries; Type is one of the constants above.
type Event struct {
	Type      string         `json:"type"`
	Time      time.Time      `json:"time"`
	Container string         `json:"container,omitempty"`
	Image     string         `json:"image,omitempty"`
	ScanID    string         `json:"scan_id,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// EventBus is a tiny in-memory pub/sub: each subscriber gets its own
// buffered channel; slow subscribers (a stalled browser tab) are
// dropped rather than back-pressuring the publisher. The whole
// daemon shares one bus.
//
// We deliberately don't persist events. The client can re-fetch the
// state-of-the-world endpoints (e.g. /api/v1/scans?limit=20) after
// reconnect; dropped events are at most a "you missed a scan
// notification" inconvenience, not data loss.
type EventBus struct {
	mu     sync.Mutex
	subs   map[int]chan Event
	nextID int
}

// NewEventBus returns a fresh bus. Safe to share across goroutines.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[int]chan Event)}
}

// subscribe registers a buffered channel for one client. The returned
// id is opaque; pass it back into unsubscribe() at disconnect.
//
// Buffer size of 16 is enough headroom for typical scan + apply
// bursts (a 50-container stack apply produces ~50 events over a few
// seconds); subscribers that fall further behind get the slow-client
// drop treatment.
func (b *EventBus) subscribe() (int, <-chan Event) {
	if b == nil {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	ch := make(chan Event, 16)
	b.subs[id] = ch
	return id, ch
}

func (b *EventBus) unsubscribe(id int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subs[id]; ok {
		close(ch)
		delete(b.subs, id)
	}
}

// Publish broadcasts e to every current subscriber. Time is filled in
// when zero so callers don't have to remember. Non-blocking: a
// subscriber whose channel is full simply doesn't get this message.
//
// Nil receiver is a no-op so the publishing call sites can be written
// unconditionally.
func (b *EventBus) Publish(e Event) {
	if b == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
			// Drop on overflow — see EventBus docstring.
		}
	}
}

// SubscriberCount reports the current open-stream count. Useful for
// metrics + tests.
func (b *EventBus) SubscriberCount() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// streamEvents serves an SSE stream over r. Format: standard
// "event:" + "data:" lines, periodic ":\n" comments to keep proxies
// from idling out the connection.
//
// Closes when:
//   - The HTTP response writer no longer accepts writes (browser
//     closed the page).
//   - The context is cancelled.
//   - The bus's subscriber channel is closed (server shutdown).
func streamEvents(w http.ResponseWriter, r *http.Request, bus *EventBus) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable nginx-style buffering when the daemon sits behind a
	// reverse proxy — most proxies honour this header for SSE.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	id, ch := bus.subscribe()
	defer bus.unsubscribe(id)

	// Send a hello so the EventSource client knows the connection
	// is live.
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// streamHandler is the HTTP entrypoint registered on
// GET /api/v1/events. It bridges the request into streamEvents, which
// owns the lifecycle. The caller (StateHandler) wraps this in
// authMiddleware so unauthenticated streams never start.
func streamHandler(bus *EventBus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bus == nil {
			http.NotFound(w, r)
			return
		}
		streamEvents(w, r, bus)
	}
}
