package api

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
)

func TestEventBus_PublishToMultipleSubscribers(t *testing.T) {
	bus := NewEventBus()
	id1, ch1 := bus.subscribe()
	id2, ch2 := bus.subscribe()
	defer bus.unsubscribe(id1)
	defer bus.unsubscribe(id2)

	bus.Publish(Event{Type: EventScanCompleted, Detail: "first"})
	bus.Publish(Event{Type: EventDecisionRecorded, Container: "alpha"})

	collect := func(ch <-chan Event, n int) []Event {
		t.Helper()
		out := make([]Event, 0, n)
		for i := 0; i < n; i++ {
			select {
			case e := <-ch:
				out = append(out, e)
			case <-time.After(time.Second):
				t.Fatalf("timeout waiting for event %d", i)
			}
		}
		return out
	}
	for _, ch := range []<-chan Event{ch1, ch2} {
		got := collect(ch, 2)
		if got[0].Type != EventScanCompleted || got[1].Type != EventDecisionRecorded {
			t.Errorf("subscriber got %+v", got)
		}
	}
}

func TestEventBus_NilReceiverNoOps(t *testing.T) {
	var bus *EventBus
	bus.Publish(Event{Type: EventScanCompleted}) // must not panic
	if got := bus.SubscriberCount(); got != 0 {
		t.Errorf("nil receiver SubscriberCount = %d", got)
	}
}

func TestEventBus_DropsOnSlowSubscriber(t *testing.T) {
	bus := NewEventBus()
	id, ch := bus.subscribe()
	defer bus.unsubscribe(id)

	// Buffer is 16; publish 100 to ensure overflow drops happen.
	for i := 0; i < 100; i++ {
		bus.Publish(Event{Type: EventScanCompleted})
	}
	// We should not have 100 in the channel — the buffer caps at 16.
	if len(ch) > 16 {
		t.Errorf("buffer capacity exceeded: len=%d", len(ch))
	}
}

func TestEventBus_UnsubscribeStopsDelivery(t *testing.T) {
	bus := NewEventBus()
	id, ch := bus.subscribe()
	bus.unsubscribe(id)

	// Channel should be closed.
	_, ok := <-ch
	if ok {
		t.Errorf("unsubscribe didn't close the channel")
	}
}

// TestStateAPI_EventsStream end-to-end: subscribe via SSE, publish via
// the bus, verify the client receives the formatted event line. This
// exercises auth + handler + bus + heartbeat in one shot.
func TestStateAPI_EventsStream(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	bus := NewEventBus()
	h := &StateHandler{
		Store:  st,
		Auth:   AnonymousAuth{},
		Events: bus,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Open the SSE connection.
	resp, err := http.Get(srv.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Errorf("Content-Type = %q", got)
	}

	// Wait for the subscriber to register before publishing.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && bus.SubscriberCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if bus.SubscriberCount() == 0 {
		t.Fatal("subscriber never registered")
	}

	bus.Publish(Event{Type: EventScanCompleted, ScanID: "scan-abc", Detail: "ok"})

	// Read until we see our event line. The hello "comment line" comes
	// first, then the event.
	scanner := bufio.NewScanner(resp.Body)
	var sawEvent atomic.Bool
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "scan.completed") || strings.Contains(line, "scan-abc") {
				sawEvent.Store(true)
				return
			}
		}
	}()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sawEvent.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawEvent.Load() {
		t.Errorf("scan.completed event not observed on the stream")
	}
}

func TestStateAPI_EventsRouteOmittedWhenBusNil(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	h := &StateHandler{Store: st, Auth: AnonymousAuth{}}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
}
