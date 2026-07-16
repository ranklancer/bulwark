package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ranklancer/bulwark/pkg/types"
)

func TestNewDiscord_RequiresURL(t *testing.T) {
	if _, err := NewDiscord("", types.RiskReview, ""); err == nil {
		t.Fatal("expected ErrEmptyURL")
	}
}

func TestDiscord_NotifySendsEmbed(t *testing.T) {
	var bodyBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := NewDiscord(srv.URL, types.RiskReview, "test")
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(context.Background(), []Event{{
		Container:      "sonarr",
		Image:          "lscr.io/linuxserver/sonarr:4.0.10-ls45",
		ComposeProject: "media",
		From:           "4.0.10-ls45",
		To:             "4.0.10-ls46",
		Risk:           types.RiskBreaking,
		Kind:           types.ChangeMajor,
		Rationale:      "Major version bump.",
		ReleaseURL:     "https://example.com/notes",
	}})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	embeds, ok := payload["embeds"].([]any)
	if !ok || len(embeds) != 1 {
		t.Fatalf("expected 1 embed, got %+v", payload)
	}
	embed := embeds[0].(map[string]any)
	if embed["url"] != "https://example.com/notes" {
		t.Errorf("url = %v", embed["url"])
	}
	if int(embed["color"].(float64)) != colorBreaking {
		t.Errorf("color = %v, want %d (breaking red)", embed["color"], colorBreaking)
	}
	body := string(bodyBytes)
	for _, want := range []string{"sonarr", "lscr.io/linuxserver/sonarr", "Major version bump", "media"} {
		if !strings.Contains(body, want) {
			t.Errorf("payload missing %q\n%s", want, body)
		}
	}
}

func TestDiscord_ChunksEmbedsWhenMoreThan10(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, _ := NewDiscord(srv.URL, types.RiskReview, "test")
	events := make([]Event, 23)
	for i := range events {
		events[i] = Event{Container: "x", Risk: types.RiskReview}
	}
	if err := n.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	// 23 embeds → 3 messages (10 + 10 + 3)
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("HTTP calls = %d, want 3", got)
	}
}

func TestDiscord_NonOKLeaksNoURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad payload"))
	}))
	defer srv.Close()

	n, _ := NewDiscord(srv.URL, types.RiskReview, "test")
	err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error leaks URL: %v", err)
	}
}

func TestColorFor(t *testing.T) {
	if colorFor(types.RiskBreaking) != colorBreaking {
		t.Error("breaking color")
	}
	if colorFor(types.RiskReview) != colorReview {
		t.Error("review color")
	}
	if colorFor(types.RiskSafe) != colorSafe {
		t.Error("safe color")
	}
	if colorFor(types.RiskUnknown) != colorUnknown {
		t.Error("unknown color")
	}
}
