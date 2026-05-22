package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestNewNtfy_Validation(t *testing.T) {
	cases := []struct {
		name    string
		server  string
		topic   string
		wantErr string
	}{
		{"empty server", "", "topic", "webhook URL is required"},
		{"bad scheme", "ftp://ntfy.sh", "topic", "must be http or https"},
		{"missing host", "https://", "topic", "must include a host"},
		{"empty topic", "https://ntfy.sh", "", "topic is required"},
		{"topic with slash", "https://ntfy.sh", "bad/topic", "must not contain slashes"},
		{"topic with space", "https://ntfy.sh", "bad topic", "must not contain slashes or whitespace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewNtfy(c.server, c.topic, "", 0, "")
			if err == nil {
				t.Fatalf("expected error %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestNewNtfy_TrimsTrailingSlash(t *testing.T) {
	n, err := NewNtfy("https://ntfy.example.com/", "alerts", "", types.RiskReview, "")
	if err != nil {
		t.Fatal(err)
	}
	if n.ServerURL != "https://ntfy.example.com" {
		t.Errorf("ServerURL = %q, want trailing slash trimmed", n.ServerURL)
	}
}

func TestNtfy_Notify_PostsExpectedShape(t *testing.T) {
	var (
		mu       sync.Mutex
		payloads []ntfyMessage
		headers  []http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg ntfyMessage
		if err := json.Unmarshal(body, &msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		payloads = append(payloads, msg)
		headers = append(headers, r.Header.Clone())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	n, err := NewNtfy(srv.URL, "bulwark-test", "tok_abc", types.RiskReview, "ntfy")
	if err != nil {
		t.Fatal(err)
	}
	n.HTTPClient = srv.Client()

	events := []Event{
		{
			Container:  "sonarr",
			Image:      "lscr.io/.../sonarr:1.2.3",
			From:       "1.2.2",
			To:         "1.2.3",
			Risk:       types.RiskReview,
			Kind:       types.ChangeMinor,
			Rationale:  "minor release",
			ReleaseURL: "https://example.com/release/1.2.3",
		},
		{
			Container: "auth",
			Image:     "ghcr.io/owner/auth:5.0.0",
			Risk:      types.RiskBreaking,
			Kind:      types.ChangeMajor,
		},
	}
	if err := n.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("got %d POSTs, want 2", len(payloads))
	}
	first := payloads[0]
	if first.Topic != "bulwark-test" {
		t.Errorf("topic = %q", first.Topic)
	}
	if !strings.Contains(first.Title, "sonarr") {
		t.Errorf("title %q missing container name", first.Title)
	}
	if first.Priority != 4 {
		t.Errorf("REVIEW priority = %d, want 4", first.Priority)
	}
	if len(first.Tags) != 1 || first.Tags[0] != "warning" {
		t.Errorf("REVIEW tags = %v, want [warning]", first.Tags)
	}
	if first.Click != "https://example.com/release/1.2.3" {
		t.Errorf("click = %q, want release URL", first.Click)
	}
	if !strings.Contains(first.Message, "sonarr:1.2.3") {
		t.Errorf("message %q missing image", first.Message)
	}
	if !strings.Contains(first.Message, "1.2.2 → 1.2.3") {
		t.Errorf("message %q missing version transition", first.Message)
	}
	// Authorization header set when token configured.
	if got := headers[0].Get("Authorization"); got != "Bearer tok_abc" {
		t.Errorf("Authorization header = %q, want 'Bearer tok_abc'", got)
	}
	// Second event is BREAKING → priority 5 + rotating_light tag.
	if payloads[1].Priority != 5 {
		t.Errorf("BREAKING priority = %d, want 5", payloads[1].Priority)
	}
	if len(payloads[1].Tags) != 1 || payloads[1].Tags[0] != "rotating_light" {
		t.Errorf("BREAKING tags = %v, want [rotating_light]", payloads[1].Tags)
	}
}

func TestNtfy_Notify_NoTokenOmitsAuthHeader(t *testing.T) {
	var captured http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	n, _ := NewNtfy(srv.URL, "public-topic", "", types.RiskSafe, "ntfy")
	n.HTTPClient = srv.Client()
	if err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskSafe}}); err != nil {
		t.Fatal(err)
	}
	if got := captured.Get("Authorization"); got != "" {
		t.Errorf("expected no Authorization header when token unset; got %q", got)
	}
}

func TestNtfy_Notify_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "topic forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	n, _ := NewNtfy(srv.URL, "alerts", "", types.RiskReview, "ntfy")
	n.HTTPClient = srv.Client()
	err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}})
	if err == nil {
		t.Fatal("expected error from 403")
	}
	if !strings.Contains(err.Error(), "topic forbidden") {
		t.Errorf("error %q does not surface body snippet", err.Error())
	}
}

func TestNtfy_SyntheticEventTags(t *testing.T) {
	got := ntfyTagsFor(Event{Synthetic: true, Risk: types.RiskReview})
	if len(got) != 1 || got[0] != "test_tube" {
		t.Errorf("synthetic tags = %v, want [test_tube]", got)
	}
}

func TestNtfy_PriorityForActionWins(t *testing.T) {
	// Rolled-back at REVIEW risk should still be priority 5.
	got := ntfyPriorityFor(Event{Risk: types.RiskReview, Action: types.ActionRolledBack})
	if got != 5 {
		t.Errorf("rollback priority = %d, want 5", got)
	}
}
