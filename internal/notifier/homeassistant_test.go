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

	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/pkg/types"
)

// haCall records one observed POST to a fake HA server.
type haCall struct {
	Service string
	Auth    string
	Title   string
	Message string
	Body    map[string]any
}

func newHAServer(t *testing.T, status int) (*httptest.Server, *[]haCall, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	calls := make([]haCall, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/api/services/notify/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		mu.Lock()
		calls = append(calls, haCall{
			Service: strings.TrimPrefix(r.URL.Path, prefix),
			Auth:    r.Header.Get("Authorization"),
			Title:   asString(parsed["title"]),
			Message: asString(parsed["message"]),
			Body:    parsed,
		})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &mu
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestNewHomeAssistant_RequiresURLAndToken(t *testing.T) {
	if _, err := NewHomeAssistant(config.HAConfig{Token: "x"}, ""); err == nil {
		t.Error("missing url should fail")
	}
	if _, err := NewHomeAssistant(config.HAConfig{URL: "https://hass.example.com"}, ""); err == nil {
		t.Error("missing token should fail")
	}
	if _, err := NewHomeAssistant(config.HAConfig{URL: "not-a-url", Token: "x"}, ""); err == nil {
		t.Error("invalid url should fail")
	}
}

func TestNewHomeAssistant_RequiresAtLeastOneLevelEnabled(t *testing.T) {
	c := config.HAConfig{URL: "https://hass.example.com", Token: "x"}
	if _, err := NewHomeAssistant(c, ""); err == nil {
		t.Error("HA with no level configured should fail")
	}
	c.Safe.Persistent = true
	if _, err := NewHomeAssistant(c, ""); err != nil {
		t.Errorf("HA with persistent on safe should construct: %v", err)
	}
}

func TestHomeAssistant_PersistentAndPush(t *testing.T) {
	srv, calls, mu := newHAServer(t, http.StatusOK)
	c := config.HAConfig{
		URL:    srv.URL,
		Token:  "test-token",
		Review: config.HANotifyLevel{Persistent: true, Push: true},
	}
	n, err := NewHomeAssistant(c, "")
	if err != nil {
		t.Fatal(err)
	}

	err = n.Notify(context.Background(), []Event{{
		Container: "demo",
		Image:     "ghcr.io/owner/app:1.2.3",
		Risk:      types.RiskReview,
		From:      "1.2.2", To: "1.2.3",
	}})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 2 {
		t.Fatalf("calls = %d, want 2 (persistent + push)", len(*calls))
	}
	got := map[string]bool{}
	for _, c := range *calls {
		got[c.Service] = true
		if c.Auth != "Bearer test-token" {
			t.Errorf("auth header %q", c.Auth)
		}
		if !strings.Contains(c.Title, "demo") {
			t.Errorf("title missing container: %q", c.Title)
		}
		if !strings.Contains(c.Message, "ghcr.io/owner/app:1.2.3") {
			t.Errorf("message missing image: %q", c.Message)
		}
	}
	if !got["persistent_notification"] || !got["notify"] {
		t.Errorf("missing service: %+v", got)
	}
}

func TestHomeAssistant_CriticalIOSFlag(t *testing.T) {
	srv, calls, mu := newHAServer(t, http.StatusOK)
	c := config.HAConfig{
		URL:      srv.URL,
		Token:    "t",
		Breaking: config.HANotifyLevel{Push: true, Critical: true},
	}
	n, err := NewHomeAssistant(c, "")
	if err != nil {
		t.Fatal(err)
	}

	if err := n.Notify(context.Background(), []Event{{
		Container: "x", Risk: types.RiskBreaking,
	}}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 1 || (*calls)[0].Service != "notify" {
		t.Fatalf("calls = %+v", *calls)
	}
	data, _ := (*calls)[0].Body["data"].(map[string]any)
	push, _ := data["push"].(map[string]any)
	sound, _ := push["sound"].(map[string]any)
	if sound["critical"] == nil {
		t.Errorf("critical flag missing: %+v", (*calls)[0].Body)
	}
}

func TestHomeAssistant_RollbackUsesRollbackConfig(t *testing.T) {
	// Original Risk is SAFE, but Action=ActionRolledBack should drive
	// us to the Rollback HANotifyLevel (Push enabled below).
	srv, calls, mu := newHAServer(t, http.StatusOK)
	c := config.HAConfig{
		URL:      srv.URL,
		Token:    "t",
		Safe:     config.HANotifyLevel{}, // OFF for safe
		Rollback: config.HANotifyLevel{Push: true},
	}
	n, err := NewHomeAssistant(c, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), []Event{{
		Container: "x", Risk: types.RiskSafe, Action: types.ActionRolledBack,
	}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 1 {
		t.Fatalf("rolled-back SAFE event should fire Rollback channel; calls = %d", len(*calls))
	}
}

func TestHomeAssistant_NonMatchingLevelIsSilent(t *testing.T) {
	srv, calls, mu := newHAServer(t, http.StatusOK)
	c := config.HAConfig{
		URL:      srv.URL,
		Token:    "t",
		Breaking: config.HANotifyLevel{Push: true},
	}
	n, err := NewHomeAssistant(c, "")
	if err != nil {
		t.Fatal(err)
	}
	// SAFE event but only Breaking is configured — no HTTP at all.
	if err := n.Notify(context.Background(), []Event{{
		Container: "x", Risk: types.RiskSafe,
	}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 0 {
		t.Errorf("SAFE event with only Breaking configured should be silent; calls = %d", len(*calls))
	}
}

func TestHomeAssistant_NonOKReturnsError(t *testing.T) {
	srv, _, _ := newHAServer(t, http.StatusUnauthorized)
	c := config.HAConfig{
		URL:    srv.URL,
		Token:  "bad",
		Review: config.HANotifyLevel{Persistent: true},
	}
	n, err := NewHomeAssistant(c, "")
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}})
	if err == nil {
		t.Fatal("401 should bubble as error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err missing status %q", err)
	}
}
