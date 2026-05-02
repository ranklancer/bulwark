package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestNewSlack_RequiresURL(t *testing.T) {
	if _, err := NewSlack("", "", types.RiskReview, ""); err == nil {
		t.Fatal("expected ErrEmptyURL")
	}
}

func TestSlack_NotifySendsBlockKit(t *testing.T) {
	var (
		gotMethod string
		gotBody   []byte
		gotCT     string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := NewSlack(srv.URL, "", types.RiskReview, "test")
	if err != nil {
		t.Fatalf("NewSlack: %v", err)
	}
	err = n.Notify(context.Background(), []Event{{
		Container: "sonarr",
		Image:     "lscr.io/linuxserver/sonarr",
		From:      "4.0.10-ls45",
		To:        "4.0.10-ls46",
		Risk:      types.RiskSafe,
		Kind:      types.ChangeLSIORebuild,
		Rationale: "LinuxServer.io rebuild — base image refreshed.",
		ReleaseURL: "https://example.com/notes",
	}})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q", gotMethod)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}

	var payload map[string]any
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	blocks, ok := payload["blocks"].([]any)
	if !ok || len(blocks) == 0 {
		t.Fatalf("blocks missing or wrong type: %+v", payload)
	}
	body := string(gotBody)
	for _, want := range []string{"sonarr", "4.0.10-ls45", "Release notes", "lsio-rebuild", "SAFE"} {
		if !strings.Contains(body, want) {
			t.Errorf("payload missing %q\n%s", want, body)
		}
	}
}

func TestSlack_NotifyChannelOverride(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, _ := NewSlack(srv.URL, "#bulwark-alerts", types.RiskReview, "test")
	if err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}}); err != nil {
		t.Fatal(err)
	}
	if got["channel"] != "#bulwark-alerts" {
		t.Errorf("channel = %v, want #bulwark-alerts", got["channel"])
	}
}

func TestSlack_Notify_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream broke"))
	}))
	defer srv.Close()

	n, _ := NewSlack(srv.URL, "", types.RiskReview, "test")
	err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}})
	if err == nil {
		t.Fatal("expected error on non-2xx")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "upstream broke") {
		t.Errorf("error should include status and snippet: %v", err)
	}
	// The webhook URL must NOT appear verbatim in the error.
	if strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error leaks webhook URL: %v", err)
	}
}

func TestSlack_DigestMessageForMultipleEvents(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, _ := NewSlack(srv.URL, "", types.RiskReview, "test")
	events := []Event{
		{Container: "sonarr", Risk: types.RiskReview},
		{Container: "radarr", Risk: types.RiskBreaking},
	}
	if err := n.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	blocks, _ := got["blocks"].([]any)
	if len(blocks) < 2 {
		t.Fatalf("expected multi-block digest, got %d blocks", len(blocks))
	}
	// First block is the header — should mention 2 updates for digest mode.
	header := blocks[0].(map[string]any)
	headerText := header["text"].(map[string]any)["text"].(string)
	if !strings.Contains(headerText, "2 update") {
		t.Errorf("header should mention 2 updates: %q", headerText)
	}
}

func TestScrubURL(t *testing.T) {
	secret := "https://hooks.example.com/services/AB/CD/secret"
	err := errFromString("Post " + secret + ": connection refused")
	scrubbed := scrubURL(err, secret)
	if strings.Contains(scrubbed.Error(), secret) {
		t.Errorf("scrubURL leaked secret: %v", scrubbed)
	}
	if !strings.Contains(scrubbed.Error(), "<redacted>") {
		t.Errorf("scrubURL should substitute <redacted>: %v", scrubbed)
	}
}

type stringErr string

func (s stringErr) Error() string { return string(s) }

func errFromString(s string) error { return stringErr(s) }
