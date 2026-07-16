package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/pkg/types"
)

func TestGeneric_RequiresURL(t *testing.T) {
	if _, err := NewGeneric("", "", nil, types.RiskReview, ""); err == nil {
		t.Fatal("expected ErrEmptyURL")
	}
}

func TestGeneric_DefaultsToPOST(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n, _ := NewGeneric(srv.URL, "", nil, types.RiskReview, "test")
	if err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
}

func TestGeneric_HonoursMethodAndHeaders(t *testing.T) {
	var (
		gotMethod string
		gotAuth   string
		gotXAPI   string
		gotCT     string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotXAPI = r.Header.Get("X-API-Key")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n, _ := NewGeneric(srv.URL, "PUT",
		map[string]string{"Authorization": "Bearer abc", "X-API-Key": "xyz"},
		types.RiskReview, "test")
	if err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "PUT" {
		t.Errorf("method = %q", gotMethod)
	}
	if gotAuth != "Bearer abc" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotXAPI != "xyz" {
		t.Errorf("X-API-Key = %q", gotXAPI)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
}

func TestGeneric_PayloadShape(t *testing.T) {
	var bodyBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n, _ := NewGeneric(srv.URL, "POST", nil, types.RiskReview, "test")
	err := n.Notify(context.Background(), []Event{{
		Container: "sonarr",
		Image:     "lscr.io/linuxserver/sonarr",
		Risk:      types.RiskReview,
		Kind:      types.ChangeMinor,
		From:      "1.0.0",
		To:        "1.1.0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Source string `json:"source"`
		Events []map[string]any
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		t.Fatalf("decode: %v\n%s", err, bodyBytes)
	}
	if payload.Source != "bulwark" {
		t.Errorf("source = %q", payload.Source)
	}
	if len(payload.Events) != 1 {
		t.Fatalf("events len = %d", len(payload.Events))
	}
	e := payload.Events[0]
	if e["risk"] != "review" {
		t.Errorf("risk = %v", e["risk"])
	}
	if e["kind"] != "minor" {
		t.Errorf("kind = %v", e["kind"])
	}
	if e["from"] != "1.0.0" || e["to"] != "1.1.0" {
		t.Errorf("from/to = %v / %v", e["from"], e["to"])
	}
	// Empty fields should be omitted.
	if _, present := e["release_url"]; present {
		t.Errorf("empty release_url leaked into payload: %v", e["release_url"])
	}
}

func TestGeneric_HeaderMapDefensiveCopy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Confirm the test mutation didn't propagate.
		if r.Header.Get("Authorization") != "Bearer original" {
			t.Errorf("Authorization = %q (mutation leaked)", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	hdrs := map[string]string{"Authorization": "Bearer original"}
	n, _ := NewGeneric(srv.URL, "POST", hdrs, types.RiskReview, "test")
	hdrs["Authorization"] = "Bearer mutated"
	if err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}}); err != nil {
		t.Fatal(err)
	}
}

func TestGeneric_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	n, _ := NewGeneric(srv.URL, "POST", nil, types.RiskReview, "test")
	err := n.Notify(context.Background(), []Event{{Container: "x", Risk: types.RiskReview}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should include status: %v", err)
	}
}
