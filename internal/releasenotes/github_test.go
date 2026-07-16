package releasenotes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func newGitHubStub(t *testing.T, h http.HandlerFunc) (*GitHubClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewGitHubClient()
	c.BaseURL = srv.URL
	return c, srv
}

func TestFetchByTag_Success(t *testing.T) {
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/app/releases/tags/v1.2.3" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); !strings.Contains(got, "github+json") {
			t.Errorf("missing Accept: %s", got)
		}
		fmt.Fprintln(w, `{"html_url":"https://github.com/owner/app/releases/tag/v1.2.3","tag_name":"v1.2.3","body":"## What's changed\n- Bug fix"}`)
	})

	notes, err := c.FetchByTag(context.Background(), "owner", "app", "v1.2.3")
	if err != nil {
		t.Fatalf("FetchByTag: %v", err)
	}
	if notes == nil {
		t.Fatal("notes were nil")
	}
	if notes.Tag != "v1.2.3" {
		t.Errorf("tag = %q", notes.Tag)
	}
	if !strings.Contains(notes.Body, "Bug fix") {
		t.Errorf("body missing expected content: %q", notes.Body)
	}
}

func TestFetchByTag_NotFoundIsNotError(t *testing.T) {
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	notes, err := c.FetchByTag(context.Background(), "owner", "app", "v9.9.9")
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if notes != nil {
		t.Errorf("expected nil notes, got %+v", notes)
	}
}

func TestFetchByTag_DraftIsSkipped(t *testing.T) {
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"tag_name":"v1.2.3","body":"draft notes","draft":true}`)
	})
	notes, err := c.FetchByTag(context.Background(), "owner", "app", "v1.2.3")
	if err != nil {
		t.Fatalf("FetchByTag: %v", err)
	}
	if notes != nil {
		t.Errorf("draft release should be ignored, got %+v", notes)
	}
}

func TestFetchByTag_RateLimitedIsTypedError(t *testing.T) {
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.FetchByTag(context.Background(), "owner", "app", "v1.2.3")
	var rl *RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("expected RateLimitedError, got %v", err)
	}
}

func TestFetchByTag_AuthHeaderWhenTokenSet(t *testing.T) {
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s3cr3t" {
			t.Errorf("Authorization = %q", got)
		}
		fmt.Fprintln(w, `{"tag_name":"v1.2.3"}`)
	})
	c.Token = "s3cr3t"
	if _, err := c.FetchByTag(context.Background(), "owner", "app", "v1.2.3"); err != nil {
		t.Fatalf("FetchByTag: %v", err)
	}
}

func TestFetchAny_TriesCandidatesInOrder(t *testing.T) {
	var calls int32
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprintln(w, `{"tag_name":"4.0.10","body":"upstream notes","html_url":"https://example.com/x"}`)
	})

	notes, err := c.FetchAny(context.Background(), "owner", "app",
		[]string{"4.0.10-ls45", "v4.0.10-ls45", "4.0.10", "v4.0.10"})
	if err != nil {
		t.Fatalf("FetchAny: %v", err)
	}
	if notes == nil || notes.Tag != "4.0.10" {
		t.Fatalf("expected fallback to '4.0.10', got %+v", notes)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("call count = %d, want 3 (stops on first success)", got)
	}
}

func TestFetchAny_RateLimitShortCircuits(t *testing.T) {
	var calls int32
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := c.FetchAny(context.Background(), "owner", "app", []string{"a", "b", "c", "d"})
	var rl *RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("expected RateLimitedError, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("call count = %d, want 1 (rate-limit must short-circuit)", got)
	}
}

func TestFetchAny_AllNotFoundReturnsNil(t *testing.T) {
	c, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	notes, err := c.FetchAny(context.Background(), "owner", "app", []string{"a", "b"})
	if err != nil {
		t.Fatalf("FetchAny: %v", err)
	}
	if notes != nil {
		t.Errorf("expected nil notes, got %+v", notes)
	}
}
