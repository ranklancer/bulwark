package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		want   map[string]string
	}{
		{
			in:     `Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:library/nginx:pull"`,
			scheme: "bearer",
			want: map[string]string{
				"realm":   "https://auth.example.com/token",
				"service": "registry.example.com",
				"scope":   "repository:library/nginx:pull",
			},
		},
		{
			in:     `Bearer realm=https://auth.example.com/token,service=registry.example.com`,
			scheme: "bearer",
			want: map[string]string{
				"realm":   "https://auth.example.com/token",
				"service": "registry.example.com",
			},
		},
		{
			in:     `Basic realm="registry"`,
			scheme: "basic",
			want:   map[string]string{"realm": "registry"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			scheme, got := parseChallenge(tc.in)
			if scheme != tc.scheme {
				t.Errorf("scheme = %q, want %q", scheme, tc.scheme)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("param %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestResolve_AnonymousRegistry(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v2/library/nginx/manifests/1.25") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Docker-Content-Digest", "sha256:fakedigest123")
		w.WriteHeader(http.StatusOK)
	}))
	defer registry.Close()

	c := New()
	c.BaseURL = registry.URL

	digest, err := c.Resolve(context.Background(), Reference{
		Registry:   "registry.example.com",
		Repository: "library/nginx",
		Tag:        "1.25",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if digest != "sha256:fakedigest123" {
		t.Errorf("digest = %q", digest)
	}
}

func TestResolve_BearerChallenge(t *testing.T) {
	var (
		manifestRequests int32
		tokenRequests    int32
	)

	mux := http.NewServeMux()

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenRequests, 1)
		if r.URL.Query().Get("service") != "registry.example.com" {
			t.Errorf("missing/wrong service param: %s", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.Query().Get("scope"), "library/nginx") {
			t.Errorf("missing/wrong scope param: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"token":"abc.def.ghi"}`))
	})

	// Manifest endpoint
	mux.HandleFunc("/v2/library/nginx/manifests/1.25", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&manifestRequests, 1)
		auth := r.Header.Get("Authorization")
		if n == 1 {
			if auth != "" {
				t.Errorf("first request should be unauthenticated, got %q", auth)
			}
			realm := "http://" + r.Host + "/token"
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="registry.example.com",scope="repository:library/nginx:pull"`, realm))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if auth != "Bearer abc.def.ghi" {
			t.Errorf("retry missing/wrong Authorization: %q", auth)
		}
		w.Header().Set("Docker-Content-Digest", "sha256:authedDigest")
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New()
	c.BaseURL = srv.URL

	ref := Reference{Registry: "registry.example.com", Repository: "library/nginx", Tag: "1.25"}
	digest, err := c.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if digest != "sha256:authedDigest" {
		t.Errorf("digest = %q", digest)
	}
	if atomic.LoadInt32(&manifestRequests) != 2 {
		t.Errorf("expected 2 manifest requests (challenge + retry), got %d", manifestRequests)
	}
	if atomic.LoadInt32(&tokenRequests) != 1 {
		t.Errorf("expected 1 token request, got %d", tokenRequests)
	}

	// Second Resolve call should reuse the cached token (no second token fetch).
	if _, err := c.Resolve(context.Background(), ref); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if got := atomic.LoadInt32(&tokenRequests); got != 1 {
		t.Errorf("token request count after second Resolve = %d, want 1 (cached)", got)
	}
}

func TestResolve_PinnedDigestSkipsNetwork(t *testing.T) {
	c := New()
	c.HTTPClient = &http.Client{Transport: failingRoundTripper{t}}
	got, err := c.Resolve(context.Background(), Reference{
		Registry:   "registry.example.com",
		Repository: "library/nginx",
		Digest:     "sha256:pinned",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "sha256:pinned" {
		t.Errorf("digest = %q", got)
	}
}

func TestResolve_RequiresTagOrDigest(t *testing.T) {
	c := New()
	if _, err := c.Resolve(context.Background(), Reference{Registry: "x", Repository: "y"}); err == nil {
		t.Fatal("expected error for ref with neither tag nor digest")
	}
}

type failingRoundTripper struct{ t *testing.T }

func (f failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Fatal("network request unexpectedly attempted")
	return nil, nil
}
