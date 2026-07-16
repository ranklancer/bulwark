package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListContainers_FiltersAndParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("all") != "true" {
			t.Errorf("all query missing/wrong: %s", r.URL.RawQuery)
		}
		fmt.Fprintln(w, `[
			{
				"Id": "abc123",
				"Names": ["/sonarr"],
				"Image": "lscr.io/linuxserver/sonarr:4.0.10-ls45",
				"ImageID": "sha256:imgid",
				"State": "running",
				"Status": "Up 2 hours",
				"Created": 1700000000,
				"Labels": {"com.docker.compose.project": "media", "bulwark.enable": "true"}
			},
			{
				"Id": "def456",
				"Names": ["/redis-db"],
				"Image": "redis:7",
				"ImageID": "sha256:imgid2",
				"State": "exited",
				"Status": "Exited (0) 3 days ago",
				"Created": 1690000000,
				"Labels": null
			}
		]`)
	}))
	defer srv.Close()

	c := New("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL

	containers, err := c.ListContainers(context.Background(), true)
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(containers))
	}
	if containers[0].Name != "sonarr" {
		t.Errorf("Name[0] = %q, want sonarr (leading slash stripped)", containers[0].Name)
	}
	if containers[0].ComposeProject() != "media" {
		t.Errorf("ComposeProject[0] = %q", containers[0].ComposeProject())
	}
	if containers[1].Labels == nil {
		t.Error("Labels[1] is nil; should be empty map")
	}
}

func TestInspectImage_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/images/") || !strings.HasSuffix(r.URL.Path, "/json") {
			t.Errorf("path = %s", r.URL.Path)
		}
		fmt.Fprintln(w, `{
			"Id": "sha256:imgid",
			"RepoTags": ["lscr.io/linuxserver/sonarr:4.0.10-ls45"],
			"RepoDigests": ["lscr.io/linuxserver/sonarr@sha256:abcdef"]
		}`)
	}))
	defer srv.Close()

	c := New("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL

	got, err := c.InspectImage(context.Background(), "sha256:imgid")
	if err != nil {
		t.Fatalf("InspectImage: %v", err)
	}
	if got == nil {
		t.Fatal("InspectImage returned nil for a 200 response")
	}
	if d := got.DigestFor("lscr.io/linuxserver/sonarr"); d != "sha256:abcdef" {
		t.Errorf("DigestFor = %q, want sha256:abcdef", d)
	}
	if d := got.DigestFor("registry.example.com/other"); d != "" {
		t.Errorf("DigestFor unknown repo should be empty, got %q", d)
	}
}

func TestInspectImage_NotFoundReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL

	got, err := c.InspectImage(context.Background(), "sha256:nope")
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil result for 404, got %+v", got)
	}
}

func TestPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestNormalizeNetError(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"dial unix /var/run/docker.sock: connect: permission denied", "permission denied"},
		{"dial unix /var/run/docker.sock: connect: no such file or directory", "socket not found"},
		{"some other error", "some other error"},
	}
	for _, tc := range cases {
		err := normalizeNetError(&fakeError{tc.in})
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("normalizeNetError(%q) = %v, want substring %q", tc.in, err, tc.want)
		}
	}
}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }
