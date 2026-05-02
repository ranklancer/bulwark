package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func newTestClient(handler http.Handler) (*Client, *httptest.Server) {
	srv := httptest.NewServer(handler)
	c := New("")
	c.HTTPClient = srv.Client()
	c.BaseURL = srv.URL
	return c, srv
}

func TestPullImage_Success(t *testing.T) {
	var gotPath string
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		fmt.Fprintln(w, `{"status":"Pulling from library/nginx"}`)
		fmt.Fprintln(w, `{"status":"Downloading","progressDetail":{"current":1,"total":2}}`)
		fmt.Fprintln(w, `{"status":"Pull complete"}`)
	}))
	defer srv.Close()

	if err := c.PullImage(context.Background(), "lscr.io/linuxserver/sonarr:4.0.10-ls45"); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if !strings.HasPrefix(gotPath, "/images/create?") {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotPath, "fromImage=lscr.io%2Flinuxserver%2Fsonarr") {
		t.Errorf("fromImage missing/wrong: %q", gotPath)
	}
	if !strings.Contains(gotPath, "tag=4.0.10-ls45") {
		t.Errorf("tag missing/wrong: %q", gotPath)
	}
}

func TestPullImage_StreamError(t *testing.T) {
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"status":"Pulling"}`)
		fmt.Fprintln(w, `{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown: ..."}`)
	}))
	defer srv.Close()

	err := c.PullImage(context.Background(), "lscr.io/linuxserver/sonarr:nonexistent")
	if err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Errorf("expected manifest-unknown error, got %v", err)
	}
}

func TestPullImage_NonOKStatus(t *testing.T) {
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"daemon out of memory"}`))
	}))
	defer srv.Close()
	err := c.PullImage(context.Background(), "ghcr.io/owner/app:1.0")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500-mentioning error, got %v", err)
	}
}

func TestSplitImageTag(t *testing.T) {
	cases := []struct {
		in        string
		fromImage string
		tag       string
	}{
		{"nginx", "nginx", "latest"},
		{"nginx:1.25", "nginx", "1.25"},
		{"lscr.io/linuxserver/sonarr:4.0.10-ls45", "lscr.io/linuxserver/sonarr", "4.0.10-ls45"},
		{"registry.example.com:5000/app:v1", "registry.example.com:5000/app", "v1"},
		{"nginx@sha256:abc", "nginx@sha256:abc", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			from, tag := splitImageTag(tc.in)
			if from != tc.fromImage || tag != tc.tag {
				t.Errorf("splitImageTag(%q) = (%q, %q), want (%q, %q)",
					tc.in, from, tag, tc.fromImage, tc.tag)
			}
		})
	}
}

func TestInspectContainer_FullShape(t *testing.T) {
	body := `{
		"Id": "abc123",
		"Name": "/sonarr",
		"Image": "sha256:imgid",
		"Config": {"Image":"lscr.io/linuxserver/sonarr:4.0.10-ls45","Env":["TZ=UTC"],"Cmd":["sonarr"],"Labels":{"x":"y"}},
		"HostConfig": {"Binds":["/data:/data"],"NetworkMode":"bridge"},
		"NetworkSettings": {"Networks":{"media":{"IPAddress":"203.0.113.5"}}},
		"State": {"Running": true, "Health": {"Status": "healthy"}}
	}`
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := c.InspectContainer(context.Background(), "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("got nil for 200")
	}
	if got.ID != "abc123" || got.Name != "/sonarr" || got.NameWithoutSlash() != "sonarr" {
		t.Errorf("name fields: %+v", got)
	}
	if !got.Running || got.Health != HealthHealthy {
		t.Errorf("state fields: running=%v health=%v", got.Running, got.Health)
	}
	if got.ImageRef != "lscr.io/linuxserver/sonarr:4.0.10-ls45" {
		t.Errorf("ImageRef = %q", got.ImageRef)
	}
	// RawMessage round-trip preserves the JSON.
	var cfg map[string]any
	if err := json.Unmarshal(got.Config, &cfg); err != nil {
		t.Fatalf("config raw not valid JSON: %v", err)
	}
	if cfg["Image"] != "lscr.io/linuxserver/sonarr:4.0.10-ls45" {
		t.Errorf("config.Image lost in RawMessage: %v", cfg)
	}
}

func TestInspectContainer_NotFoundReturnsNil(t *testing.T) {
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, err := c.InspectContainer(context.Background(), "nope")
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestStopStartRemoveRename_HitTheRightEndpoints(t *testing.T) {
	var calls atomic.Int32
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/stop"):
			if r.URL.Query().Get("t") != "30" {
				t.Errorf("stop t = %q, want 30", r.URL.Query().Get("t"))
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/rename"):
			if r.URL.Query().Get("name") != "newname" {
				t.Errorf("rename name = %q", r.URL.Query().Get("name"))
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "DELETE":
			if r.URL.Query().Get("force") != "true" {
				t.Errorf("delete force = %q", r.URL.Query().Get("force"))
			}
			if r.URL.Query().Get("v") != "false" {
				t.Errorf("delete v = %q (must be false to preserve volumes)", r.URL.Query().Get("v"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	if err := c.StopContainer(context.Background(), "x", 30); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if err := c.StartContainer(context.Background(), "x"); err != nil {
		t.Errorf("Start: %v", err)
	}
	if err := c.RenameContainer(context.Background(), "x", "newname"); err != nil {
		t.Errorf("Rename: %v", err)
	}
	if err := c.RemoveContainer(context.Background(), "x", true); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if calls.Load() != 4 {
		t.Errorf("expected 4 calls, got %d", calls.Load())
	}
}

func TestStop_AlreadyStoppedIs304_TreatedAsSuccess(t *testing.T) {
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	if err := c.StopContainer(context.Background(), "x", 0); err != nil {
		t.Errorf("304 should be success: %v", err)
	}
}

func TestCreateContainer_PassesThroughConfigAndReturnsID(t *testing.T) {
	c, srv := newTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/create" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("name") != "sonarr" {
			t.Errorf("name = %q", r.URL.Query().Get("name"))
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		// Image is in the top-level Config keys (not nested).
		if got["Image"] != "lscr.io/linuxserver/sonarr:4.0.11-ls47" {
			t.Errorf("Image = %v, want new tag", got["Image"])
		}
		// HostConfig should be present.
		if _, ok := got["HostConfig"]; !ok {
			t.Errorf("missing HostConfig in body: %s", body)
		}
		// NetworkingConfig should be present and contain EndpointsConfig.
		nc, ok := got["NetworkingConfig"].(map[string]any)
		if !ok {
			t.Fatalf("NetworkingConfig missing/wrong type: %v", got["NetworkingConfig"])
		}
		if _, ok := nc["EndpointsConfig"]; !ok {
			t.Errorf("EndpointsConfig missing")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"newid","Warnings":null}`))
	}))
	defer srv.Close()

	insp := &ContainerInspect{
		Config:          json.RawMessage(`{"Image":"lscr.io/linuxserver/sonarr:4.0.10-ls45","Env":["TZ=UTC"]}`),
		HostConfig:      json.RawMessage(`{"Binds":["/data:/data"]}`),
		NetworkSettings: json.RawMessage(`{"Networks":{"media":{"IPAddress":"203.0.113.5"}}}`),
	}
	cfg, err := NewCreateConfigFromInspect(insp, "lscr.io/linuxserver/sonarr:4.0.11-ls47")
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.CreateContainer(context.Background(), "sonarr", cfg)
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if id != "newid" {
		t.Errorf("returned ID = %q", id)
	}
}

func TestCreateContainer_RejectsEmptyName(t *testing.T) {
	c := New("")
	if _, err := c.CreateContainer(context.Background(), "", CreateContainerConfig{}); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestNewCreateConfigFromInspect_NoNetworksProducesNilNetCfg(t *testing.T) {
	insp := &ContainerInspect{
		Config:          json.RawMessage(`{"Image":"x:1"}`),
		HostConfig:      json.RawMessage(`{}`),
		NetworkSettings: json.RawMessage(`{"Networks":null}`),
	}
	cfg, err := NewCreateConfigFromInspect(insp, "x:2")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetworkingConfig) != 0 {
		t.Errorf("NetworkingConfig = %s, want empty when Networks is null", cfg.NetworkingConfig)
	}
}
