package api

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestServer_HealthEndpoints(t *testing.T) {
	srv := NewServer(":0", nil, nil, nil, nil, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.HTTPServer.Addr = listener.Addr().String()
	go func() { _ = srv.HTTPServer.Serve(listener) }()
	defer srv.HTTPServer.Close()

	// Wait briefly for the goroutine to take ownership of the listener.
	time.Sleep(20 * time.Millisecond)

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get("http://" + listener.Addr().String() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s status = %d", path, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), `"status":"ok"`) {
			t.Errorf("%s body = %q", path, body)
		}
	}
}

func TestServer_Run_GracefulShutdownOnContextCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv := NewServer(addr, nil, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.Run(ctx, 2*time.Second)
	}()

	// Wait until the server is responding.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancel")
	}

	// After shutdown, requests should fail.
	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		t.Error("server still accepting requests after shutdown")
	}
}

func TestServer_DIUNRouteOnlyMountedWhenHandlerNonNil(t *testing.T) {
	// nil DIUN handler → POST returns 404 (path not mounted)
	srv := NewServer("127.0.0.1:0", nil, nil, nil, nil, nil)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	srv.HTTPServer.Addr = listener.Addr().String()
	go func() { _ = srv.HTTPServer.Serve(listener) }()
	defer srv.HTTPServer.Close()
	time.Sleep(20 * time.Millisecond)

	resp, err := http.Post("http://"+listener.Addr().String()+"/api/v1/webhooks/diun",
		"application/json", strings.NewReader(`{"image":"x:1"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (DIUN handler is nil)", resp.StatusCode)
	}
}

// TestMountUIRoutes_VanillaWhenReactPlaceholder asserts the
// pre-React-build mode: only "/" exists, and it serves the vanilla
// dashboard. No "/legacy/" mount, no "/assets/" mount.
func TestMountUIRoutes_VanillaWhenReactPlaceholder(t *testing.T) {
	legacy := []byte(`<!doctype html><title>vanilla</title>`)

	mux := http.NewServeMux()
	mountUIRoutes(mux, legacy, nil, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "vanilla") {
		t.Errorf("GET / served unexpected body: %q", body)
	}
	if got := res.Header.Get("Content-Security-Policy"); got == "" {
		t.Error("missing CSP header on legacy index")
	}

	// No /legacy/ mount in placeholder mode.
	resLegacy, err := http.Get(srv.URL + "/legacy/")
	if err != nil {
		t.Fatal(err)
	}
	resLegacy.Body.Close()
	if resLegacy.StatusCode != http.StatusNotFound {
		t.Errorf("GET /legacy/ in placeholder mode = %d, want 404", resLegacy.StatusCode)
	}
}

// TestMountUIRoutes_ReactBuiltMountsBoth asserts the post-React-build
// mode: "/" → React, "/legacy/" → vanilla, "/assets/<file>" → static
// asset with immutable cache headers.
func TestMountUIRoutes_ReactBuiltMountsBoth(t *testing.T) {
	legacy := []byte(`<!doctype html><title>vanilla</title>`)
	reactIndex := []byte(`<!doctype html><title>react</title>`)
	reactFS := fstest.MapFS{
		"index.html":         &fstest.MapFile{Data: reactIndex},
		"assets/app-abc.js":  &fstest.MapFile{Data: []byte(`console.log("ok");`)},
		"assets/app-abc.css": &fstest.MapFile{Data: []byte(`body{color:red}`)},
	}

	mux := http.NewServeMux()
	mountUIRoutes(mux, legacy, fs.FS(reactFS), reactIndex)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// "/" serves React, not vanilla.
	rootRes, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	rootBody, _ := io.ReadAll(rootRes.Body)
	rootRes.Body.Close()
	if !strings.Contains(string(rootBody), "react") {
		t.Errorf("GET / body = %q, want React index", rootBody)
	}
	if strings.Contains(string(rootBody), "vanilla") {
		t.Error("GET / leaked legacy content into React mount")
	}

	// "/legacy/" serves vanilla.
	legacyRes, err := http.Get(srv.URL + "/legacy/")
	if err != nil {
		t.Fatal(err)
	}
	legacyBody, _ := io.ReadAll(legacyRes.Body)
	legacyRes.Body.Close()
	if !strings.Contains(string(legacyBody), "vanilla") {
		t.Errorf("GET /legacy/ body = %q", legacyBody)
	}

	// "/assets/app-abc.js" serves the bundled asset with immutable
	// cache headers.
	assetRes, err := http.Get(srv.URL + "/assets/app-abc.js")
	if err != nil {
		t.Fatal(err)
	}
	assetBody, _ := io.ReadAll(assetRes.Body)
	assetRes.Body.Close()
	if assetRes.StatusCode != http.StatusOK {
		t.Errorf("GET /assets/app-abc.js = %d", assetRes.StatusCode)
	}
	if !strings.Contains(string(assetBody), "console.log") {
		t.Errorf("asset body = %q", assetBody)
	}
	if cc := assetRes.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("asset Cache-Control = %q, want immutable", cc)
	}
}
