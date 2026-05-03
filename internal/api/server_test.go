package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
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
