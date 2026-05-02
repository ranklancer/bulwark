package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

type serveTestRegistry struct {
	digests map[string]string
}

func (s *serveTestRegistry) Resolve(_ context.Context, ref registry.Reference) (string, error) {
	if d, ok := s.digests[ref.String()]; ok {
		return d, nil
	}
	return "", errors.New("not stubbed")
}

type serveTestDocker struct{}

func (s *serveTestDocker) ListContainers(_ context.Context, _ bool) ([]docker.Container, error) {
	return nil, nil
}
func (s *serveTestDocker) InspectImage(_ context.Context, _ string) (*docker.ImageInspect, error) {
	return nil, nil
}

type serveTestNotifier struct {
	calls int32
}

func (n *serveTestNotifier) Name() string              { return "test" }
func (n *serveTestNotifier) MinLevel() types.RiskLevel { return types.RiskSafe }
func (n *serveTestNotifier) Notify(_ context.Context, _ []notifier.Event) error {
	atomic.AddInt32(&n.calls, 1)
	return nil
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitForReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not become ready within 3s")
}

func TestServe_LifecycleAndDIUNDispatch(t *testing.T) {
	addr := freePort(t)
	rec := &serveTestNotifier{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deps := serveDeps{
		Docker:    &serveTestDocker{},
		Registry:  &serveTestRegistry{digests: map[string]string{"ghcr.io/owner/app:1.0": "sha256:reg"}},
		Notifiers: []notifier.Notifier{rec},
		Ctx:       ctx,
	}

	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- cmdServeWith(
			[]string{"--listen", addr, "--no-docker", "--diun-token", ""},
			&stdout, &stderr,
			deps,
		)
	}()
	defer func() { <-done }()

	waitForReady(t, addr)

	resp, err := http.Post(
		"http://"+addr+"/api/v1/webhooks/diun",
		"application/json",
		strings.NewReader(`{"status":"new","image":"ghcr.io/owner/app:1.0","digest":"sha256:reg"}`),
	)
	if err != nil {
		t.Fatalf("POST /diun: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DIUN response %d: %s", resp.StatusCode, body)
	}

	// Allow the dispatcher's goroutine to land its mark before we cancel.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("notifier calls = %d, want 1; body: %s", got, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down within 5s of context cancel")
	}

	// Drain done channel so the deferred receive doesn't block.
	done = make(chan error, 1)
	close(done)
}

func TestServe_RejectsUnauthorizedDIUN(t *testing.T) {
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rec := &serveTestNotifier{}
	deps := serveDeps{
		Registry:  &serveTestRegistry{},
		Notifiers: []notifier.Notifier{rec},
		Ctx:       ctx,
	}

	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- cmdServeWith(
			[]string{"--listen", addr, "--no-docker", "--diun-token", "secret-xyz"},
			&stdout, &stderr,
			deps,
		)
	}()

	waitForReady(t, addr)

	// No auth header → 401.
	resp, err := http.Post("http://"+addr+"/api/v1/webhooks/diun",
		"application/json", strings.NewReader(`{"image":"ghcr.io/owner/app:1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	// With correct bearer → 200.
	req, _ := http.NewRequest("POST", "http://"+addr+"/api/v1/webhooks/diun",
		strings.NewReader(`{"image":"ghcr.io/owner/app:1.0"}`))
	req.Header.Set("Authorization", "Bearer secret-xyz")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authed status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func TestServe_RejectsUnknownArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := cmdServe([]string{"unexpected"}, &stdout, &stderr); err == nil {
		t.Error("expected error for unexpected positional arg")
	}
}
