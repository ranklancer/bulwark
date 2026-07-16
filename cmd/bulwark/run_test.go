package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/pkg/types"
)

// runTestRegistry returns the digest the daemon will see in each scan cycle.
// We mutate it between assertions to simulate "the registry just published a
// new digest" so the daemon's second scan emits a notification.
type runTestRegistry struct {
	digestForTag map[string]string
}

func (r *runTestRegistry) Resolve(_ context.Context, ref registry.Reference) (string, error) {
	if d, ok := r.digestForTag[ref.String()]; ok {
		return d, nil
	}
	return "", errors.New("not stubbed: " + ref.String())
}

// runTestDocker returns a fixed container set on every ListContainers call
// (the daemon expects the listing to refresh each cycle, so we re-use the
// same fixture intentionally).
type runTestDocker struct {
	containers []docker.Container
	images     map[string]*docker.ImageInspect
	listCalls  int32
}

func (d *runTestDocker) ListContainers(_ context.Context, _ bool) ([]docker.Container, error) {
	atomic.AddInt32(&d.listCalls, 1)
	return d.containers, nil
}
func (d *runTestDocker) InspectImage(_ context.Context, id string) (*docker.ImageInspect, error) {
	return d.images[id], nil
}

type runRecorder struct {
	mu    *bytes.Buffer
	calls int32
}

func (r *runRecorder) Name() string              { return "test" }
func (r *runRecorder) MinLevel() types.RiskLevel { return types.RiskSafe }
func (r *runRecorder) Notify(_ context.Context, e []notifier.Event) error {
	atomic.AddInt32(&r.calls, 1)
	return nil
}

func TestRun_PeriodicScanFiresAndDispatches(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dockerStub := &runTestDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "sonarr",
			Image:   "lscr.io/linuxserver/sonarr:4.0.10-ls45",
			ImageID: "sha256:local",
			Labels:  map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:local": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
		},
	}
	regStub := &runTestRegistry{digestForTag: map[string]string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45": "sha256:new",
	}}
	rec := &runRecorder{}

	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deps := runDeps{
		Docker:    dockerStub,
		Registry:  regStub,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Ctx:       ctx,
	}

	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- cmdRunWith(
			[]string{
				"--listen", addr,
				"--scan-interval", "30ms",
				"--no-fetch-notes",
			},
			&stdout, &stderr,
			deps,
		)
	}()

	// Wait for the HTTP server to be ready.
	waitForReady(t, addr)

	// At least one scan should have happened by now (RunImmediately=true).
	// Allow a short grace window for the dispatcher's goroutine to land
	// its mark.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&rec.calls) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&rec.calls); got < 1 {
		t.Fatalf("notifier calls = %d, want >=1 after initial scan", got)
	}

	// At least one Docker ListContainers call should have happened.
	if got := atomic.LoadInt32(&dockerStub.listCalls); got < 1 {
		t.Errorf("ListContainers calls = %d, want >=1", got)
	}

	// Verify the daemon also serves the DIUN webhook.
	resp, err := http.Post(
		"http://"+addr+"/api/v1/webhooks/diun",
		"application/json",
		strings.NewReader(`{"image":"ghcr.io/owner/app:1.0","digest":"sha256:irrelevant"}`),
	)
	if err != nil {
		t.Fatalf("DIUN POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DIUN status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down within 5s of context cancel")
	}

	// Scan history should contain at least one record.
	scans, err := st.ListScans(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) < 1 {
		t.Errorf("history has %d records, want >=1", len(scans))
	}
}

func TestRun_DedupSilencesRepeatScans(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	dockerStub := &runTestDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "sonarr",
			Image:   "lscr.io/linuxserver/sonarr:4.0.10-ls45",
			ImageID: "sha256:local",
			Labels:  map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:local": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
		},
	}
	regStub := &runTestRegistry{digestForTag: map[string]string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45": "sha256:new",
	}}
	rec := &runRecorder{}

	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Frozen time so dedup TTL is deterministic.
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	deps := runDeps{
		Docker:    dockerStub,
		Registry:  regStub,
		Notifiers: []notifier.Notifier{rec},
		Store:     st,
		Ctx:       ctx,
		Now:       func() time.Time { return now },
	}

	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- cmdRunWith(
			[]string{
				"--listen", addr,
				"--scan-interval", "20ms",
				"--no-fetch-notes",
				"--dedup-ttl", "24h",
			},
			&stdout, &stderr,
			deps,
		)
	}()
	waitForReady(t, addr)

	// Allow plenty of cycles to fire.
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	// Multiple scan cycles ran, but Now was frozen so dedup TTL silenced
	// every scan after the first. Notifier should have been called exactly
	// once.
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("notifier calls = %d, want 1 (dedup must silence repeats with frozen clock)", got)
	}
	if got := atomic.LoadInt32(&dockerStub.listCalls); got < 3 {
		t.Errorf("ListContainers calls = %d, want >=3 (multiple scan cycles)", got)
	}
}

func TestRun_NoDockerDisablesScheduler(t *testing.T) {
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deps := runDeps{Ctx: ctx}

	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- cmdRunWith(
			[]string{
				"--listen", addr,
				"--no-docker",
				"--scan-interval", "10ms",
				"--no-fetch-notes",
			},
			&stdout, &stderr,
			deps,
		)
	}()
	waitForReady(t, addr)

	// Confirm the HTTP server is still serving despite no scheduler running.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d body=%s", resp.StatusCode, body)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run did not shut down in --no-docker mode")
	}
}

func TestRun_RejectsInvalidCron(t *testing.T) {
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deps := runDeps{Ctx: ctx}
	var stdout, stderr bytes.Buffer
	err := cmdRunWith(
		[]string{"--listen", addr, "--cron", "not a cron expr", "--no-docker"},
		&stdout, &stderr,
		deps,
	)
	if err == nil {
		t.Fatal("expected error for invalid cron expression")
	}
	if !strings.Contains(err.Error(), "cron") {
		t.Errorf("error should mention cron: %v", err)
	}
}

func TestRun_RejectsUnknownArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := cmdRun([]string{"unexpected"}, &stdout, &stderr); err == nil {
		t.Error("expected error for unexpected positional arg")
	}
}

func TestRun_NoInitialScanFlagDelaysFirstCycle(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	dockerStub := &runTestDocker{}
	regStub := &runTestRegistry{}

	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deps := runDeps{
		Docker:   dockerStub,
		Registry: regStub,
		Store:    st,
		Ctx:      ctx,
	}

	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- cmdRunWith(
			[]string{
				"--listen", addr,
				"--scan-interval", "1h", // long enough we won't tick during the test
				"--no-initial-scan",
				"--no-fetch-notes",
			},
			&stdout, &stderr,
			deps,
		)
	}()
	waitForReady(t, addr)

	// Confirm no scan happened despite the daemon being ready.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&dockerStub.listCalls); got != 0 {
		t.Errorf("ListContainers calls = %d, want 0 (--no-initial-scan)", got)
	}
	cancel()
	<-done
}
