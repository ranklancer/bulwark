package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// --- test doubles -----------------------------------------------------------

type fakeRegistry struct {
	digests map[string]string
}

func (f *fakeRegistry) Resolve(_ context.Context, ref registry.Reference) (string, error) {
	if d, ok := f.digests[ref.String()]; ok {
		return d, nil
	}
	return "", errors.New("digest not stubbed: " + ref.String())
}

type fakeDocker struct {
	containers []docker.Container
	images     map[string]*docker.ImageInspect
}

func (f *fakeDocker) ListContainers(_ context.Context, _ bool) ([]docker.Container, error) {
	return f.containers, nil
}
func (f *fakeDocker) InspectImage(_ context.Context, id string) (*docker.ImageInspect, error) {
	return f.images[id], nil
}

type recordingNotifier struct {
	name  string
	min   types.RiskLevel
	calls int32
	got   []notifier.Event
}

func (r *recordingNotifier) Name() string              { return r.name }
func (r *recordingNotifier) MinLevel() types.RiskLevel { return r.min }
func (r *recordingNotifier) Notify(_ context.Context, e []notifier.Event) error {
	atomic.AddInt32(&r.calls, 1)
	r.got = append(r.got, e...)
	return nil
}

// minimalHandler builds a DIUNHandler with sane defaults for these tests.
func minimalHandler(t *testing.T, opts ...func(*DIUNHandler)) *DIUNHandler {
	t.Helper()
	h := &DIUNHandler{
		Classifier: classifier.New(classifier.DefaultConfig()),
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

func postJSON(handler http.Handler, body any) *httptest.ResponseRecorder {
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// --- happy path -------------------------------------------------------------

func TestDIUN_HappyPath_LSIO_RebuildClassifiesAsSafe(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "sonarr",
			Image: "lscr.io/linuxserver/sonarr:4.0.10-ls45", ImageID: "sha256:l1",
			Labels: map[string]string{"com.docker.compose.project": "media"},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:olddigest"}},
		},
	}
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.Docker = fd
		h.Registry = &fakeRegistry{}
		h.Notifier = notifier.NewDispatcher([]notifier.Notifier{rec}, nil, time.Second)
	})

	resp := postJSON(h, map[string]any{
		"status": "new",
		"image":  "lscr.io/linuxserver/sonarr:4.0.10-ls45",
		"digest": "sha256:newdigest",
	})

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", resp.Code, resp.Body.String())
	}
	var body diunResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Received || !body.ContainerMatched || body.ContainerName != "sonarr" {
		t.Errorf("response = %+v, want matched sonarr", body)
	}
	if !body.ClassificationPerformed || body.Level != "safe" {
		t.Errorf("classification: level=%q kind=%q (LSIO rebuild should be safe)", body.Level, body.Kind)
	}
	if body.Notifications != 1 {
		t.Errorf("notifications = %d, want 1", body.Notifications)
	}
	if atomic.LoadInt32(&rec.calls) != 1 {
		t.Errorf("notifier calls = %d, want 1", rec.calls)
	}
	// Compose project propagated.
	if rec.got[0].ComposeProject != "media" {
		t.Errorf("ComposeProject = %q", rec.got[0].ComposeProject)
	}
}

// --- malformed input --------------------------------------------------------

func TestDIUN_RejectsNonPOST(t *testing.T) {
	h := minimalHandler(t)
	req := httptest.NewRequest("GET", "/api/v1/webhooks/diun", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestDIUN_RejectsMalformedJSON(t *testing.T) {
	h := minimalHandler(t)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestDIUN_RejectsMissingImage(t *testing.T) {
	h := minimalHandler(t)
	resp := postJSON(h, map[string]any{"status": "new"})
	if resp.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "image") {
		t.Errorf("expected 'image' in error body, got %s", resp.Body.String())
	}
}

// --- auth -------------------------------------------------------------------

func TestDIUN_AuthRequired_Missing(t *testing.T) {
	h := minimalHandler(t, func(h *DIUNHandler) { h.Token = "secret-xyz" })
	resp := postJSON(h, map[string]any{"image": "x:1"})
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.Code)
	}
}

func TestDIUN_AuthRequired_Wrong(t *testing.T) {
	h := minimalHandler(t, func(h *DIUNHandler) { h.Token = "secret-xyz" })
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun",
		strings.NewReader(`{"image":"ghcr.io/owner/app:1.0"}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestDIUN_AuthAcceptsBearer(t *testing.T) {
	h := minimalHandler(t, func(h *DIUNHandler) { h.Token = "secret-xyz" })
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun",
		strings.NewReader(`{"image":"ghcr.io/owner/app:1.0"}`))
	req.Header.Set("Authorization", "Bearer secret-xyz")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDIUN_AuthAcceptsCustomHeader(t *testing.T) {
	h := minimalHandler(t, func(h *DIUNHandler) { h.Token = "secret-xyz" })
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun",
		strings.NewReader(`{"image":"ghcr.io/owner/app:1.0"}`))
	req.Header.Set("X-Bulwark-Token", "secret-xyz")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// --- container matching -----------------------------------------------------

func TestDIUN_NoMatchingContainer_StillReturns200(t *testing.T) {
	fd := &fakeDocker{containers: []docker.Container{{
		ID: "x1", Name: "other", Image: "ghcr.io/different/app:2",
	}}}
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.Docker = fd
		h.Registry = &fakeRegistry{digests: map[string]string{
			"ghcr.io/owner/app:1.0": "sha256:fromregistry",
		}}
	})
	resp := postJSON(h, map[string]any{"image": "ghcr.io/owner/app:1.0"})
	if resp.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.Code)
	}
	var body diunResponse
	_ = json.Unmarshal(resp.Body.Bytes(), &body)
	if body.ContainerMatched {
		t.Errorf("ContainerMatched should be false")
	}
}

func TestDIUN_NoDocker_NoNotifier_OnlyClassifies(t *testing.T) {
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.Registry = &fakeRegistry{digests: map[string]string{
			"ghcr.io/owner/app:1.0": "sha256:reg",
		}}
	})
	resp := postJSON(h, map[string]any{
		"image":  "ghcr.io/owner/app:1.0",
		"digest": "sha256:reg",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d", resp.Code)
	}
	var body diunResponse
	_ = json.Unmarshal(resp.Body.Bytes(), &body)
	if !body.ClassificationPerformed {
		t.Error("classification should still happen without Docker/Notifier")
	}
}

// --- dedup behaviour --------------------------------------------------------

func TestDIUN_DedupSilencesRepeatNotifications(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	rec := &recordingNotifier{name: "test", min: types.RiskSafe}
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "sonarr",
			Image: "lscr.io/linuxserver/sonarr:4.0.10-ls45", ImageID: "sha256:l1",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
		},
	}
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.Docker = fd
		h.Registry = &fakeRegistry{}
		h.Notifier = notifier.NewDispatcher([]notifier.Notifier{rec}, nil, time.Second)
		h.Store = st
		h.DedupTTL = 24 * time.Hour
		h.Now = func() time.Time { return now }
	})

	body := map[string]any{
		"image":  "lscr.io/linuxserver/sonarr:4.0.10-ls45",
		"digest": "sha256:new",
	}

	resp := postJSON(h, body)
	if resp.Code != http.StatusOK {
		t.Fatalf("first call: status %d body %s", resp.Code, resp.Body.String())
	}
	if atomic.LoadInt32(&rec.calls) != 1 {
		t.Fatalf("first call calls = %d, want 1", rec.calls)
	}

	// Second call within TTL → silenced.
	h.Now = func() time.Time { return now.Add(time.Hour) }
	resp2 := postJSON(h, body)
	var body2 diunResponse
	_ = json.Unmarshal(resp2.Body.Bytes(), &body2)
	if body2.Silenced != 1 {
		t.Errorf("Silenced = %d, want 1", body2.Silenced)
	}
	if got := atomic.LoadInt32(&rec.calls); got != 1 {
		t.Errorf("notifier called again despite dedup: calls=%d", got)
	}

	// Third call past TTL → notify again.
	h.Now = func() time.Time { return now.Add(25 * time.Hour) }
	postJSON(h, body)
	if got := atomic.LoadInt32(&rec.calls); got != 2 {
		t.Errorf("after-TTL notifier calls = %d, want 2", got)
	}
}

// --- body size limit --------------------------------------------------------

func TestDIUN_HMAC_AcceptsSignedRequest(t *testing.T) {
	when := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	scheme := &HMACScheme{Secret: []byte("topsecret"), MaxSkew: time.Minute, Now: func() time.Time { return when }}
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.HMAC = scheme
	})

	body := []byte(`{"image":"ghcr.io/owner/app:1.0"}`)
	ts, sig := scheme.Sign(body, when)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bulwark-Timestamp", ts)
	req.Header.Set("X-Bulwark-Signature", sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDIUN_HMAC_RejectsReplayWithStaleTimestamp(t *testing.T) {
	signedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	verifyAt := signedAt.Add(10 * time.Minute) // past 5-min skew
	scheme := &HMACScheme{Secret: []byte("topsecret"), MaxSkew: 5 * time.Minute,
		Now: func() time.Time { return verifyAt }}
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.HMAC = scheme
	})

	body := []byte(`{"image":"x:1"}`)
	ts, sig := scheme.Sign(body, signedAt)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bulwark-Timestamp", ts)
	req.Header.Set("X-Bulwark-Signature", sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (stale timestamp)", rec.Code)
	}
}

func TestDIUN_HMAC_RejectsTamperedBody(t *testing.T) {
	when := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	scheme := &HMACScheme{Secret: []byte("topsecret"), MaxSkew: time.Minute, Now: func() time.Time { return when }}
	h := minimalHandler(t, func(h *DIUNHandler) {
		h.HMAC = scheme
	})

	original := []byte(`{"image":"x:1"}`)
	ts, sig := scheme.Sign(original, when)
	tampered := []byte(`{"image":"y:2"}`)

	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun", bytes.NewReader(tampered))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bulwark-Timestamp", ts)
	req.Header.Set("X-Bulwark-Signature", sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (tampered body)", rec.Code)
	}
}

func TestDIUN_HMAC_DisabledByDefault(t *testing.T) {
	// No HMAC configured → signature headers ignored, request succeeds
	// based on bearer (or anonymous when no token is set either).
	h := minimalHandler(t)
	resp := postJSON(h, map[string]any{"image": "x:1"})
	if resp.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (HMAC disabled)", resp.Code)
	}
}

func TestDIUN_RejectsOversizedBody(t *testing.T) {
	h := minimalHandler(t)
	huge := strings.Repeat("x", maxDIUNBodyBytes+1024)
	req := httptest.NewRequest("POST", "/api/v1/webhooks/diun",
		strings.NewReader(`{"image":"ghcr.io/x/y:1","note":"`+huge+`"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (oversized body)", rec.Code)
	}
}
