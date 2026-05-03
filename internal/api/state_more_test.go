package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/snapshot"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

func newStateHandlerWithStore(t *testing.T) (*StateHandler, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &StateHandler{Store: st, Auth: AnonymousAuth{}}, st
}

func TestStateAPI_ListAudit(t *testing.T) {
	h, st := newStateHandlerWithStore(t)
	st.Audit(store.AuditEvent{Action: store.ActionApplied, Container: "alpha"})
	st.Audit(store.AuditEvent{Action: store.ActionRolledBack, Container: "bravo"})

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/audit?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var events []store.AuditEvent
	if err := json.NewDecoder(res.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	// Newest-first: rolled_back comes back before applied.
	if events[0].Action != store.ActionRolledBack {
		t.Errorf("events[0].Action = %q, want rolled_back", events[0].Action)
	}
}

func TestStateAPI_ListAudit_EmptyReturnsArrayNotNull(t *testing.T) {
	h, _ := newStateHandlerWithStore(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) == "null\n" || string(body) == "null" {
		t.Errorf("empty audit returned null literal: %q", body)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		t.Errorf("empty audit body = %q, want JSON array", body)
	}
}

func TestStateAPI_ListContainers(t *testing.T) {
	h, st := newStateHandlerWithStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	rec := store.ScanRecord{
		StartedAt:  now,
		FinishedAt: now.Add(time.Second),
		Summary:    store.ScanSummary{Total: 2, Pending: 1, Review: 1},
		Results: []store.ScanResultRecord{
			{ContainerID: "id-a", ContainerName: "alpha", Image: "ghcr.io/x/alpha:1.0",
				UpdateAvailable: true, Level: types.RiskReview, From: "1.0", To: "1.1"},
			{ContainerID: "id-b", ContainerName: "bravo", Image: "ghcr.io/x/bravo:1.0",
				UpdateAvailable: false, Level: types.RiskSafe},
		},
	}
	if _, err := st.RecordScan(rec); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/containers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var rows []containerView
	if err := json.NewDecoder(res.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].ContainerName != "alpha" {
		t.Errorf("rows[0].ContainerName = %q", rows[0].ContainerName)
	}
	if !rows[0].UpdateAvailable {
		t.Errorf("rows[0].UpdateAvailable = false; want true")
	}
	if rows[0].LastScanID == "" {
		t.Errorf("rows[0].LastScanID empty; should reference the scan")
	}
}

func TestStateAPI_ListContainers_NoScansYet(t *testing.T) {
	h, _ := newStateHandlerWithStore(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/containers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (empty list)", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		t.Errorf("body should be empty array; got %q", body)
	}
}

func TestStateAPI_ListNotifiers(t *testing.T) {
	rec := &recordingNotifier{name: "slack", min: types.RiskReview}
	dispatcher := notifier.NewDispatcher([]notifier.Notifier{rec}, nil, 0)
	h, _ := newStateHandlerWithStore(t)
	h.Dispatcher = dispatcher

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/notifiers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var rows []notifierView
	if err := json.NewDecoder(res.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Name != "slack" || rows[0].MinLevel != "review" {
		t.Errorf("rows[0] = %+v", rows[0])
	}
}

func TestStateAPI_TestNotifier_DeliversSyntheticEvent(t *testing.T) {
	rec := &recordingNotifier{name: "slack", min: types.RiskBreaking} // min above the synthetic event
	dispatcher := notifier.NewDispatcher([]notifier.Notifier{rec}, nil, 0)
	h, _ := newStateHandlerWithStore(t)
	h.Dispatcher = dispatcher

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/notifiers/slack/test", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status = %d, body = %s", res.StatusCode, body)
	}
	if len(rec.got) != 1 {
		t.Fatalf("notifier got %d events, want 1", len(rec.got))
	}
	// Synthetic flag must be set so internal MinLevel filters bypass.
	if !rec.got[0].Synthetic {
		t.Error("synthetic flag missing")
	}
	if rec.got[0].Risk != types.RiskReview {
		t.Errorf("event Risk = %v, want Review (default for tests)", rec.got[0].Risk)
	}
}

func TestStateAPI_TestNotifier_UnknownName404(t *testing.T) {
	dispatcher := notifier.NewDispatcher(nil, nil, 0)
	h, _ := newStateHandlerWithStore(t)
	h.Dispatcher = dispatcher

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/notifiers/nope/test", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
}

func TestStateAPI_NotifierRoutes_NotMountedWhenDispatcherNil(t *testing.T) {
	h, _ := newStateHandlerWithStore(t)
	// h.Dispatcher == nil
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, _ := http.Get(srv.URL + "/api/v1/notifiers")
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("listNotifiers without Dispatcher = %d, want 404", res.StatusCode)
	}
}

func TestStateAPI_GetConfig_RedactsSecrets(t *testing.T) {
	cfg := &config.Config{}
	cfg.API.DIUN.Token = "diun-bearer"
	cfg.API.DIUN.HMACSecret = "hmac-secret-value"
	cfg.API.Auth.Token = "api-bearer"
	cfg.Notifications.Slack.Enabled = true
	cfg.Notifications.Slack.WebhookURL = "https://hooks.slack.example.com/services/abc/xyz"
	cfg.Notifications.SMTP.Password = "smtp-pass"
	cfg.Notifications.HomeAssistant.Token = "ha-long-lived-token"

	h, _ := newStateHandlerWithStore(t)
	h.LoadedConfig = cfg

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	out := string(body)

	for _, secret := range []string{
		"diun-bearer",
		"hmac-secret-value",
		"api-bearer",
		"hooks.slack.example.com/services/abc/xyz",
		"smtp-pass",
		"ha-long-lived-token",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("response leaked secret %q", secret)
		}
	}
	// Sanity: the redaction marker must appear (otherwise the test
	// would also pass if the field were dropped entirely).
	if !strings.Contains(out, `"***"`) {
		t.Errorf("expected redaction marker '***' in response: %s", out)
	}
}

func TestStateAPI_GetConfigPolicies_NotMountedWhenConfigNil(t *testing.T) {
	h, _ := newStateHandlerWithStore(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res1, _ := http.Get(srv.URL + "/api/v1/config")
	res1.Body.Close()
	res2, _ := http.Get(srv.URL + "/api/v1/policies")
	res2.Body.Close()

	if res1.StatusCode != http.StatusNotFound || res2.StatusCode != http.StatusNotFound {
		t.Errorf("config/policies without LoadedConfig = %d/%d, want 404/404",
			res1.StatusCode, res2.StatusCode)
	}
}

func TestStateAPI_GetPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Classification.DefaultRisk = "review"
	h, _ := newStateHandlerWithStore(t)
	h.LoadedConfig = cfg

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/api/v1/policies")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["classifier"] == nil {
		t.Errorf("body missing classifier: %+v", body)
	}
	if _, ok := body["overrides"]; !ok {
		t.Errorf("body missing overrides: %+v", body)
	}
}

// fakeSnapshotBackend satisfies snapshot.Backend for tests. Unrelated
// to the cmd/bulwark fake — kept local to keep this test file
// self-contained.
type fakeSnapshotBackend struct {
	snaps []snapshot.Snapshot
	err   error
}

func (f *fakeSnapshotBackend) Name() string                                            { return "fake" }
func (f *fakeSnapshotBackend) Available(_ context.Context) bool                        { return true }
func (f *fakeSnapshotBackend) Snapshot(_ context.Context, _, _ string) (string, error) { return "", nil }
func (f *fakeSnapshotBackend) Restore(_ context.Context, _ string) error               { return nil }
func (f *fakeSnapshotBackend) Destroy(_ context.Context, _ string) error               { return nil }
func (f *fakeSnapshotBackend) List(_ context.Context, _ string) ([]snapshot.Snapshot, error) {
	return f.snaps, f.err
}

func TestStateAPI_ListSnapshots(t *testing.T) {
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	be := &fakeSnapshotBackend{
		snaps: []snapshot.Snapshot{
			{ID: "abc", Target: "/var/lib/sonarr", Label: "sonarr", CreatedAt: now},
		},
	}
	h, _ := newStateHandlerWithStore(t)
	h.SnapshotBackend = be

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Missing target → 400.
	res1, _ := http.Get(srv.URL + "/api/v1/snapshots")
	res1.Body.Close()
	if res1.StatusCode != http.StatusBadRequest {
		t.Errorf("missing target = %d, want 400", res1.StatusCode)
	}

	// With target → returns rows.
	res2, err := http.Get(srv.URL + "/api/v1/snapshots?target=/var/lib/sonarr")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res2.StatusCode)
	}
	var rows []snapshotView
	if err := json.NewDecoder(res2.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "abc" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestStateAPI_ListSnapshots_NotMountedWhenBackendNil(t *testing.T) {
	h, _ := newStateHandlerWithStore(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, _ := http.Get(srv.URL + "/api/v1/snapshots?target=/foo")
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("snapshots without backend = %d, want 404", res.StatusCode)
	}
}
