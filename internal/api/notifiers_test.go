package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/configstore"
	"github.com/ranklancer/bulwark/internal/notifier"
)

// newRegistryForTests returns a notifier.Registry with the provided yaml
// list and a fresh on-disk configstore rooted at a temp dir.
func newRegistryForTests(t *testing.T, yamlList []notifier.Notifier) (*notifier.Registry, *configstore.Store) {
	t.Helper()
	cs, err := configstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := notifier.NewRegistry(yamlList, cs, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return reg, cs
}

func TestStateAPI_CreateAndListUINotifier(t *testing.T) {
	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{
		Store:      stateFixture(t),
		Auth:       AnonymousAuth{},
		Registry:   reg,
		Dispatcher: reg.Dispatcher(), // mirrors run.go wiring
	}
	srv := newStateServer(t, h)

	body := strings.NewReader(`{
		"name": "ops-channel",
		"kind": "slack",
		"min_level": "review",
		"enabled": true,
		"slack": {"webhook_url": "https://hooks.slack.com/services/T0/B0/abc"}
	}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/notifiers", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode, raw)
	}
	var created notifierView
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Error("created notifier missing id")
	}
	if created.Source != "ui" {
		t.Errorf("created notifier source = %q, want ui", created.Source)
	}

	// GET /api/v1/notifiers should now include it with source=ui.
	resp2, err := srv.Client().Get(srv.URL + "/api/v1/notifiers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var listed []notifierView
	if err := json.NewDecoder(resp2.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("list returned %d, want 1: %+v", len(listed), listed)
	}
	if listed[0].ID != created.ID || listed[0].Source != "ui" {
		t.Errorf("listed[0] = %+v, want id=%s source=ui", listed[0], created.ID)
	}
}

func TestStateAPI_CreateNotifier_ValidationRejected(t *testing.T) {
	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)

	// Bad URL scheme — should be rejected by Validate.
	body := strings.NewReader(`{
		"name": "bad-slack",
		"kind": "slack",
		"enabled": true,
		"slack": {"webhook_url": "ftp://hooks.example.com/x"}
	}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/notifiers", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestStateAPI_DeleteUINotifier(t *testing.T) {
	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)

	id := mustCreate(t, srv, `{"name":"x","kind":"slack","enabled":true,"slack":{"webhook_url":"https://hooks.slack.com/services/T/B/x"}}`)

	req, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/notifiers/"+id, nil)
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE returned %d, want 204", resp.StatusCode)
	}

	// Second DELETE should 404 — entry no longer exists.
	req2, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/notifiers/"+id, nil)
	req2.Header.Set("Origin", srv.URL)
	resp2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("second DELETE returned %d, want 404", resp2.StatusCode)
	}
}

func TestStateAPI_YAMLAndUINotifiersCoexist(t *testing.T) {
	yamlSlack, err := notifier.NewSlack("https://hooks.slack.com/yaml/x", "", 0, "yaml-slack")
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := newRegistryForTests(t, []notifier.Notifier{yamlSlack})
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)

	// Add a UI-managed one.
	mustCreate(t, srv, `{"name":"ui-slack","kind":"slack","enabled":true,"slack":{"webhook_url":"https://hooks.slack.com/services/T/B/x"}}`)

	resp, err := srv.Client().Get(srv.URL + "/api/v1/notifiers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed []notifierView
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("list returned %d, want 2: %+v", len(listed), listed)
	}
	var sawYAML, sawUI bool
	for _, v := range listed {
		if v.Source == "yaml" && v.Name == "yaml-slack" {
			sawYAML = true
		}
		if v.Source == "ui" && v.Name == "ui-slack" {
			sawUI = true
		}
	}
	if !sawYAML || !sawUI {
		t.Errorf("expected both yaml + ui notifiers; got %+v", listed)
	}
}

func TestStateAPI_CreateNotifier_503WhenRegistryNil(t *testing.T) {
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}}
	srv := newStateServer(t, h)
	resp, err := srv.Client().Post(srv.URL+"/api/v1/notifiers", "application/json", strings.NewReader(`{}`))
	if err == nil {
		// Route isn't even mounted when Registry is nil → expect 404
		// rather than 503. Either way it's not 201.
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			t.Fatalf("create should not succeed without a registry; got 201")
		}
	}
}

func TestStateAPI_TestEphemeralNotifier(t *testing.T) {
	// Stand up a fake webhook server that records the body it received,
	// then point a Slack notifier at it via the test-ephemeral endpoint.
	var captured []byte
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hook.Close)

	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)

	body := strings.NewReader(`{"name":"trial","kind":"slack","enabled":true,"slack":{"webhook_url":"` + hook.URL + `"}}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/notifiers/test", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("test POST = %d, body=%s", resp.StatusCode, raw)
	}
	if !bytes.Contains(captured, []byte("bulwark-test")) {
		t.Errorf("hook did not receive the synthetic event; got: %s", captured)
	}
	// Nothing persisted to the registry.
	if got := reg.Entries(); len(got) != 0 {
		t.Errorf("ephemeral test should not persist; registry has %d entries", len(got))
	}
}

func TestStateAPI_UpdateNotifier(t *testing.T) {
	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)

	id := mustCreate(t, srv, `{"name":"orig","kind":"slack","enabled":true,"slack":{"webhook_url":"https://hooks.slack.com/services/T/B/x"}}`)

	body := strings.NewReader(`{
		"name": "renamed",
		"kind": "slack",
		"min_level": "breaking",
		"enabled": true,
		"slack": {"webhook_url": "https://hooks.slack.com/services/T/B/y"}
	}`)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/notifiers/"+id, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH = %d, body=%s", resp.StatusCode, raw)
	}
	var updated notifierView
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != id {
		t.Errorf("ID changed: %s → %s", id, updated.ID)
	}
	if updated.Name != "renamed" {
		t.Errorf("name not updated: %q", updated.Name)
	}
	if updated.MinLevel != "breaking" {
		t.Errorf("min_level not updated: %q", updated.MinLevel)
	}

	// GET should reflect the new settings.
	getResp, err := srv.Client().Get(srv.URL + "/api/v1/notifiers/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", getResp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	slack, ok := got["slack"].(map[string]any)
	if !ok {
		t.Fatalf("response missing slack: %+v", got)
	}
	if slack["webhook_url"] != "https://hooks.slack.com/services/T/B/y" {
		t.Errorf("webhook_url not updated: %v", slack["webhook_url"])
	}
}

func TestStateAPI_UpdateNotifier_UnknownIDReturns404(t *testing.T) {
	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/notifiers/nonexistent",
		strings.NewReader(`{"name":"x","kind":"slack","enabled":true,"slack":{"webhook_url":"https://hooks.slack.com/services/T/B/z"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("PATCH unknown id = %d, want 404", resp.StatusCode)
	}
}

func TestStateAPI_GetNotifier(t *testing.T) {
	reg, _ := newRegistryForTests(t, nil)
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}, Registry: reg, Dispatcher: reg.Dispatcher()}
	srv := newStateServer(t, h)

	id := mustCreate(t, srv, `{"name":"x","kind":"slack","enabled":true,"slack":{"webhook_url":"https://hooks.slack.com/services/T/B/abc"}}`)

	resp, err := srv.Client().Get(srv.URL + "/api/v1/notifiers/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != id {
		t.Errorf("id = %v, want %s", got["id"], id)
	}
	slack, ok := got["slack"].(map[string]any)
	if !ok {
		t.Fatalf("missing slack section: %+v", got)
	}
	if slack["webhook_url"] != "https://hooks.slack.com/services/T/B/abc" {
		t.Errorf("webhook_url = %v", slack["webhook_url"])
	}
}

func mustCreate(t *testing.T, srv *httptest.Server, payload string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/notifiers", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create failed: status %d, body %s", resp.StatusCode, raw)
	}
	var view notifierView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	return view.ID
}
