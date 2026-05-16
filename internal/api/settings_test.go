package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/configstore"
)

func newStateHandlerWithConfigStore(t *testing.T) (*StateHandler, *configstore.Store) {
	t.Helper()
	cs, err := configstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reloadCalled := 0
	return &StateHandler{
		Store:        stateFixture(t),
		Auth:         AnonymousAuth{},
		LoadedConfig: config.Defaults(),
		ConfigStore:  cs,
		ReloadConfig: func() { reloadCalled++ },
	}, cs
}

func TestStateAPI_GetSettings(t *testing.T) {
	h, _ := newStateHandlerWithConfigStore(t)
	srv := newStateServer(t, h)
	resp, err := srv.Client().Get(srv.URL + "/api/v1/config/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Settings configstore.SettingsOverride  `json:"settings"`
		Sections []configstore.SettingsSection `json:"sections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sections) == 0 {
		t.Error("sections list is empty")
	}
	// Sanity: every section in the enumeration is present.
	seen := map[string]bool{}
	for _, s := range body.Sections {
		seen[s.Name] = true
	}
	for _, want := range []string{"schedule", "classification"} {
		if !seen[want] {
			t.Errorf("missing section %q in response", want)
		}
	}
}

func TestStateAPI_PatchClassification(t *testing.T) {
	h, cs := newStateHandlerWithConfigStore(t)
	srv := newStateServer(t, h)

	body := strings.NewReader(`{"default_risk":"breaking","policies":{"major":"safe"}}`)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/config/classification", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}

	// Verify persisted in the store.
	got := cs.Settings()
	if got.Classification == nil || got.Classification.DefaultRisk == nil ||
		*got.Classification.DefaultRisk != "breaking" {
		t.Errorf("classification override not persisted: %+v", got)
	}
}

func TestStateAPI_PatchClassification_RejectsBadRisk(t *testing.T) {
	h, _ := newStateHandlerWithConfigStore(t)
	srv := newStateServer(t, h)

	body := strings.NewReader(`{"default_risk":"chaos"}`)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/config/classification", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestStateAPI_GetEffectiveConfigAppliesOverride(t *testing.T) {
	h, cs := newStateHandlerWithConfigStore(t)
	srv := newStateServer(t, h)

	// Override policies.major → safe.
	if _, err := cs.PatchSection("classification", []byte(`{"policies":{"major":"safe"}}`), json.Unmarshal); err != nil {
		t.Fatal(err)
	}

	resp, err := srv.Client().Get(srv.URL + "/api/v1/config/effective")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		Config             any      `json:"config"`
		OverriddenSections []string `json:"overridden_sections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// Walk the parsed tree to find classification.policies.major.
	root, ok := body.Config.(map[string]any)
	if !ok {
		t.Fatalf("config root is not a map: %T", body.Config)
	}
	cls, ok := root["classification"].(map[string]any)
	if !ok {
		t.Fatalf("classification not a map: %v", root["classification"])
	}
	policies, ok := cls["policies"].(map[string]any)
	if !ok {
		t.Fatalf("policies not a map: %v", cls["policies"])
	}
	if policies["major"] != "safe" {
		t.Errorf("effective config policies.major = %v, want 'safe'", policies["major"])
	}
	if len(body.OverriddenSections) != 1 || body.OverriddenSections[0] != "classification" {
		t.Errorf("overridden_sections = %v, want ['classification']", body.OverriddenSections)
	}
}

func TestStateAPI_PatchSettings_UnknownSection(t *testing.T) {
	h, _ := newStateHandlerWithConfigStore(t)
	srv := newStateServer(t, h)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/config/registries", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestStateAPI_PatchSettingsTriggersReload(t *testing.T) {
	cs, err := configstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	h := &StateHandler{
		Store:        stateFixture(t),
		Auth:         AnonymousAuth{},
		LoadedConfig: config.Defaults(),
		ConfigStore:  cs,
		ReloadConfig: func() { called++ },
	}
	srv := newStateServer(t, h)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/config/classification", strings.NewReader(`{"default_risk":"safe"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if called != 1 {
		t.Errorf("ReloadConfig called %d times, want 1", called)
	}
}
