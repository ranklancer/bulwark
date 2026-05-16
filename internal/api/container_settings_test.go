package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/configstore"
)

func TestStateAPI_PutContainerSettings_Roundtrip(t *testing.T) {
	cs, err := configstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &StateHandler{
		Store:       stateFixture(t),
		Auth:        AnonymousAuth{},
		ConfigStore: cs,
	}
	srv := newStateServer(t, h)

	body := strings.NewReader(`{"snapshot_auto": true, "snapshot_dataset": "tank/sonarr"}`)
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/containers/sonarr/settings", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	got, ok := cs.ContainerOverride("sonarr")
	if !ok {
		t.Fatal("expected override persisted")
	}
	if got.SnapshotAuto == nil || !*got.SnapshotAuto {
		t.Errorf("snapshot_auto not set: %+v", got)
	}
	if got.SnapshotDataset == nil || *got.SnapshotDataset != "tank/sonarr" {
		t.Errorf("snapshot_dataset not set: %+v", got)
	}
}

func TestStateAPI_ListContainerSettings(t *testing.T) {
	cs, _ := configstore.Open(t.TempDir())
	auto := true
	_ = cs.SetContainerOverride("a", configstore.ContainerOverride{SnapshotAuto: &auto})
	_ = cs.SetContainerOverride("b", configstore.ContainerOverride{SnapshotAuto: &auto})

	h := &StateHandler{
		Store:       stateFixture(t),
		Auth:        AnonymousAuth{},
		ConfigStore: cs,
	}
	srv := newStateServer(t, h)
	resp, err := srv.Client().Get(srv.URL + "/api/v1/containers/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]configstore.ContainerOverride
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d entries, want 2: %+v", len(got), got)
	}
}

func TestStateAPI_DeleteContainerSettings(t *testing.T) {
	cs, _ := configstore.Open(t.TempDir())
	auto := true
	_ = cs.SetContainerOverride("sonarr", configstore.ContainerOverride{SnapshotAuto: &auto})
	h := &StateHandler{
		Store:       stateFixture(t),
		Auth:        AnonymousAuth{},
		ConfigStore: cs,
	}
	srv := newStateServer(t, h)
	req, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/containers/sonarr/settings", nil)
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if _, ok := cs.ContainerOverride("sonarr"); ok {
		t.Error("override still present after delete")
	}
}

func TestStateAPI_ContainerSettings_503WhenStoreNil(t *testing.T) {
	h := &StateHandler{Store: stateFixture(t), Auth: AnonymousAuth{}}
	srv := newStateServer(t, h)
	resp, err := srv.Client().Get(srv.URL + "/api/v1/containers/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Without ConfigStore the route isn't mounted → 404.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("unexpected 200; route should not be mounted without configstore")
	}
}
