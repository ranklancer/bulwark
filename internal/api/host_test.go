package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/snapshot/detect"
)

func TestStateAPI_GetHost_ReturnsFixture(t *testing.T) {
	fixture := &detect.Result{
		Platform:         detect.PlatformTrueNAS,
		VersionString:    "TrueNAS-SCALE-24.04.0",
		Capabilities:     []detect.Capability{detect.CapZFS},
		SuggestedBackend: "zfs",
	}
	loaded := config.Defaults()
	loaded.Snapshots.Backend = "zfs"
	h := &StateHandler{
		Store:         stateFixture(t),
		Auth:          AnonymousAuth{},
		LoadedConfig:  loaded,
		HostDetection: fixture,
	}
	srv := newStateServer(t, h)
	resp, err := srv.Client().Get(srv.URL + "/api/v1/host")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got hostView
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Platform != "truenas-scale" {
		t.Errorf("platform = %q", got.Platform)
	}
	if got.Version != "TrueNAS-SCALE-24.04.0" {
		t.Errorf("version = %q", got.Version)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "zfs" {
		t.Errorf("capabilities = %v", got.Capabilities)
	}
	if got.SuggestedBackend != "zfs" {
		t.Errorf("suggested = %q", got.SuggestedBackend)
	}
	if got.ConfiguredBackend != "zfs" {
		t.Errorf("configured = %q", got.ConfiguredBackend)
	}
}

func TestStateAPI_GetHost_NoLoadedConfig(t *testing.T) {
	fixture := &detect.Result{
		Platform: detect.PlatformProxmox,
		Capabilities: []detect.Capability{detect.CapProxmoxAPI},
	}
	h := &StateHandler{
		Store:         stateFixture(t),
		Auth:          AnonymousAuth{},
		HostDetection: fixture,
	}
	srv := newStateServer(t, h)
	resp, err := srv.Client().Get(srv.URL + "/api/v1/host")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got hostView
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Platform != "proxmox-ve" {
		t.Errorf("platform = %q", got.Platform)
	}
	if got.ConfiguredBackend != "" {
		t.Errorf("configured backend should be empty without loaded config; got %q", got.ConfiguredBackend)
	}
}
