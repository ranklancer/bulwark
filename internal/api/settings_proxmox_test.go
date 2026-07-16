package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/configstore"
)

func TestStateAPI_GetSettings_RedactsProxmoxToken(t *testing.T) {
	cs, err := configstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.PatchSection("snapshots", []byte(`{"proxmox":{"token":"u@pve!t=secret"}}`), json.Unmarshal); err != nil {
		t.Fatal(err)
	}
	h := newStateHandlerWithConfigStoreOnly(t, cs)
	srv := newStateServer(t, h)

	resp, err := srv.Client().Get(srv.URL + "/api/v1/config/settings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := readAllString(resp.Body)
	if strings.Contains(body, "secret") {
		t.Errorf("response leaked the raw proxmox token: %s", body)
	}
	if !strings.Contains(body, "***") {
		t.Errorf("expected '***' redaction marker in response: %s", body)
	}
}

func TestStateAPI_PatchSettings_PreservesTokenOnRedactedEcho(t *testing.T) {
	cs, _ := configstore.Open(t.TempDir())
	if _, err := cs.PatchSection("snapshots", []byte(`{"proxmox":{"token":"u@pve!t=keep-me","node":"old-node"}}`), json.Unmarshal); err != nil {
		t.Fatal(err)
	}
	h := newStateHandlerWithConfigStoreOnly(t, cs)
	srv := newStateServer(t, h)

	// Simulate the dashboard echoing back the redacted marker for token
	// while changing node. The server should drop the marker token and
	// only apply node.
	body := strings.NewReader(`{"proxmox":{"token":"***","node":"new-node"}}`)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/config/snapshots", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	got := cs.Settings()
	if got.Snapshots.Proxmox.Token == nil || *got.Snapshots.Proxmox.Token != "u@pve!t=keep-me" {
		t.Errorf("token clobbered by redacted echo: %+v", got.Snapshots.Proxmox.Token)
	}
	if got.Snapshots.Proxmox.Node == nil || *got.Snapshots.Proxmox.Node != "new-node" {
		t.Errorf("node not updated: %+v", got.Snapshots.Proxmox.Node)
	}
}

func TestStateAPI_PatchSettings_Health(t *testing.T) {
	cs, _ := configstore.Open(t.TempDir())
	h := newStateHandlerWithConfigStoreOnly(t, cs)
	srv := newStateServer(t, h)
	req, _ := http.NewRequest("PATCH", srv.URL+"/api/v1/config/health",
		strings.NewReader(`{"timeout":"240s","threshold":3}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := cs.Settings()
	if got.Health == nil || got.Health.Timeout == nil || *got.Health.Timeout != "240s" {
		t.Errorf("health.timeout not persisted: %+v", got.Health)
	}
}

func newStateHandlerWithConfigStoreOnly(t *testing.T, cs *configstore.Store) *StateHandler {
	return &StateHandler{
		Store:        stateFixture(t),
		Auth:         AnonymousAuth{},
		LoadedConfig: nil,
		ConfigStore:  cs,
		// nil LoadedConfig prevents the /effective endpoint from mounting,
		// which is fine for tests that only exercise /settings + /{section}.
		ReloadConfig: func() {},
	}
}

func readAllString(r interface{ Read(p []byte) (int, error) }) (string, error) {
	buf := make([]byte, 8192)
	out := make([]byte, 0, 8192)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return string(out), nil
			}
			return string(out), err
		}
	}
}
