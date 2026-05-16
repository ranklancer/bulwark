package snapshot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// proxmoxFake stands in for the Proxmox VE REST API: it records every
// request and lets each test stub specific endpoints. The default
// behaviour is "401 unless overridden" so a missing handler is loud,
// not silent.
type proxmoxFake struct {
	mu       sync.Mutex
	requests []proxmoxRequest
	handlers map[string]http.HandlerFunc
}

type proxmoxRequest struct {
	Method string
	Path   string
	Token  string
	Body   string
}

func newProxmoxFake() *proxmoxFake {
	return &proxmoxFake{handlers: map[string]http.HandlerFunc{}}
}

func (f *proxmoxFake) handle(pattern string, h http.HandlerFunc) {
	f.handlers[pattern] = h
}

func (f *proxmoxFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, proxmoxRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Token:  r.Header.Get("Authorization"),
		Body:   string(body),
	})
	f.mu.Unlock()
	// Restore body for the handler.
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	key := r.Method + " " + r.URL.Path
	if h, ok := f.handlers[key]; ok {
		h(w, r)
		return
	}
	http.Error(w, `{"errors":{"path":"not stubbed: `+key+`"}}`, http.StatusNotFound)
}

func newProxmoxBackend(t *testing.T, fake *proxmoxFake) (*ProxmoxBackend, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	cfg := ProxmoxConfig{
		URL:        srv.URL,
		Token:      "bulwark@pve!ci=secret-value",
		Node:       "pve01",
		VMID:       100,
		Kind:       ProxmoxKindLXC,
		HTTPClient: srv.Client(),
		Now:        func() time.Time { return time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC) },
	}
	b, err := NewProxmox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b, srv
}

func TestNewProxmox_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ProxmoxConfig
		wantErr string
	}{
		{"missing url", ProxmoxConfig{}, "url is required"},
		{"bad scheme", ProxmoxConfig{URL: "ftp://x"}, "scheme must be http or https"},
		{"malformed token", ProxmoxConfig{URL: "https://x", Token: "no-bang"}, "token must be"},
		{"missing node", ProxmoxConfig{URL: "https://x", Token: "u@r!t=s"}, "node is required"},
		{"bad vmid", ProxmoxConfig{URL: "https://x", Token: "u@r!t=s", Node: "n", VMID: 0}, "vmid must be > 0"},
		{"bad kind", ProxmoxConfig{URL: "https://x", Token: "u@r!t=s", Node: "n", VMID: 100, Kind: "bsd"}, "kind must be"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewProxmox(c.cfg)
			if err == nil {
				t.Fatalf("expected error %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestProxmox_Snapshot_PostsExpectedAPI(t *testing.T) {
	fake := newProxmoxFake()
	fake.handle("POST /api2/json/nodes/pve01/lxc/100/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"data":"UPID:pve01:..."}`)
	})
	b, _ := newProxmoxBackend(t, fake)

	id, err := b.Snapshot(context.Background(), "ignored", "sonarr")
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot name: bulwark-sonarr-20260516T100000Z, then "." → "_" but
	// the label contains no dots so it should round-trip cleanly.
	if !strings.HasPrefix(id, "bulwark-sonarr-2026") {
		t.Errorf("snapshot id = %q, want bulwark-sonarr-2026...", id)
	}
	if len(fake.requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(fake.requests))
	}
	req := fake.requests[0]
	if req.Token != "PVEAPIToken=bulwark@pve!ci=secret-value" {
		t.Errorf("token header = %q", req.Token)
	}
	values, _ := url.ParseQuery(req.Body)
	if values.Get("snapname") != id {
		t.Errorf("body snapname = %q, want %q", values.Get("snapname"), id)
	}
	if values.Get("description") == "" {
		t.Error("missing description in POST body")
	}
}

func TestProxmox_Snapshot_PropagatesAPIError(t *testing.T) {
	fake := newProxmoxFake()
	fake.handle("POST /api2/json/nodes/pve01/lxc/100/snapshot", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":{"snapname":"already exists"}}`, http.StatusBadRequest)
	})
	b, _ := newProxmoxBackend(t, fake)
	_, err := b.Snapshot(context.Background(), "", "sonarr")
	if err == nil {
		t.Fatal("expected error from API 400")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected error to surface API body; got %q", err.Error())
	}
}

func TestProxmox_Restore(t *testing.T) {
	fake := newProxmoxFake()
	fake.handle("POST /api2/json/nodes/pve01/lxc/100/snapshot/bulwark-x-1/rollback", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	b, _ := newProxmoxBackend(t, fake)
	if err := b.Restore(context.Background(), "bulwark-x-1"); err != nil {
		t.Fatal(err)
	}
}

func TestProxmox_Destroy(t *testing.T) {
	fake := newProxmoxFake()
	fake.handle("DELETE /api2/json/nodes/pve01/lxc/100/snapshot/bulwark-x-1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	b, _ := newProxmoxBackend(t, fake)
	if err := b.Destroy(context.Background(), "bulwark-x-1"); err != nil {
		t.Fatal(err)
	}
}

func TestProxmox_List_FiltersAndParses(t *testing.T) {
	fake := newProxmoxFake()
	fake.handle("GET /api2/json/nodes/pve01/lxc/100/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"name": "current", "snaptime": 0}, // synthetic "current" entry; filter out
				{"name": "manual-snap", "snaptime": 1700000000}, // not bulwark; filter
				{"name": "bulwark-sonarr-20260516T100000Z", "snaptime": 1747396800},
				{"name": "bulwark-jellyfin-20260516T110000Z", "snaptime": 1747400400},
			},
		})
	})
	b, _ := newProxmoxBackend(t, fake)
	got, err := b.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d snapshots, want 2 (current + manual filtered): %+v", len(got), got)
	}
	if got[0].Label != "sonarr" || got[1].Label != "jellyfin" {
		t.Errorf("labels = [%q, %q]", got[0].Label, got[1].Label)
	}
	if got[0].Target != "100" {
		t.Errorf("target = %q, want '100'", got[0].Target)
	}
}

func TestProxmox_Available_2xxOr401(t *testing.T) {
	for name, status := range map[string]int{
		"200 ok":         http.StatusOK,
		"401 scoped":     http.StatusUnauthorized,
	} {
		t.Run(name, func(t *testing.T) {
			fake := newProxmoxFake()
			fake.handle("GET /api2/json/version", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})
			b, _ := newProxmoxBackend(t, fake)
			if !b.Available(context.Background()) {
				t.Errorf("Available() should return true for HTTP %d", status)
			}
		})
	}
}

func TestProxmox_Available_NetworkError(t *testing.T) {
	// Build a backend whose URL points nowhere reachable.
	cfg := ProxmoxConfig{
		URL:   "http://127.0.0.1:1", // 1 is reserved; nothing listens
		Token: "u@pve!t=s",
		Node:  "n",
		VMID:  1,
		Kind:  ProxmoxKindLXC,
		HTTPClient: &http.Client{Timeout: 100 * time.Millisecond},
	}
	b, err := NewProxmox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if b.Available(context.Background()) {
		t.Error("Available() should return false when the API is unreachable")
	}
}

func TestProxmox_SnapshotNameTruncated(t *testing.T) {
	fake := newProxmoxFake()
	fake.handle("POST /api2/json/nodes/pve01/lxc/100/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	b, _ := newProxmoxBackend(t, fake)
	id, err := b.Snapshot(context.Background(), "", strings.Repeat("a", 60))
	if err != nil {
		t.Fatal(err)
	}
	if len(id) > 40 {
		t.Errorf("id length = %d, want <= 40 (proxmox limit)", len(id))
	}
}
