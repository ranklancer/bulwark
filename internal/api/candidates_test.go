package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/store"
)

func TestListCandidates(t *testing.T) {
	dir := t.TempDir()
	ps := store.OpenPinStore(dir)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(ps.Set("web/app", store.PinRecord{Ref: "nginx:1.27", IndexDigest: "sha256:abc", CanaryState: store.CanaryCandidate, Service: "app"}))
	must(ps.Set("web/canary", store.PinRecord{Ref: "redis:7", IndexDigest: "sha256:def", CanaryState: store.CanaryActive}))
	must(ps.Set("web/done", store.PinRecord{Ref: "x:1", IndexDigest: "sha256:ghi", CanaryState: store.CanaryPromoted}))

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := newStateServer(t, &StateHandler{Store: st, Pins: ps})
	resp, err := http.Get(srv.URL + "/api/v1/candidates")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []candidateView
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2 (promoted terminal omitted)", len(got))
	}
	if got[0].Key != "web/app" || got[0].CanaryState != store.CanaryCandidate {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Key != "web/canary" || got[1].CanaryState != store.CanaryActive {
		t.Errorf("second = %+v", got[1])
	}
}

func TestListCandidates_RouteOmittedWithoutPins(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/candidates")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route omitted when Pins is nil)", resp.StatusCode)
	}
}
