package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// stateFixture seeds a store with one scan that has two pending updates,
// plus a single recorded "approved" decision.
func stateFixture(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.RecordScan(store.ScanRecord{
		StartedAt:  time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 5, 1, 9, 0, 5, 0, time.UTC),
		Summary:    store.ScanSummary{Total: 2, Pending: 2, Review: 1, Breaking: 1},
		Results: []store.ScanResultRecord{
			{
				ContainerName: "sonarr",
				Image:         "lscr.io/.../sonarr:1",
				UpdateAvailable: true,
				Level:           types.RiskReview,
				From:            "1", To: "2",
				RegistryDigest: "sha256:sonarrnew",
			},
			{
				ContainerName: "auth",
				Image:         "ghcr.io/owner/auth:1",
				UpdateAvailable: true,
				Level:           types.RiskBreaking,
				RegistryDigest: "sha256:authnew",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDecision(store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{
			ContainerID: "sonarr", RegistryDigest: "sha256:sonarrnew",
		},
		ContainerName: "sonarr",
		Decision:      store.DecisionApproved,
		DecidedBy:     "alice",
		DecidedAt:     time.Date(2026, 5, 1, 9, 5, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func newStateServer(t *testing.T, h *StateHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// --- /scans ----------------------------------------------------------------

func TestListScans(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/scans")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("got %d scans, want 1", len(got))
	}
}

func TestGetScan_Latest(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/scans/latest")
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
	if got["id"] == nil {
		t.Errorf("latest scan missing id field: %+v", got)
	}
}

func TestGetScan_Unknown_404(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/scans/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetScan_PathTraversalReturns400(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	// %2F = /, %5C = \. Even percent-decoded the id contains forbidden chars.
	resp, err := http.Get(srv.URL + "/api/v1/scans/..%2F..%2Fetc%2Fpasswd")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (invalid id, not 404)", resp.StatusCode)
	}
}

// --- /queue ----------------------------------------------------------------

func TestListQueue_ReflectsApproval(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/queue")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	for _, row := range got {
		if row["container"] == "sonarr" && row["decision"] != "approved" {
			t.Errorf("sonarr decision = %v, want approved", row["decision"])
		}
		if row["container"] == "auth" && row["decision"] != "pending" {
			t.Errorf("auth decision = %v, want pending", row["decision"])
		}
	}
}

func TestPostDecision_RecordsApproval(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	body := `{"container":"auth","decision":"approved","note":"reviewed in standup","decided_by":"bob"}`
	resp, err := http.Post(srv.URL+"/api/v1/queue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	got, _ := st.LookupDecision(store.ApprovalKey{ContainerID: "auth", RegistryDigest: "sha256:authnew"})
	if got == nil || got.Decision != store.DecisionApproved {
		t.Errorf("decision not recorded: %+v", got)
	}
	if got.Note != "reviewed in standup" {
		t.Errorf("note not preserved: %+v", got)
	}
	if got.DecidedBy != "bob" {
		t.Errorf("decided_by not preserved: %+v", got)
	}
}

func TestPostDecision_RejectsBadDecision(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	body := `{"container":"auth","decision":"maybe"}`
	resp, err := http.Post(srv.URL+"/api/v1/queue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPostDecision_UnknownContainer_404(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	body := `{"container":"ghostly","decision":"approved"}`
	resp, err := http.Post(srv.URL+"/api/v1/queue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPostDecision_NoScanHistory_409(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	srv := newStateServer(t, &StateHandler{Store: st})
	body := `{"container":"x","decision":"approved"}`
	resp, err := http.Post(srv.URL+"/api/v1/queue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestForgetDecision(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/queue/sonarr", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got, _ := st.LookupDecision(store.ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:sonarrnew"})
	if got != nil {
		t.Errorf("decision still present: %+v", got)
	}
}

func TestForgetDecision_Unknown_404(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/queue/ghost", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// --- /notifications --------------------------------------------------------

func TestListNotifications(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	_ = st.MarkNotified(
		store.NotificationKey{ContainerID: "x", RegistryDigest: "y"},
		store.NotificationRecord{Level: types.RiskReview},
		time.Now(),
	)
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/notifications")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("got %d, want 1", len(got))
	}
}

func TestClearNotifications(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	_ = st.MarkNotified(
		store.NotificationKey{ContainerID: "x", RegistryDigest: "y"},
		store.NotificationRecord{Level: types.RiskReview},
		time.Now(),
	)
	srv := newStateServer(t, &StateHandler{Store: st})
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/notifications", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	entries, _ := st.ListNotifications()
	if len(entries) != 0 {
		t.Errorf("not cleared: %+v", entries)
	}
}

// --- auth -----------------------------------------------------------------

func TestAuth_RequiredOnAllEndpoints(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st, Auth: BearerAuth{Token: "secret"}})

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/scans", ""},
		{"GET", "/api/v1/scans/latest", ""},
		{"GET", "/api/v1/queue", ""},
		{"POST", "/api/v1/queue", `{"container":"x","decision":"approved"}`},
		{"DELETE", "/api/v1/queue/sonarr", ""},
		{"GET", "/api/v1/notifications", ""},
		{"DELETE", "/api/v1/notifications", ""},
	}
	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req, _ := http.NewRequest(ep.method, srv.URL+ep.path, strings.NewReader(ep.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}

			req, _ = http.NewRequest(ep.method, srv.URL+ep.path, strings.NewReader(ep.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer secret")
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				t.Errorf("authed call still got 401")
			}
		})
	}
}

func TestPostDecision_DecidedByFallsBackToForwardProxyIdentity(t *testing.T) {
	st := stateFixture(t)
	auth, err := NewForwardProxyAuth([]string{"192.0.2.0/24"}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	srv := newStateServer(t, &StateHandler{Store: st, Auth: auth})

	// httptest.NewServer binds to 127.0.0.1, but the auth check runs on
	// r.RemoteAddr. We need to fake a request from a "trusted proxy". The
	// simplest path is to construct the request manually and dial through
	// http.DefaultClient — but RemoteAddr is set by the server based on
	// the actual TCP peer. To test this end-to-end we instead invoke the
	// handler directly via httptest.NewRecorder.
	body := `{"container":"sonarr","decision":"approved"}`
	r, _ := http.NewRequest("POST", srv.URL+"/api/v1/queue", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.5:54321"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Remote-User", "alice")
	r.Header.Set("Remote-Groups", "ops")
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	(&StateHandler{Store: st, Auth: auth}).Register(mux)
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	got, _ := st.LookupDecision(store.ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:sonarrnew"})
	if got == nil {
		t.Fatal("decision not recorded")
	}
	if got.DecidedBy != "alice" {
		t.Errorf("DecidedBy = %q, want 'alice' (from forward-proxy Remote-User)", got.DecidedBy)
	}
}

func TestAuth_AnonymousAllowedWhenTokenEmpty(t *testing.T) {
	st := stateFixture(t)
	srv := newStateServer(t, &StateHandler{Store: st})
	resp, err := http.Get(srv.URL + "/api/v1/scans")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous = %d, want 200 when Token is empty", resp.StatusCode)
	}
}

func TestRegister_NoStoreNoMounts(t *testing.T) {
	mux := http.NewServeMux()
	(&StateHandler{Store: nil}).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/scans")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (route not mounted) when Store is nil, got %d", resp.StatusCode)
	}
}
