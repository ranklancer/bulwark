package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServerForUITests() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mountUI(mux, slogDiscard())
	return httptest.NewServer(mux)
}

func TestUI_RootServesHTMLDashboard(t *testing.T) {
	srv := newServerForUITests()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html…", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// GET / serves the dashboard shell in whichever mode is embedded: the
	// legacy vanilla dashboard when the React SPA has not been built
	// (placeholder dist/), or the Vite/React index when it has. Assert only
	// the markers common to both modes -- a valid HTML document that
	// identifies as the Bulwark dashboard. Mode-specific bodies (the vanilla
	// dashboard inlined /api/v1/* calls vs. the React shell hashed /assets/
	// bundle) are covered deterministically by the mountUIRoutes tests in
	// server_test.go.
	if lower := strings.ToLower(string(body)); !strings.Contains(lower, "<!doctype html>") {
		t.Errorf("dashboard missing HTML doctype; body=%q", body)
	}
	if !strings.Contains(string(body), "Bulwark") {
		t.Errorf("dashboard missing product name %q", "Bulwark")
	}
}

func TestUI_SetsContentSecurityPolicy(t *testing.T) {
	srv := newServerForUITests()
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q\nfull: %s", want, csp)
		}
	}
}

func TestUI_NoCacheHeader(t *testing.T) {
	srv := newServerForUITests()
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (UI should not be cached)", cc)
	}
}

func TestUI_UnknownPathFalls404(t *testing.T) {
	srv := newServerForUITests()
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/static/missing.css")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 — wildcard '/' must not shadow other paths", resp.StatusCode)
	}
}

func TestUI_DoesNotShadowAPIRoutes(t *testing.T) {
	// Compose a server with both UI and a placeholder API route, to verify
	// the UI's "/" handler doesn't accidentally swallow API requests.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mountUI(mux, slogDiscard())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200 (UI must not shadow other routes)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("/healthz body = %q (UI may have shadowed it)", body)
	}
}
