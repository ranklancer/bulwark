package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_RendersPrometheusFormat(t *testing.T) {
	m := NewMetrics()
	m.IncScan()
	m.IncScan()
	m.IncDispatch("slack", false)
	m.IncDispatch("slack", true)
	m.IncDispatch("discord", false)
	m.IncApply("success")
	m.IncApply("rolled_back")
	m.IncDecision("approved")
	m.IncRateLimited()

	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := w.Body.String()

	wants := []string{
		"# TYPE bulwark_scans_total counter",
		"bulwark_scans_total 2",
		"bulwark_dispatch_total{channel=\"slack\"} 2",
		"bulwark_dispatch_total{channel=\"discord\"} 1",
		"bulwark_dispatch_errors_total{channel=\"slack\"} 1",
		"bulwark_apply_total{outcome=\"success\"} 1",
		"bulwark_apply_total{outcome=\"rolled_back\"} 1",
		"bulwark_decisions_total{outcome=\"approved\"} 1",
		"bulwark_rate_limited_total 1",
	}
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("missing line: %q\nfull body:\n%s", w, body)
		}
	}
}

func TestMetrics_NilRecordersAreSafe(t *testing.T) {
	var m *Metrics
	// No panic on any recorder method.
	m.IncScan()
	m.IncDispatch("x", false)
	m.IncApply("success")
	m.IncDecision("forgot")
	m.IncHTTP("/foo", 200)
	m.IncRateLimited()
}

func TestMetrics_HTTPLabelSplit(t *testing.T) {
	m := NewMetrics()
	m.IncHTTP("/api/v1/queue", 200)
	m.IncHTTP("/api/v1/queue", 401)
	m.IncHTTP("/api/v1/scans/abc", 404)
	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	body := w.Body.String()
	for _, want := range []string{
		`bulwark_http_total{route="/api/v1/queue",code="2xx"} 1`,
		`bulwark_http_total{route="/api/v1/queue",code="4xx"} 1`,
		`bulwark_http_total{route="/api/v1/scans/abc",code="4xx"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q\n%s", want, body)
		}
	}
}
