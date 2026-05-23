package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestNegotiateEncoding(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"identity", ""},
		{"gzip", "gzip"},
		{"br", "br"},
		{"gzip, deflate, br", "br"},      // br wins when both present
		{"gzip;q=1.0", "gzip"},           // q-values stripped
		{"br;q=1.0, gzip;q=0.5", "br"},   // br wins regardless of q
		{"deflate", ""},                  // deflate not supported
		{"GZIP", "gzip"},                 // case-insensitive
		{"  br  ,  gzip  ", "br"},        // whitespace tolerant
	}
	for _, tc := range cases {
		if got := negotiateEncoding(tc.header); got != tc.want {
			t.Errorf("negotiateEncoding(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestCompressMiddleware_GzipRequestRoundTrips(t *testing.T) {
	payload := bytes.Repeat([]byte("bulwark "), 200) // 1600 bytes, compressible
	handler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", got)
	}
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary = %q, want to contain Accept-Encoding", got)
	}

	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(zr)
	if !bytes.Equal(body, payload) {
		t.Errorf("decompressed body mismatch (got %d bytes, want %d)", len(body), len(payload))
	}
}

func TestCompressMiddleware_BrotliRequestRoundTrips(t *testing.T) {
	payload := bytes.Repeat([]byte("bulwark "), 200)
	handler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "br")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if got := res.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br", got)
	}

	body, _ := io.ReadAll(brotli.NewReader(res.Body))
	if !bytes.Equal(body, payload) {
		t.Errorf("decompressed body mismatch (got %d bytes, want %d)", len(body), len(payload))
	}
}

func TestCompressMiddleware_PrefersBrotliWhenBothAccepted(t *testing.T) {
	handler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if got := res.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br (preferred over gzip)", got)
	}
}

func TestCompressMiddleware_NoEncodingWhenClientDeclines(t *testing.T) {
	handler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// No Accept-Encoding header at all (Go's transport adds gzip by
	// default; build the request via RoundTripper-aware path that
	// suppresses it).
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "identity")
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary = %q, want Accept-Encoding (so caches keep per-encoding entries even when this client opted out)", got)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
}

func TestCompressMiddleware_PassesThroughAlreadyEncodedBody(t *testing.T) {
	// A handler that has already encoded its own response should not
	// have its body re-encoded by the middleware.
	handler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("pre-encoded"))
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if got := res.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br (preserved from handler)", got)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "pre-encoded" {
		t.Errorf("body = %q, want raw bytes", body)
	}
}

func TestCompressMiddleware_DropsContentLength(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 1000)
	handler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write(payload)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	// Content-Length set by the handler must be removed once the body
	// is encoded — the compressed length is unknown, chunked transfer
	// takes over.
	if got := res.Header.Get("Content-Length"); got == "1000" {
		t.Errorf("Content-Length = %q, want absent or chunked-friendly (compressed length differs from raw)", got)
	}
}
