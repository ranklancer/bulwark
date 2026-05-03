package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func newRelay(t *testing.T, upstreamURL string, secret []byte, bearer string) *relayHandler {
	t.Helper()
	return &relayHandler{
		Upstream: upstreamURL,
		Secret:   secret,
		Bearer:   bearer,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Client:   &http.Client{},
	}
}

func TestRelay_SignsAndForwards(t *testing.T) {
	secret := []byte("topsecret")
	var (
		gotSig  string
		gotTS   string
		gotBody []byte
		gotAuth string
		gotCT   string
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Bulwark-Signature")
		gotTS = r.Header.Get("X-Bulwark-Timestamp")
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	}))
	defer upstream.Close()

	h := newRelay(t, upstream.URL, secret, "abc123")

	body := `{"image":"x:1"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if string(gotBody) != body {
		t.Errorf("body forwarded = %q, want %q", gotBody, body)
	}
	if gotAuth != "Bearer abc123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	// Verify the signature relays computed.
	if _, err := strconv.ParseInt(gotTS, 10, 64); err != nil {
		t.Errorf("X-Bulwark-Timestamp not numeric: %q", gotTS)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(gotTS))
	mac.Write([]byte{'.'})
	mac.Write([]byte(body))
	want := hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("signature mismatch:\n  got:  %s\n  want: %s", gotSig, want)
	}
}

func TestRelay_OmitsBearerWhenUnset(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	h := newRelay(t, upstream.URL, []byte("k"), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if gotAuth != "" {
		t.Errorf("Authorization header sent unexpectedly: %q", gotAuth)
	}
}

func TestRelay_MirrorsUpstreamStatusAndBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad token"}`))
	}))
	defer upstream.Close()
	h := newRelay(t, upstream.URL, []byte("k"), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status mirror = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bad token") {
		t.Errorf("body mirror missing upstream content: %q", rec.Body.String())
	}
}

func TestRelay_BadGatewayWhenUpstreamUnreachable(t *testing.T) {
	h := newRelay(t, "http://127.0.0.1:1/should-fail", []byte("k"), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestRelay_RejectsOversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream should not be called for oversized body")
	}))
	defer upstream.Close()
	h := newRelay(t, upstream.URL, []byte("k"), "")
	huge := bytes.Repeat([]byte("x"), maxBodyBytes+1024)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(huge))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRedactURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://bulwark.example.com/api/v1/webhooks/diun", "https://bulwark.example.com/api/v1/webhooks/diun"},
		{"https://user:pass@bulwark.example.com/api/v1/webhooks/diun", "https://<redacted>@bulwark.example.com/api/v1/webhooks/diun"},
	}
	for _, tc := range cases {
		if got := redactURL(tc.in); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRun_RejectsMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--listen", ":0"}, &stdout, &stderr); err == nil {
		t.Error("expected error for missing --upstream / --secret-file")
	}
}
