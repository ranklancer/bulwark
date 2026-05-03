package api

import (
	"strings"
	"testing"
	"time"
)

func TestHMACScheme_RoundTrip(t *testing.T) {
	s := &HMACScheme{Secret: []byte("topsecret"), MaxSkew: time.Minute}
	body := []byte(`{"image":"x:1"}`)
	when := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return when }

	ts, sig := s.Sign(body, when)
	if err := s.Verify(ts, sig, body); err != nil {
		t.Fatalf("Verify of own signature: %v", err)
	}
}

func TestHMACScheme_DisabledNoOp(t *testing.T) {
	s := NewHMACScheme(nil)
	if s.Enabled() {
		t.Error("empty secret should disable")
	}
	if err := s.Verify("", "", []byte("anything")); err != nil {
		t.Errorf("disabled scheme should accept everything: %v", err)
	}
}

func TestHMACScheme_RejectsStaleTimestamp(t *testing.T) {
	s := &HMACScheme{Secret: []byte("k"), MaxSkew: time.Minute}
	when := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return when.Add(10 * time.Minute) } // 10 min later
	body := []byte("data")
	ts, sig := s.Sign(body, when)
	err := s.Verify(ts, sig, body)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("stale timestamp not rejected: %v", err)
	}
}

func TestHMACScheme_RejectsTamperedBody(t *testing.T) {
	s := &HMACScheme{Secret: []byte("k"), MaxSkew: time.Minute}
	when := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return when }
	ts, sig := s.Sign([]byte("original"), when)
	if err := s.Verify(ts, sig, []byte("tampered")); err == nil {
		t.Error("tampered body must fail verification")
	}
}

func TestHMACScheme_RejectsTamperedTimestamp(t *testing.T) {
	s := &HMACScheme{Secret: []byte("k"), MaxSkew: time.Minute}
	when := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return when }
	ts, sig := s.Sign([]byte("body"), when)
	bumped := strings.TrimSpace(ts) + "0" // append a digit; signature no longer matches
	if err := s.Verify(bumped, sig, []byte("body")); err == nil {
		t.Error("tampered timestamp must fail signature check")
	}
}

func TestHMACScheme_RejectsBadHex(t *testing.T) {
	s := &HMACScheme{Secret: []byte("k"), MaxSkew: time.Minute, Now: func() time.Time {
		return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	}}
	ts, _ := s.Sign([]byte("body"), time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err := s.Verify(ts, "not-hex", []byte("body")); err == nil {
		t.Error("non-hex signature should fail")
	}
}

func TestHMACScheme_RejectsMissingHeaders(t *testing.T) {
	s := &HMACScheme{Secret: []byte("k")}
	if err := s.Verify("", "", []byte("body")); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("missing both headers should error clearly: %v", err)
	}
}
