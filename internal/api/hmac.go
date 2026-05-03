package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// HMACScheme is the over-the-wire signing scheme for the DIUN webhook
// (and any future request that needs replay protection on top of bearer
// auth).
//
// Wire format:
//
//	X-Bulwark-Timestamp:  <unix seconds, ASCII-decimal>
//	X-Bulwark-Signature:  <hex(HMAC-SHA256(secret, "<timestamp>.<body>"))>
//
// The timestamp is part of the signed material so a replay with the same
// body but a stale timestamp produces a valid signature for an unwanted
// time — which the freshness check then rejects. The dot-separator is the
// same convention Slack uses for v0= signatures, picked here for
// familiarity.
//
// Receivers verify in three stages, all required:
//
//  1. Timestamp parses and is within MaxSkew of now (anti-replay).
//  2. Signature decodes as hex and is exactly sha256.Size bytes.
//  3. HMAC-SHA256 over "<timestamp>.<body>" matches in constant time.
//
// Constant-time compare is required — the standard timing-attack hardening
// for any signature verifier. crypto/hmac.Equal does this for us.
type HMACScheme struct {
	Secret  []byte
	MaxSkew time.Duration // default 5 minutes
	Now     func() time.Time
}

// NewHMACScheme returns a scheme with the canonical 5-minute skew.
// Empty secret is permitted — Verify always returns nil for empty secret,
// so callers can use a single code path with the scheme either configured
// or disabled.
func NewHMACScheme(secret []byte) *HMACScheme {
	return &HMACScheme{Secret: secret, MaxSkew: 5 * time.Minute}
}

// Enabled reports whether a non-empty secret is configured. When false,
// Verify is a no-op.
func (s *HMACScheme) Enabled() bool { return s != nil && len(s.Secret) > 0 }

// Sign returns the timestamp and hex-encoded signature for body. Used by
// the bulwark-diun-relay binary; tests import it directly so the relay
// and the receiver can't drift.
func (s *HMACScheme) Sign(body []byte, when time.Time) (timestamp, signature string) {
	ts := strconv.FormatInt(when.Unix(), 10)
	mac := hmac.New(sha256.New, s.Secret)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return ts, hex.EncodeToString(mac.Sum(nil))
}

// Verify returns nil when the (timestamp, signature) pair is valid for
// body within MaxSkew. Empty secret is treated as "verification not
// required" — Verify returns nil immediately. This is the same flow we
// already use for BearerAuth: configure to enable, leave empty to skip.
func (s *HMACScheme) Verify(timestamp, signature string, body []byte) error {
	if !s.Enabled() {
		return nil
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	skew := s.MaxSkew
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	if timestamp == "" || signature == "" {
		return fmt.Errorf("hmac: missing X-Bulwark-Timestamp or X-Bulwark-Signature")
	}
	tsSec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("hmac: timestamp is not an integer")
	}
	t := time.Unix(tsSec, 0)
	delta := now().Sub(t)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return fmt.Errorf("hmac: timestamp out of range (skew %s > %s)", delta, skew)
	}
	gotSig, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("hmac: signature is not valid hex")
	}
	if len(gotSig) != sha256.Size {
		return fmt.Errorf("hmac: signature length is %d, want %d", len(gotSig), sha256.Size)
	}
	mac := hmac.New(sha256.New, s.Secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	want := mac.Sum(nil)
	if !hmac.Equal(gotSig, want) {
		return fmt.Errorf("hmac: signature mismatch")
	}
	return nil
}
