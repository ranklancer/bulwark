package verify

import (
	"strings"
	"time"
)

// Break-glass is expressed as container labels so a deliberate, one-off deploy
// of an otherwise-blocked image is easy to authorize — but never silent. Every
// honored override is stamped into the append-only audit log and counted in
// /metrics.
const (
	// LabelBreakGlass carries the human reason for the override. A non-empty
	// value is required to activate break-glass.
	LabelBreakGlass = "bulwark.verify.break-glass"
	// LabelBreakGlassExpires optionally bounds the override with an RFC3339
	// timestamp. Past or unparseable expiries are not honored (fail-closed).
	LabelBreakGlassExpires = "bulwark.verify.break-glass-expires"
)

// BreakGlass describes a parsed break-glass override.
type BreakGlass struct {
	Reason  string
	Expires time.Time // zero value == no expiry set
	Expired bool      // true when an expiry was set and is in the past/invalid
}

// parseBreakGlass reads the break-glass labels. ok is true only when a
// non-empty reason is present AND either no expiry is set or the expiry is in
// the future relative to now. A present-but-past (or unparseable) expiry yields
// ok=false with Expired=true so callers can surface "break-glass expired"
// rather than silently blocking.
func parseBreakGlass(labels map[string]string, now time.Time) (bg BreakGlass, ok bool) {
	reason := strings.TrimSpace(labels[LabelBreakGlass])
	if reason == "" {
		return BreakGlass{}, false
	}
	bg.Reason = reason
	if raw := strings.TrimSpace(labels[LabelBreakGlassExpires]); raw != "" {
		exp, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			bg.Expired = true
			return bg, false
		}
		bg.Expires = exp
		if !now.Before(exp) {
			bg.Expired = true
			return bg, false
		}
	}
	return bg, true
}
