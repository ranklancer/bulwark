package verify

import (
	"context"
	"fmt"
	"time"

	"github.com/bulwark-docker/bulwark/internal/cve"
)

// Gate is the deploy-time trust engine. It composes the signature and
// vulnerability axes into a single Verdict for one candidate image.
type Gate struct {
	Policy    Policy
	Signature SignatureVerifier // nil => signature axis cannot be evaluated
	Vulns     cve.Source        // nil => vulnerability axis cannot be evaluated
	Now       func() time.Time  // injectable clock; nil => time.Now
}

// Input is one image about to be applied.
type Input struct {
	PinnedRef string            // digest-pinned reference the daemon will deploy
	Labels    map[string]string // container labels (break-glass lives here)
}

// Evaluate runs the enabled axes and returns a Verdict.
//
// It is fail-closed: in ModeBlock, an axis that cannot be evaluated (verifier or
// source error, or a nil dependency) is treated as a failure, not a pass. A
// valid break-glass label converts a would-be block into an audited
// DecisionBreakGlass. When verify is disabled, every image is allowed with no
// behavior change.
func (g Gate) Evaluate(ctx context.Context, in Input) Verdict {
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}

	if !g.Policy.Enabled {
		return Verdict{Decision: DecisionAllow, Reasons: []string{"verify disabled"}}
	}

	v := Verdict{Decision: DecisionAllow}
	blocking := false
	warning := false

	// --- signature axis ---
	if sp := g.Policy.Signature; sp.Mode != ModeOff {
		var sr SignatureResult
		if g.Signature == nil {
			sr = SignatureResult{Evaluated: true, Err: fmt.Errorf("no signature verifier configured")}
		} else {
			sr = g.Signature.Verify(ctx, in.PinnedRef, sp)
		}
		v.Signature = sr
		if sr.Err != nil || !sr.Verified {
			reason := "signature: untrusted or unsigned"
			if sr.Err != nil {
				reason = "signature: unable to verify (" + sr.Err.Error() + ")"
			}
			v.Reasons = append(v.Reasons, reason)
			switch sp.Mode {
			case ModeBlock:
				blocking = true
			case ModeWarn:
				warning = true
			}
		} else {
			v.Reasons = append(v.Reasons, "signature: trusted")
		}
	}

	// --- vulnerability axis ---
	if vp := g.Policy.Vuln; vp.enabled() {
		vr := VulnResult{Evaluated: true}
		if g.Vulns == nil {
			vr.Err = fmt.Errorf("no vulnerability source configured")
		} else if vulns, err := g.Vulns.Vulns(ctx, in.PinnedRef); err != nil {
			vr.Err = err
		} else {
			for _, vu := range vulns {
				if vu.Severity >= vp.BlockThreshold {
					vr.Blocking = append(vr.Blocking, vu)
					if vu.Severity > vr.Highest {
						vr.Highest = vu.Severity
					}
				}
			}
		}
		v.Vuln = vr
		if vr.Err != nil || len(vr.Blocking) > 0 {
			var reason string
			if vr.Err != nil {
				reason = "vulnerability: unable to scan (" + vr.Err.Error() + ")"
			} else {
				reason = fmt.Sprintf("vulnerability: %d at/above %s (highest %s)",
					len(vr.Blocking), vp.BlockThreshold, vr.Highest)
			}
			v.Reasons = append(v.Reasons, reason)
			switch vp.Mode {
			case ModeBlock:
				blocking = true
			case ModeWarn:
				warning = true
			}
		} else {
			v.Reasons = append(v.Reasons, "vulnerability: clean")
		}
	}

	// --- combine (block > break-glass > warn > allow) ---
	switch {
	case blocking:
		bg, ok := parseBreakGlass(in.Labels, now())
		if ok {
			v.BreakGlass = &bg
			v.Decision = DecisionBreakGlass
			exp := "no expiry"
			if !bg.Expires.IsZero() {
				exp = "expires " + bg.Expires.Format(time.RFC3339)
			}
			v.Reasons = append(v.Reasons, "break-glass override: "+bg.Reason+" ("+exp+")")
		} else {
			v.Decision = DecisionBlock
			if bg.Reason != "" && bg.Expired {
				v.Reasons = append(v.Reasons, "break-glass present but expired — blocking")
			}
		}
	case warning:
		v.Decision = DecisionWarn
	default:
		v.Decision = DecisionAllow
	}
	return v
}
