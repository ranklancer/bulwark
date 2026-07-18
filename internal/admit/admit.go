// Package admit implements the admission-gate design Phase 1: the deploy-time supply-chain
// admission gate. It answers "may this workload be deployed?" for the images in
// a deploy target by composing a new pin-state axis with the existing the trust engine trust
// engine (internal/verify), and aggregating per-image verdicts into a single
// ALLOW / WARN / BREAK_GLASS / BLOCK decision whose exit-code contract gates
// `docker compose up` (and, in later phases, any capture.Source backend).
//
// It reuses — never re-implements — the trust engine: signature, provenance/SBOM
// and vulnerability verification (and break-glass, and fail-closed semantics) all
// live in internal/verify. the admission gate adds only the pin-state axis and the aggregation,
// at the deploy boundary rather than the auto-apply boundary.
package admit

import (
	"context"

	"github.com/ranklancer/bulwark/internal/verify"
)

// Decision is the terminal outcome of an admission. It mirrors verify.Decision so
// the exit-code contract is identical to the trust engine's.
type Decision string

const (
	// DecisionAllow: every axis passed. Deploy proceeds (exit 0).
	DecisionAllow Decision = "allow"
	// DecisionWarn: an axis failed only in warn mode. Deploy proceeds (exit 0).
	DecisionWarn Decision = "warn"
	// DecisionBreakGlass: a block-mode axis failed but a valid, audited break-glass
	// applied. Deploy proceeds (exit 0), loudly and on the audit trail.
	DecisionBreakGlass Decision = "break_glass"
	// DecisionBlock: a block-mode axis failed with no break-glass. Deploy stops
	// (non-zero exit).
	DecisionBlock Decision = "block"
)

// rank orders decisions from most permissive (0) to most restrictive (3) so an
// aggregate is the worst across images. BreakGlass ranks above Warn (it proceeds,
// but represents an overridden would-block) and below Block.
func rank(d Decision) int {
	switch d {
	case DecisionBlock:
		return 3
	case DecisionBreakGlass:
		return 2
	case DecisionWarn:
		return 1
	default:
		return 0
	}
}

// worse returns the more restrictive of two decisions.
func worse(a, b Decision) Decision {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// fromVerify maps a verify.Decision to the admit.Decision of the same name.
func fromVerify(d verify.Decision) Decision {
	switch d {
	case verify.DecisionBlock:
		return DecisionBlock
	case verify.DecisionBreakGlass:
		return DecisionBreakGlass
	case verify.DecisionWarn:
		return DecisionWarn
	case verify.DecisionAllow:
		return DecisionAllow
	default:
		// Unknown/unhandled trust decision fails closed: an admission gate must
		// never silently ALLOW on a verdict it cannot classify.
		return DecisionBlock
	}
}

// TrustGate is the trust engine trust-engine surface the admission engine consumes. It is
// satisfied by *verify.Gate; a fake is injected in tests. A nil TrustGate means
// the trust axes cannot be evaluated (equivalent to verify being disabled).
type TrustGate interface {
	Evaluate(ctx context.Context, in verify.Input) verify.Verdict
}

// Image is one service image about to be deployed.
type Image struct {
	Service   string            // compose service (or Source target/service)
	Ref       string            // the reference as written, e.g. "nginx:1.27" or "...@sha256:..."
	Pinned    bool              // digest-pinned (ref carries @sha256: OR the pin store holds a digest)
	PinnedRef string            // the digest-pinned reference handed to the trust engine (== Ref when already pinned)
	PinSource string            // provenance of the pin: "literal" | "var" (${VAR}/.env-resolved) | "store" | "" (unpinned)
	Labels    map[string]string // container labels; a valid break-glass lives here (passed to verify)

	// PinStoreErr, when non-nil, means the pin-store read/parse for this
	// image failed (the admission-gate design fail-closed pin-state model, case 3): the pin
	// state is UNKNOWN, NOT "unpinned". This is distinct from a healthy
	// store that genuinely has no pin recorded (case 2, PinStoreErr==nil,
	// Pinned==false), which keeps existing --pin-mode policy unchanged.
	// Engine.Admit forces a BLOCK decision for this image whenever
	// PinStoreErr is set, regardless of Policy.Pin (warn/off/block all
	// block), and skips the trust axis entirely since it cannot know
	// whether the image was pinned. Set by cmd/bulwark/admit.go from the
	// error admitPinState receives off store.PinStore.Get.
	PinStoreErr error
}

// ImageResult is the per-image admission outcome.
type ImageResult struct {
	Service   string          `json:"service"`
	Ref       string          `json:"ref"`
	Pinned    bool            `json:"pinned"`
	PinSource string          `json:"pin_source,omitempty"` // literal | var | store
	Decision  Decision        `json:"decision"`
	Trust     *verify.Verdict `json:"-"` // in-memory only; never serialized (keeps verifier paths out of machine output)
	Reasons   []string        `json:"reasons,omitempty"`
}

// Verdict is the aggregate admission answer for a deploy target.
type Verdict struct {
	Decision Decision      `json:"decision"`
	Images   []ImageResult `json:"images"`
}

// Allowed reports whether the deploy may proceed (allow/warn/break-glass); only
// block stops it. This is the exit-code contract: Allowed() => exit 0.
func (v Verdict) Allowed() bool { return v.Decision != DecisionBlock }

// Blocked is the inverse of Allowed.
func (v Verdict) Blocked() bool { return v.Decision == DecisionBlock }

// Policy is the admission policy. The pin-state axis mode is the admission gate-specific; the
// signature/provenance/vulnerability policy is the reused the trust engine policy carried on
// the Gate, so it is not duplicated here.
type Policy struct {
	// Pin is the pin-state axis enforcement mode: an unpinned image is a no-op
	// under ModeOff, a warning under ModeWarn, and a block under ModeBlock.
	Pin verify.Mode
}

// Engine is the deploy-time admission engine.
type Engine struct {
	Policy Policy
	Gate   TrustGate // nil => trust axes are not evaluated (verify disabled)
}

// Admit evaluates every image and returns per-image plus aggregate verdicts.
//
// Design (fail-closed, progressive):
//   - Pin-state axis: an UNPINNED image cannot have its signature/SBOM/provenance/
//     vulnerability verified (there is no digest to attest), so the pin-state axis
//     is the gate for it — ModeBlock blocks, ModeWarn warns, ModeOff allows. To
//     actually enforce the trust axes you must first enforce pinning; you cannot
//     verify what you cannot address.
//   - Trust axes: a PINNED image is handed to the trust engine trust engine, whose own
//     fail-closed semantics apply (an unevaluable block-mode axis blocks). Its
//     verdict (allow/warn/break-glass/block) becomes the image's trust decision.
//   - The per-image decision is the worse of the pin-state and trust decisions;
//     the aggregate is the worst across all images.
//
// When Gate is nil, the trust axes are skipped (verify disabled): a pinned image
// gets the pin-state result only, with no behavior change.
func (e Engine) Admit(ctx context.Context, images []Image) Verdict {
	agg := DecisionAllow
	results := make([]ImageResult, 0, len(images))
	for _, img := range images {
		r := ImageResult{Service: img.Service, Ref: img.Ref, Pinned: img.Pinned, PinSource: img.PinSource, Decision: DecisionAllow}

		if img.PinStoreErr != nil {
			// Fail closed irrespective of --pin-mode (case 3 of the admission-gate design
			// pin-state model): a pin-store read/parse error means we
			// cannot determine whether this image was pinned, so we must
			// not silently treat it as "unpinned" -- under warn/off that
			// would admit the deploy and skip the trust axis on a possibly
			// genuinely-pinned, previously-trusted image. The reason is
			// deliberately generic (never the raw filesystem error) so it
			// cannot leak local paths into the admission report.
			r.Decision = DecisionBlock
			r.Reasons = append(r.Reasons, "pin: cannot determine pin state (pin-store read failed, failing closed)")
			agg = worse(agg, r.Decision)
			results = append(results, r)
			continue
		}

		if !img.Pinned {
			switch e.Policy.Pin {
			case verify.ModeBlock:
				r.Decision = DecisionBlock
				r.Reasons = append(r.Reasons, "pin: image is not digest-pinned (block)")
			case verify.ModeWarn:
				r.Decision = DecisionWarn
				r.Reasons = append(r.Reasons, "pin: image is not digest-pinned (warn) — pin it to enable the trust axes")
			}
		} else if e.Gate != nil {
			v := e.Gate.Evaluate(ctx, verify.Input{PinnedRef: img.PinnedRef, Labels: img.Labels})
			r.Trust = &v
			d := fromVerify(v.Decision)
			r.Decision = worse(r.Decision, d)
			// Surface only the path-free remediation code, never the verifier's
			// free-text reasons (which can embed local cosign/trivy paths). The raw
			// verdict stays in Trust (json:"-"), out of machine output.
			reason := "trust: " + string(d)
			if rc := v.Remediation(); rc != verify.RemediationNone {
				reason += " (" + string(rc) + ")"
			}
			r.Reasons = append(r.Reasons, reason)
		} else {
			r.Reasons = append(r.Reasons, "trust: verification disabled (no gate configured)")
		}

		agg = worse(agg, r.Decision)
		results = append(results, r)
	}
	return Verdict{Decision: agg, Images: results}
}
