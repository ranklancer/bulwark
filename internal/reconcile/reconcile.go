// Package reconcile implements the trust engine deploy-time reconcile flow: given a
// detected image update (from a DIUN webhook or a manual `bulwark reconcile`),
// it resolves the authoritative multi-arch INDEX digest (digest pinning), runs the trust
// gate (signature + provenance + vulnerability), and — per an internal note — QUEUES a
// verified update as a canary candidate for MANUAL promotion. A blocked update
// is held (audited + surfaced), never queued. Auto-starting the canary is opt-in
// and deferred to a later phase.
package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

// Update is a detected image update to reconcile.
type Update struct {
	Ref         string // image reference, e.g. "nginx:1.27"
	Stack       string // stack name; the pins key is "<stack>/<service>"
	Service     string // service name
	ComposePath string // host compose file, when known (for later rollback)
	Source      string // adapter/source label for the pin record
}

func (u Update) key() string { return u.Stack + "/" + u.Service }

// IndexResolver resolves the authoritative multi-arch INDEX digest for a ref
// into a PinRecord skeleton (IndexDigest/MediaType/Arches populated).
type IndexResolver interface {
	ResolveIndex(ctx context.Context, ref string) (store.PinRecord, error)
}

// Verdicter evaluates the deploy-time trust gate for a pinned reference.
type Verdicter interface {
	Evaluate(ctx context.Context, in verify.Input) verify.Verdict
}

// Recorder queues a candidate pin (satisfied by *store.PinStore).
type Recorder interface {
	Set(key string, rec store.PinRecord) error
}

// Auditor appends an audit event (satisfied by *store.Store).
type Auditor interface {
	Audit(store.AuditEvent)
}

// Outcome summarises one reconcile.
type Outcome struct {
	Key       string
	PinnedRef string // ref@sha256:<index>
	Decision  verify.Decision
	Queued    bool // recorded as a candidate for manual promotion
	Held      bool // gate blocked; not queued
	Reasons   []string
}

// Reconciler drives capture -> gate -> queue/hold. All collaborators are
// interfaces so the flow is unit-testable without a registry, Docker, or disk.
type Reconciler struct {
	Resolve IndexResolver
	Gate    Verdicter
	Pins    Recorder // optional; when nil, a verified update is not persisted
	Audit   Auditor  // optional
	Now     func() time.Time

	// AutoStartCanary is opt-in (an internal note). When false (the default), a verified
	// update is queued as a candidate for MANUAL promotion and the canary is not
	// started automatically. Auto-start is deferred to a later phase.
	AutoStartCanary bool
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile resolves, gates, and queues/holds one detected update. It is
// fail-safe: a resolver error is returned (nothing is queued); a gate BLOCK
// holds the update; allow/warn/break-glass queue a candidate.
func (r *Reconciler) Reconcile(ctx context.Context, u Update) (Outcome, error) {
	out := Outcome{Key: u.key()}
	if r.Resolve == nil || r.Gate == nil {
		return out, fmt.Errorf("reconcile: a resolver and a gate are required")
	}
	if u.Service == "" || u.Stack == "" {
		return out, fmt.Errorf("reconcile: stack and service are required")
	}

	rec, err := r.Resolve.ResolveIndex(ctx, u.Ref)
	if err != nil {
		return out, fmt.Errorf("reconcile: resolve index digest for %q: %w", u.Ref, err)
	}
	if rec.IndexDigest == "" {
		return out, fmt.Errorf("reconcile: resolver returned an empty index digest for %q", u.Ref)
	}
	rec.Ref = u.Ref
	rec.Service = u.Service
	if u.ComposePath != "" {
		rec.ComposePath = u.ComposePath
	}
	if u.Source != "" {
		rec.Source = u.Source
	}
	out.PinnedRef = u.Ref + "@" + rec.IndexDigest

	v := r.Gate.Evaluate(ctx, verify.Input{PinnedRef: out.PinnedRef})
	out.Decision = v.Decision
	out.Reasons = v.Reasons

	if v.Blocked() {
		out.Held = true
		r.audit(store.ActionReconcileHeld, u.key(), rec, "gate blocked; update held — "+v.Summary())
		return out, nil
	}

	// Allowed (allow / warn / break-glass): queue a candidate for MANUAL
	// promotion. The gate has already confirmed a verified, digest-pinned ref.
	rec.CanaryState = store.CanaryCandidate
	rec.CapturedAt = r.now().UTC().Format(time.RFC3339)
	if r.Pins != nil {
		if err := r.Pins.Set(u.key(), rec); err != nil {
			return out, fmt.Errorf("reconcile: record candidate pin: %w", err)
		}
	}
	out.Queued = true
	note := "verified; queued as candidate for manual promotion"
	if v.Decision == verify.DecisionWarn {
		note = "verified with warnings; queued as candidate for manual promotion"
	}
	r.audit(store.ActionReconcileQueued, u.key(), rec, note+" — "+v.Summary())
	// AutoStartCanary is intentionally deferred (an internal note default: manual).
	return out, nil
}

func (r *Reconciler) audit(action, key string, rec store.PinRecord, detail string) {
	if r.Audit == nil {
		return
	}
	r.Audit.Audit(store.AuditEvent{
		Time:      r.now().UTC(),
		Action:    action,
		Container: key,
		Image:     rec.Ref + "@" + rec.IndexDigest,
		Digest:    rec.IndexDigest,
		Detail:    detail,
	})
}
