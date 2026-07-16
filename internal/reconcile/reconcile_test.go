package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/verify"
)

type fakeResolver struct {
	rec store.PinRecord
	err error
}

func (f fakeResolver) ResolveIndex(_ context.Context, _ string) (store.PinRecord, error) {
	return f.rec, f.err
}

type fakeGate struct{ v verify.Verdict }

func (f fakeGate) Evaluate(_ context.Context, _ verify.Input) verify.Verdict { return f.v }

type fakeRecorder struct {
	set map[string]store.PinRecord
}

func (f *fakeRecorder) Set(key string, rec store.PinRecord) error {
	if f.set == nil {
		f.set = map[string]store.PinRecord{}
	}
	f.set[key] = rec
	return nil
}

type fakeAuditor struct{ events []store.AuditEvent }

func (f *fakeAuditor) Audit(e store.AuditEvent) { f.events = append(f.events, e) }

func newReconciler(v verify.Verdict, resErr error) (*Reconciler, *fakeRecorder, *fakeAuditor) {
	rec := &fakeRecorder{}
	aud := &fakeAuditor{}
	r := &Reconciler{
		Resolve: fakeResolver{rec: store.PinRecord{IndexDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MediaType: "application/vnd.oci.image.index.v1+json", Arches: []string{"amd64", "arm64"}}, err: resErr},
		Gate:    fakeGate{v: v},
		Pins:    rec,
		Audit:   aud,
	}
	return r, rec, aud
}

func upd() Update {
	return Update{Ref: "nginx:1.27", Stack: "web", Service: "nginx", ComposePath: "/stacks/web/compose.yaml", Source: "diun"}
}

func TestReconcile_Allow_QueuesCandidate(t *testing.T) {
	r, rec, aud := newReconciler(verify.Verdict{Decision: verify.DecisionAllow, Reasons: []string{"signature: trusted", "provenance: trusted builder"}}, nil)
	out, err := r.Reconcile(context.Background(), upd())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !out.Queued || out.Held {
		t.Fatalf("outcome = %+v, want queued", out)
	}
	got, ok := rec.set["web/nginx"]
	if !ok {
		t.Fatal("candidate pin was not recorded")
	}
	if got.CanaryState != store.CanaryCandidate {
		t.Fatalf("canary state = %q, want candidate", got.CanaryState)
	}
	if got.IndexDigest != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || got.Ref != "nginx:1.27" {
		t.Fatalf("pin = %+v, want the resolved index + ref", got)
	}
	if len(aud.events) != 1 || aud.events[0].Action != store.ActionReconcileQueued {
		t.Fatalf("audit = %+v, want one reconcile.queued", aud.events)
	}
}

func TestReconcile_Warn_StillQueues(t *testing.T) {
	r, rec, _ := newReconciler(verify.Verdict{Decision: verify.DecisionWarn, Reasons: []string{"provenance: untrusted"}}, nil)
	out, err := r.Reconcile(context.Background(), upd())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !out.Queued {
		t.Fatalf("warn should still queue for manual promotion; outcome=%+v", out)
	}
	if _, ok := rec.set["web/nginx"]; !ok {
		t.Fatal("warn candidate not recorded")
	}
}

func TestReconcile_Block_HoldsAndDoesNotQueue(t *testing.T) {
	r, rec, aud := newReconciler(verify.Verdict{Decision: verify.DecisionBlock, Reasons: []string{"provenance: untrusted"}}, nil)
	out, err := r.Reconcile(context.Background(), upd())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !out.Held || out.Queued {
		t.Fatalf("outcome = %+v, want held", out)
	}
	if len(rec.set) != 0 {
		t.Fatalf("a blocked update must not be queued, got %+v", rec.set)
	}
	if len(aud.events) != 1 || aud.events[0].Action != store.ActionReconcileHeld {
		t.Fatalf("audit = %+v, want one reconcile.held", aud.events)
	}
}

func TestReconcile_ResolverError_QueuesNothing(t *testing.T) {
	r, rec, _ := newReconciler(verify.Verdict{Decision: verify.DecisionAllow}, errors.New("registry down"))
	if _, err := r.Reconcile(context.Background(), upd()); err == nil {
		t.Fatal("expected an error when the resolver fails")
	}
	if len(rec.set) != 0 {
		t.Fatal("nothing should be queued on a resolver error")
	}
}

func TestReconcile_EmptyIndexDigest_Errors(t *testing.T) {
	r := &Reconciler{Resolve: fakeResolver{rec: store.PinRecord{IndexDigest: ""}}, Gate: fakeGate{v: verify.Verdict{Decision: verify.DecisionAllow}}}
	if _, err := r.Reconcile(context.Background(), upd()); err == nil {
		t.Fatal("expected an error for an empty resolved index digest")
	}
}

func TestReconcile_RequiresStackAndService(t *testing.T) {
	r, _, _ := newReconciler(verify.Verdict{Decision: verify.DecisionAllow}, nil)
	if _, err := r.Reconcile(context.Background(), Update{Ref: "nginx:1.27"}); err == nil {
		t.Fatal("expected an error when stack/service are missing")
	}
}

// TestReconcile_RejectsNonSHA256IndexDigest is the defense-in-depth guard for the
// Recorder path: even if a resolver returns a non-canonical digest, the core must
// refuse to gate or record it as a candidate pin.
func TestReconcile_RejectsNonSHA256IndexDigest(t *testing.T) {
	r := &Reconciler{
		Resolve: fakeResolver{rec: store.PinRecord{IndexDigest: "sha256:abc"}}, // too short
		Gate:    fakeGate{v: verify.Verdict{Decision: verify.DecisionAllow}},
	}
	if _, err := r.Reconcile(context.Background(), Update{Ref: "nginx:1.27", Stack: "s", Service: "web"}); err == nil {
		t.Fatal("Reconcile must refuse a non-sha256 index digest before recording a candidate")
	}
}
