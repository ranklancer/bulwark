package admit

import (
	"context"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/verify"
)

// fakeGate returns a preset verify.Decision per PinnedRef (default allow).
type fakeGate struct{ byRef map[string]verify.Decision }

func (f fakeGate) Evaluate(_ context.Context, in verify.Input) verify.Verdict {
	d := verify.DecisionAllow
	if x, ok := f.byRef[in.PinnedRef]; ok {
		d = x
	}
	return verify.Verdict{Decision: d, Reasons: []string{"fake:" + string(d)}}
}

func pinned(service, ref string) Image {
	return Image{Service: service, Ref: ref, Pinned: true, PinnedRef: ref}
}
func unpinned(service, ref string) Image { return Image{Service: service, Ref: ref} }

func TestAdmit_AllPinnedAllowed(t *testing.T) {
	e := Engine{Policy: Policy{Pin: verify.ModeBlock}, Gate: fakeGate{}}
	v := e.Admit(context.Background(), []Image{pinned("web", "nginx@sha256:a"), pinned("db", "pg@sha256:b")})
	if !v.Allowed() || v.Decision != DecisionAllow {
		t.Fatalf("want allow, got %+v", v)
	}
}

func TestAdmit_TrustBlockBlocks(t *testing.T) {
	g := fakeGate{byRef: map[string]verify.Decision{"bad@sha256:x": verify.DecisionBlock}}
	e := Engine{Policy: Policy{Pin: verify.ModeWarn}, Gate: g}
	v := e.Admit(context.Background(), []Image{pinned("web", "good@sha256:y"), pinned("db", "bad@sha256:x")})
	if !v.Blocked() {
		t.Fatalf("a block-mode trust failure must block the deploy: %+v", v)
	}
	// Per-image: only the bad one blocks.
	if v.Images[0].Decision != DecisionAllow || v.Images[1].Decision != DecisionBlock {
		t.Fatalf("per-image decisions wrong: %+v", v.Images)
	}
}

func TestAdmit_UnpinnedPinModes(t *testing.T) {
	cases := []struct {
		mode verify.Mode
		want Decision
	}{
		{verify.ModeBlock, DecisionBlock},
		{verify.ModeWarn, DecisionWarn},
		{verify.ModeOff, DecisionAllow},
	}
	for _, c := range cases {
		e := Engine{Policy: Policy{Pin: c.mode}, Gate: fakeGate{}}
		v := e.Admit(context.Background(), []Image{unpinned("web", "nginx:1.27")})
		if v.Decision != c.want {
			t.Fatalf("pin-mode %v: want %s, got %s", c.mode, c.want, v.Decision)
		}
		if (c.want == DecisionBlock) == v.Allowed() {
			t.Fatalf("pin-mode %v: exit-code contract wrong (Allowed=%v)", c.mode, v.Allowed())
		}
	}
}

func TestAdmit_UnpinnedNeverConsultsGate(t *testing.T) {
	// An unpinned image has no digest to verify; the gate must not be consulted
	// (it would evaluate the wrong/empty ref). Trust stays nil for it.
	e := Engine{Policy: Policy{Pin: verify.ModeWarn}, Gate: fakeGate{byRef: map[string]verify.Decision{"": verify.DecisionBlock}}}
	v := e.Admit(context.Background(), []Image{unpinned("web", "nginx:1.27")})
	if v.Images[0].Trust != nil {
		t.Fatalf("unpinned image must not carry a trust verdict: %+v", v.Images[0])
	}
	if v.Decision != DecisionWarn {
		t.Fatalf("want warn from pin axis only, got %s", v.Decision)
	}
}

func TestAdmit_AggregateWorst(t *testing.T) {
	g := fakeGate{byRef: map[string]verify.Decision{"c@sha256:1": verify.DecisionBlock}}
	e := Engine{Policy: Policy{Pin: verify.ModeWarn}, Gate: g}
	// one warn (unpinned), one block (trust) -> aggregate block.
	v := e.Admit(context.Background(), []Image{unpinned("a", "a:1"), pinned("c", "c@sha256:1")})
	if v.Decision != DecisionBlock {
		t.Fatalf("aggregate must be the worst (block): %+v", v)
	}
}

func TestAdmit_BreakGlassProceeds(t *testing.T) {
	g := fakeGate{byRef: map[string]verify.Decision{"x@sha256:9": verify.DecisionBreakGlass}}
	e := Engine{Policy: Policy{Pin: verify.ModeBlock}, Gate: g}
	v := e.Admit(context.Background(), []Image{pinned("x", "x@sha256:9")})
	if v.Decision != DecisionBreakGlass || !v.Allowed() {
		t.Fatalf("break-glass must proceed (exit 0) as break_glass: %+v", v)
	}
}

func TestAdmit_NilGateSkipsTrust(t *testing.T) {
	e := Engine{Policy: Policy{Pin: verify.ModeBlock}} // Gate nil
	v := e.Admit(context.Background(), []Image{pinned("web", "nginx@sha256:a")})
	if v.Decision != DecisionAllow || v.Images[0].Trust != nil {
		t.Fatalf("nil gate => trust skipped, pinned image allowed: %+v", v)
	}
}

func TestAdmit_Empty(t *testing.T) {
	v := Engine{Policy: Policy{Pin: verify.ModeBlock}, Gate: fakeGate{}}.Admit(context.Background(), nil)
	if v.Decision != DecisionAllow || len(v.Images) != 0 {
		t.Fatalf("empty target => allow, no images: %+v", v)
	}
}

func TestWorseOrdering(t *testing.T) {
	if worse(DecisionAllow, DecisionWarn) != DecisionWarn ||
		worse(DecisionWarn, DecisionBreakGlass) != DecisionBreakGlass ||
		worse(DecisionBreakGlass, DecisionBlock) != DecisionBlock ||
		worse(DecisionBlock, DecisionWarn) != DecisionBlock {
		t.Fatal("worse() ordering incorrect")
	}
}
