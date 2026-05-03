package notifier

import (
	"testing"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestDigestBuffer_AddDrain(t *testing.T) {
	b := NewDigestBuffer()
	if got := b.Len(); got != 0 {
		t.Errorf("fresh buffer Len = %d", got)
	}
	if got := b.Drain(); got != nil {
		t.Errorf("empty Drain = %v, want nil", got)
	}

	b.Add([]Event{{Container: "a"}, {Container: "b"}})
	if got := b.Len(); got != 2 {
		t.Errorf("Len after add = %d, want 2", got)
	}

	b.Add([]Event{{Container: "c"}})
	if got := b.Len(); got != 3 {
		t.Errorf("Len after second add = %d, want 3", got)
	}

	out := b.Drain()
	if len(out) != 3 {
		t.Errorf("drained = %d, want 3", len(out))
	}
	if out[0].Container != "a" || out[2].Container != "c" {
		t.Errorf("Drain order = %+v", out)
	}
	if got := b.Len(); got != 0 {
		t.Errorf("Len after drain = %d, want 0", got)
	}
}

func TestDigestBuffer_NilSafe(t *testing.T) {
	var b *DigestBuffer
	b.Add([]Event{{Container: "x"}}) // must not panic
	if got := b.Len(); got != 0 {
		t.Errorf("nil receiver Len = %d", got)
	}
	if got := b.Drain(); got != nil {
		t.Errorf("nil Drain = %v, want nil", got)
	}
}

func TestIsUrgent(t *testing.T) {
	cases := []struct {
		name string
		e    Event
		want bool
	}{
		{"safe immediate", Event{Risk: types.RiskSafe}, false},
		{"review immediate", Event{Risk: types.RiskReview}, false},
		{"breaking always urgent", Event{Risk: types.RiskBreaking}, true},
		{"rollback always urgent", Event{Risk: types.RiskSafe, Action: types.ActionRolledBack}, true},
		{"stack-skipped always urgent", Event{Risk: types.RiskSafe, Action: types.ActionStackSkipped}, true},
		{"synthetic bypasses queue", Event{Risk: types.RiskSafe, Synthetic: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUrgent(tc.e); got != tc.want {
				t.Errorf("IsUrgent(%+v) = %v, want %v", tc.e, got, tc.want)
			}
		})
	}
}

func TestSplitForDigest_PreservesInputOrderWithinPartitions(t *testing.T) {
	events := []Event{
		{Container: "safe1", Risk: types.RiskSafe},
		{Container: "breaking", Risk: types.RiskBreaking},
		{Container: "review", Risk: types.RiskReview},
		{Container: "rollback", Risk: types.RiskSafe, Action: types.ActionRolledBack},
		{Container: "safe2", Risk: types.RiskSafe},
	}
	urgent, buffered := SplitForDigest(events)
	if len(urgent) != 2 {
		t.Errorf("urgent count = %d, want 2", len(urgent))
	}
	if len(buffered) != 3 {
		t.Errorf("buffered count = %d, want 3", len(buffered))
	}
	// Order preserved within partitions.
	if urgent[0].Container != "breaking" || urgent[1].Container != "rollback" {
		t.Errorf("urgent order = %+v", urgent)
	}
	if buffered[0].Container != "safe1" || buffered[1].Container != "review" || buffered[2].Container != "safe2" {
		t.Errorf("buffered order = %+v", buffered)
	}
}

func TestSplitForDigest_AllUrgent(t *testing.T) {
	events := []Event{
		{Risk: types.RiskBreaking},
		{Risk: types.RiskSafe, Action: types.ActionRolledBack},
	}
	urgent, buffered := SplitForDigest(events)
	if len(urgent) != 2 {
		t.Errorf("urgent = %d", len(urgent))
	}
	if len(buffered) != 0 {
		t.Errorf("buffered = %d", len(buffered))
	}
}

func TestSplitForDigest_AllBuffered(t *testing.T) {
	events := []Event{
		{Risk: types.RiskSafe},
		{Risk: types.RiskReview},
	}
	urgent, buffered := SplitForDigest(events)
	if len(urgent) != 0 {
		t.Errorf("urgent = %d", len(urgent))
	}
	if len(buffered) != 2 {
		t.Errorf("buffered = %d", len(buffered))
	}
}
