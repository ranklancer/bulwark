package verify

import "testing"

func TestMode_String(t *testing.T) {
	cases := map[Mode]string{ModeOff: "off", ModeWarn: "warn", ModeBlock: "block", Mode(99): "off"}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String()=%q want %q", m, got, want)
		}
	}
}

func TestParseMode(t *testing.T) {
	ok := map[string]Mode{"": ModeOff, "off": ModeOff, "OFF": ModeOff, " warn ": ModeWarn, "Block": ModeBlock}
	for in, want := range ok {
		m, err := ParseMode(in)
		if err != nil || m != want {
			t.Errorf("ParseMode(%q)=%v,%v want %v,nil", in, m, err, want)
		}
	}
	if m, err := ParseMode("bogus"); err == nil || m != ModeOff {
		t.Errorf("ParseMode(bogus)=%v,%v want off,error", m, err)
	}
}

func TestVerdict_Accessors(t *testing.T) {
	block := Verdict{Decision: DecisionBlock, Reasons: []string{"signature: untrusted", "vulnerability: 2 at/above high"}}
	if !block.Blocked() || block.Allowed() {
		t.Fatal("block verdict must be Blocked and not Allowed")
	}
	if got := block.Summary(); got != "signature: untrusted; vulnerability: 2 at/above high" {
		t.Fatalf("Summary=%q", got)
	}
	for _, d := range []Decision{DecisionAllow, DecisionWarn, DecisionBreakGlass} {
		v := Verdict{Decision: d}
		if v.Blocked() || !v.Allowed() {
			t.Fatalf("decision %s must be Allowed and not Blocked", d)
		}
	}
	if got := (Verdict{}).Summary(); got != "" {
		t.Fatalf("empty verdict Summary=%q want empty", got)
	}
}

func TestProvenancePolicy_predicateTypesOrDefault(t *testing.T) {
	if got := (ProvenancePolicy{}).predicateTypesOrDefault(); len(got) != 1 || got[0] != "slsaprovenance" {
		t.Fatalf("unset must default to slsaprovenance, got %v", got)
	}
	custom := ProvenancePolicy{PredicateTypes: []string{"https://slsa.dev/provenance/v1", "spdx"}}
	if got := custom.predicateTypesOrDefault(); len(got) != 2 || got[0] != "https://slsa.dev/provenance/v1" {
		t.Fatalf("configured types must pass through, got %v", got)
	}
}
