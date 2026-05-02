package types

import (
	"encoding/json"
	"testing"
)

func TestRiskLevel_RoundTripJSON(t *testing.T) {
	cases := []RiskLevel{RiskUnknown, RiskSafe, RiskReview, RiskBreaking}
	for _, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %v: %v", in, err)
		}
		var out RiskLevel
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if out != in {
			t.Errorf("round-trip %v → %s → %v", in, b, out)
		}
	}
}

func TestRiskLevel_UnmarshalLegacyNumeric(t *testing.T) {
	var r RiskLevel
	if err := json.Unmarshal([]byte("2"), &r); err != nil {
		t.Fatalf("unmarshal numeric: %v", err)
	}
	if r != RiskReview {
		t.Errorf("legacy numeric 2 = %v, want RiskReview", r)
	}
}

func TestChangeKind_RoundTripJSON(t *testing.T) {
	cases := []ChangeKind{
		ChangeUnknown, ChangeDigest, ChangePatch, ChangeMinor, ChangeMajor,
		ChangePrerelease, ChangeLSIORebuild, ChangeLatest, ChangeNone,
	}
	for _, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %v: %v", in, err)
		}
		var out ChangeKind
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if out != in {
			t.Errorf("round-trip %v → %s → %v", in, b, out)
		}
	}
}

func TestConfidence_RoundTripJSON(t *testing.T) {
	cases := []Confidence{ConfidenceUnknown, ConfidenceLow, ConfidenceMedium, ConfidenceHigh}
	for _, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %v: %v", in, err)
		}
		var out Confidence
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if out != in {
			t.Errorf("round-trip %v → %s → %v", in, b, out)
		}
	}
}

func TestUnmarshalJSON_NullSafe(t *testing.T) {
	var r RiskLevel
	if err := json.Unmarshal([]byte("null"), &r); err != nil {
		t.Errorf("RiskLevel null: %v", err)
	}
	if r != RiskUnknown {
		t.Errorf("null → %v, want Unknown", r)
	}
}
