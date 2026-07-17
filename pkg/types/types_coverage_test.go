package types

import (
	"encoding/json"
	"testing"
)

func TestChangeKind_JSONRoundTripAndParse(t *testing.T) {
	all := []ChangeKind{ChangeUnknown, ChangeDigest, ChangePatch, ChangeMinor, ChangeMajor, ChangePrerelease, ChangeLSIORebuild, ChangeLatest, ChangeNone}
	for _, c := range all {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal %v: %v", c, err)
		}
		var got ChangeKind
		if err := json.Unmarshal(b, &got); err != nil || got != c {
			t.Fatalf("round-trip %v: got %v err %v", c, got, err)
		}
	}
	// numeric legacy form
	var c ChangeKind
	if err := c.UnmarshalJSON([]byte("3")); err != nil || c != ChangeMinor {
		t.Fatalf("numeric: %v %v", c, err)
	}
	// null and empty -> unknown
	if err := c.UnmarshalJSON([]byte("null")); err != nil || c != ChangeUnknown {
		t.Fatalf("null: %v %v", c, err)
	}
	// unrecognised string -> unknown
	if err := c.UnmarshalJSON([]byte(`"bogus"`)); err != nil || c != ChangeUnknown {
		t.Fatalf("bogus string: %v %v", c, err)
	}
	// invalid numeric -> error
	if err := c.UnmarshalJSON([]byte("xx")); err == nil {
		t.Fatal("invalid numeric must error")
	}
	// bad quoted -> error
	if err := c.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Fatal("bad quote must error")
	}
}

func TestConfidence_JSONRoundTrip(t *testing.T) {
	for _, c := range []Confidence{ConfidenceUnknown, ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		b, _ := json.Marshal(c)
		var got Confidence
		if err := json.Unmarshal(b, &got); err != nil || got != c {
			t.Fatalf("round-trip %v: got %v err %v", c, got, err)
		}
	}
	var c Confidence
	if err := c.UnmarshalJSON([]byte("2")); err != nil || c != ConfidenceMedium {
		t.Fatalf("numeric: %v %v", c, err)
	}
	if err := c.UnmarshalJSON([]byte("null")); err != nil || c != ConfidenceUnknown {
		t.Fatalf("null: %v %v", c, err)
	}
	if err := c.UnmarshalJSON([]byte(`"nope"`)); err != nil || c != ConfidenceUnknown {
		t.Fatalf("bad string: %v %v", c, err)
	}
	if err := c.UnmarshalJSON([]byte("zz")); err == nil {
		t.Fatal("invalid numeric must error")
	}
}

func TestRiskLevel_UnmarshalErrors(t *testing.T) {
	var r RiskLevel
	if err := r.UnmarshalJSON([]byte("zz")); err == nil {
		t.Fatal("invalid numeric must error")
	}
	if err := r.UnmarshalJSON([]byte(`"bad`)); err == nil {
		t.Fatal("bad quote must error")
	}
	if err := r.UnmarshalJSON([]byte("null")); err != nil || r != RiskUnknown {
		t.Fatalf("null: %v %v", r, err)
	}
}

func TestSecurityUrgency_StringMarshalUnmarshal(t *testing.T) {
	want := map[SecurityUrgency]string{UrgencyNone: "none", UrgencyRecommended: "recommended", UrgencyUrgent: "urgent", SecurityUrgency(9): "none"}
	for u, s := range want {
		if u.String() != s {
			t.Errorf("String(%d)=%q want %q", u, u.String(), s)
		}
	}
	for _, u := range []SecurityUrgency{UrgencyNone, UrgencyRecommended, UrgencyUrgent} {
		b, _ := json.Marshal(u)
		var got SecurityUrgency
		if err := json.Unmarshal(b, &got); err != nil || got != u {
			t.Fatalf("round-trip %v: %v %v", u, got, err)
		}
	}
	var u SecurityUrgency
	if err := u.UnmarshalJSON([]byte("2")); err != nil || u != UrgencyUrgent {
		t.Fatalf("numeric: %v %v", u, err)
	}
	if err := u.UnmarshalJSON([]byte("null")); err != nil || u != UrgencyNone {
		t.Fatalf("null: %v %v", u, err)
	}
	if err := u.UnmarshalJSON([]byte(`"other"`)); err != nil || u != UrgencyNone {
		t.Fatalf("bad string: %v %v", u, err)
	}
	if err := u.UnmarshalJSON([]byte("qq")); err == nil {
		t.Fatal("invalid numeric must error")
	}
}

func TestImageInfo_Reference(t *testing.T) {
	cases := []struct {
		in   ImageInfo
		want string
	}{
		{ImageInfo{Repository: "lscr.io/x/sonarr"}, "lscr.io/x/sonarr"},
		{ImageInfo{Repository: "r", Tag: "1.0"}, "r:1.0"},
		{ImageInfo{Repository: "r", Tag: "1.0", Digest: "sha256:abc"}, "r:1.0@sha256:abc"},
		{ImageInfo{Repository: "r", Digest: "sha256:abc"}, "r@sha256:abc"},
	}
	for _, c := range cases {
		if got := c.in.Reference(); got != c.want {
			t.Errorf("Reference(%+v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSecurityAssessment_Summary(t *testing.T) {
	if (*SecurityAssessment)(nil).Summary() != "" {
		t.Fatal("nil summary must be empty")
	}
	if (&SecurityAssessment{ClosedCount: 0}).Summary() != "" {
		t.Fatal("zero-closed summary must be empty")
	}
	urgent := &SecurityAssessment{Urgency: UrgencyUrgent, ClosedCount: 7, CriticalClosed: 2, HighClosed: 5, Source: "trivy"}
	if got := urgent.Summary(); got != "security-urgent: closes 2 CRITICAL, 5 HIGH (trivy)" {
		t.Fatalf("urgent summary=%q", got)
	}
	rec := &SecurityAssessment{Urgency: UrgencyRecommended, ClosedCount: 3, HighClosed: 3}
	if got := rec.Summary(); got != "security-recommended: closes 3 HIGH" {
		t.Fatalf("recommended summary=%q", got)
	}
	plain := &SecurityAssessment{Urgency: UrgencyNone, ClosedCount: 4}
	if got := plain.Summary(); got != "security: closes 4 CVE" {
		t.Fatalf("plain summary=%q", got)
	}
}

func TestUpdateAction_String(t *testing.T) {
	want := map[UpdateAction]string{
		ActionUnknown: "unknown", ActionAutoUpdated: "auto-updated", ActionNeedsReview: "needs-review",
		ActionBlocked: "blocked", ActionRolledBack: "rolled-back", ActionSkipped: "skipped",
		ActionStackSkipped: "stack-skipped", UpdateAction(99): "unknown",
	}
	for a, s := range want {
		if a.String() != s {
			t.Errorf("String(%d)=%q want %q", a, a.String(), s)
		}
	}
}
