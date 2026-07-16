package verify

import (
	"testing"
	"time"
)

func TestParseBreakGlass(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		labels  map[string]string
		wantOK  bool
		wantExp bool
	}{
		{"none", nil, false, false},
		{"empty reason", map[string]string{LabelBreakGlass: "  "}, false, false},
		{"reason only", map[string]string{LabelBreakGlass: "vendor not signed"}, true, false},
		{"future expiry", map[string]string{LabelBreakGlass: "r", LabelBreakGlassExpires: "2026-07-06T18:00:00Z"}, true, false},
		{"past expiry", map[string]string{LabelBreakGlass: "r", LabelBreakGlassExpires: "2026-07-06T06:00:00Z"}, false, true},
		{"bad expiry", map[string]string{LabelBreakGlass: "r", LabelBreakGlassExpires: "not-a-time"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bg, ok := parseBreakGlass(tc.labels, now)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if bg.Expired != tc.wantExp {
				t.Fatalf("expired=%v want %v", bg.Expired, tc.wantExp)
			}
		})
	}
}
