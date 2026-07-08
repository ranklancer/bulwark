package scheduler

import (
	"testing"
	"time"
)

func mustParseWindow(t *testing.T, start, end string, days []string) Window {
	t.Helper()
	w, err := ParseWindow(start, end, days)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestParseWindow_AcceptsValid(t *testing.T) {
	cases := []struct {
		start, end string
		days       []string
	}{
		{"02:00", "06:00", []string{"mon", "tue"}},
		{"00:00", "24:00", nil},
		{"22:00", "04:00", []string{"friday", "saturday"}},
		{"00:00", "01:00", []string{}},
	}
	for _, c := range cases {
		if _, err := ParseWindow(c.start, c.end, c.days); err != nil {
			t.Errorf("Parse(%q, %q, %v): %v", c.start, c.end, c.days, err)
		}
	}
}

func TestParseWindow_RejectsInvalid(t *testing.T) {
	cases := []struct {
		start, end string
		days       []string
	}{
		{"25:00", "06:00", nil},                // bad hour
		{"00:60", "06:00", nil},                // bad minute
		{"24:30", "06:00", nil},                // 24:00 is sentinel; 24:30 invalid
		{"02:00", "06:00", []string{"funday"}}, // bad weekday
		{"02:00", "06", nil},                   // no colon
		{"02:00", "abc", nil},                  // non-numeric
	}
	for _, c := range cases {
		if _, err := ParseWindow(c.start, c.end, c.days); err == nil {
			t.Errorf("Parse(%q, %q, %v) should error", c.start, c.end, c.days)
		}
	}
}

func TestWindow_IsActive_SameDay(t *testing.T) {
	w := mustParseWindow(t, "02:00", "06:00", []string{"mon", "tue", "wed", "thu", "fri"})
	loc := time.UTC

	// 2026-05-04 is a Monday.
	cases := []struct {
		when time.Time
		want bool
	}{
		{time.Date(2026, 5, 4, 1, 59, 0, 0, loc), false},
		{time.Date(2026, 5, 4, 2, 0, 0, 0, loc), true},
		{time.Date(2026, 5, 4, 5, 59, 0, 0, loc), true},
		{time.Date(2026, 5, 4, 6, 0, 0, 0, loc), false},
		{time.Date(2026, 5, 9, 3, 0, 0, 0, loc), false}, // Saturday — not in days
	}
	for _, c := range cases {
		if got := w.IsActive(c.when); got != c.want {
			t.Errorf("IsActive(%s) = %v, want %v", c.when.Format(time.RFC3339), got, c.want)
		}
	}
}

func TestWindow_IsActive_WrapAround(t *testing.T) {
	// Friday 22:00 → 04:00, runs into Saturday morning.
	w := mustParseWindow(t, "22:00", "04:00", []string{"friday"})
	loc := time.UTC

	// 2026-05-01 is a Friday.
	cases := []struct {
		when time.Time
		want bool
	}{
		{time.Date(2026, 5, 1, 21, 59, 0, 0, loc), false},
		{time.Date(2026, 5, 1, 22, 0, 0, 0, loc), true},
		{time.Date(2026, 5, 1, 23, 30, 0, 0, loc), true},
		{time.Date(2026, 5, 2, 0, 30, 0, 0, loc), true}, // Sat 00:30 — yesterday=Fri ✓
		{time.Date(2026, 5, 2, 3, 59, 0, 0, loc), true},
		{time.Date(2026, 5, 2, 4, 0, 0, 0, loc), false},
		{time.Date(2026, 5, 2, 22, 0, 0, 0, loc), false}, // Sat 22:00 — Sat not in days
	}
	for _, c := range cases {
		if got := w.IsActive(c.when); got != c.want {
			t.Errorf("IsActive(%s) = %v, want %v", c.when.Format(time.RFC3339), got, c.want)
		}
	}
}

func TestWindow_IsActive_EmptyDaysMeansEveryDay(t *testing.T) {
	w := mustParseWindow(t, "02:00", "06:00", nil)
	loc := time.UTC
	for d := 0; d < 7; d++ {
		when := time.Date(2026, 5, 4+d, 3, 0, 0, 0, loc)
		if !w.IsActive(when) {
			t.Errorf("IsActive(%s) = false, want true (no days = every day)", when.Format(time.RFC3339))
		}
	}
}

func TestWindow_IsActive_ZeroLengthNeverFires(t *testing.T) {
	w := mustParseWindow(t, "03:00", "03:00", nil)
	if w.IsActive(time.Date(2026, 5, 4, 3, 0, 0, 0, time.UTC)) {
		t.Error("zero-length window should never be active")
	}
}

func TestAnyActive(t *testing.T) {
	wins := []Window{
		mustParseWindow(t, "02:00", "04:00", []string{"mon", "tue", "wed", "thu", "fri"}),
		mustParseWindow(t, "00:00", "23:59", []string{"sat", "sun"}),
	}
	weekday := time.Date(2026, 5, 4, 3, 0, 0, 0, time.UTC)     // Mon 03:00
	weekend := time.Date(2026, 5, 9, 14, 0, 0, 0, time.UTC)    // Sat 14:00
	weekdayOff := time.Date(2026, 5, 4, 14, 0, 0, 0, time.UTC) // Mon 14:00 — neither

	if !AnyActive(weekday, wins) {
		t.Error("expected weekday morning active")
	}
	if !AnyActive(weekend, wins) {
		t.Error("expected weekend afternoon active")
	}
	if AnyActive(weekdayOff, wins) {
		t.Error("expected weekday afternoon NOT active")
	}
	if AnyActive(weekday, nil) {
		t.Error("AnyActive over no windows must be false")
	}
}
