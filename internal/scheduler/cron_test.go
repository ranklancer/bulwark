package scheduler

import (
	"testing"
	"time"
)

func TestParseCron_Valid(t *testing.T) {
	cases := []string{
		"* * * * *",
		"0 * * * *",
		"0 0 * * *",
		"0 0 1 * *",
		"0 0 * * 0",
		"*/5 * * * *",
		"0 0-5 * * *",
		"0 9-17/2 * * 1-5",
		"0,15,30,45 * * * *",
		"0 3 * * 0,6",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			s, err := ParseCron(in)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", in, err)
			}
			if s.String() != in {
				t.Errorf("String() = %q, want %q", s.String(), in)
			}
		})
	}
}

func TestParseCron_Invalid(t *testing.T) {
	cases := []string{
		"",
		"* * * *",     // 4 fields
		"* * * * * *", // 6 fields
		"60 * * * *",  // minute out of range
		"* 24 * * *",  // hour out of range
		"* * 32 * *",  // day-of-month out of range
		"* * * 13 *",  // month out of range
		"* * * * 7",   // day-of-week out of range
		"-1 * * * *",  // negative
		"a * * * *",   // non-numeric
		"5-3 * * * *", // reversed range
		"*/0 * * * *", // zero step
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseCron(in); err == nil {
				t.Errorf("expected error for %q", in)
			}
		})
	}
}

func TestCronSchedule_Match(t *testing.T) {
	s, err := ParseCron("0 3 * * 0") // Sundays at 03:00
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		t    time.Time
		want bool
	}{
		// 2026-05-03 is a Sunday.
		{time.Date(2026, 5, 3, 3, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 5, 3, 3, 1, 0, 0, time.UTC), false},
		{time.Date(2026, 5, 3, 4, 0, 0, 0, time.UTC), false},
		// 2026-05-04 is a Monday.
		{time.Date(2026, 5, 4, 3, 0, 0, 0, time.UTC), false},
	}
	for _, tc := range cases {
		if got := s.Match(tc.t); got != tc.want {
			t.Errorf("Match(%s) = %v, want %v", tc.t.Format(time.RFC3339), got, tc.want)
		}
	}
}

func TestCronSchedule_Next_HourlyAt00(t *testing.T) {
	s, _ := ParseCron("0 * * * *")
	from := time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC)
	got := s.Next(from)
	want := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %s, want %s", got, want)
	}
}

func TestCronSchedule_Next_StrictlyAfter(t *testing.T) {
	// Even when the input time matches, Next must skip ahead.
	s, _ := ParseCron("0 * * * *")
	from := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	got := s.Next(from)
	want := time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next at boundary = %s, want %s", got, want)
	}
}

func TestCronSchedule_Next_VixieORSemantics(t *testing.T) {
	// "0 3 1,15 * 0" — Vixie cron OR: 1st OR 15th OR Sunday.
	s, _ := ParseCron("0 3 1,15 * 0")

	// 2026-05-01 is a Friday (DOM matches → fire).
	if !s.Match(time.Date(2026, 5, 1, 3, 0, 0, 0, time.UTC)) {
		t.Error("expected match on the 1st (DOM matches)")
	}
	// 2026-05-03 is a Sunday (DOW matches → fire).
	if !s.Match(time.Date(2026, 5, 3, 3, 0, 0, 0, time.UTC)) {
		t.Error("expected match on Sunday (DOW matches)")
	}
	// 2026-05-08 is a Friday (neither matches).
	if s.Match(time.Date(2026, 5, 8, 3, 0, 0, 0, time.UTC)) {
		t.Error("did not expect match on a non-special date")
	}
}

func TestCronSchedule_Next_StarSemantics_DOMOnly(t *testing.T) {
	// "0 3 15 * *" — DOW is *, only the 15th matters regardless of weekday.
	s, _ := ParseCron("0 3 15 * *")
	if !s.Match(time.Date(2026, 5, 15, 3, 0, 0, 0, time.UTC)) {
		t.Error("expected match on the 15th")
	}
	if s.Match(time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)) {
		t.Error("did not expect match on the 16th")
	}
}

func TestCronSchedule_Next_DailyAt0300(t *testing.T) {
	s, _ := ParseCron("0 3 * * *")
	from := time.Date(2026, 5, 1, 3, 0, 0, 0, time.UTC)
	got := s.Next(from)
	want := time.Date(2026, 5, 2, 3, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %s, want %s", got, want)
	}
}

func TestCronSchedule_Next_WeeklySunday3am(t *testing.T) {
	s, _ := ParseCron("0 3 * * 0")
	// from a Wednesday
	from := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	got := s.Next(from)
	// Next Sunday is 2026-05-03.
	want := time.Date(2026, 5, 3, 3, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next = %s, want %s", got, want)
	}
}

func TestCronSchedule_Next_NeverMatchingReturnsZero(t *testing.T) {
	// February 30th doesn't exist — schedule never fires.
	s, _ := ParseCron("0 0 30 2 *")
	from := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	got := s.Next(from)
	if !got.IsZero() {
		t.Errorf("expected zero time for impossible schedule, got %s", got)
	}
}

func TestCronSchedule_StepInRange(t *testing.T) {
	// "0 9-17/2 * * 1-5" — every 2 hours from 09 through 17 on weekdays.
	s, _ := ParseCron("0 9-17/2 * * 1-5")

	// 2026-05-04 is a Monday.
	for _, hr := range []int{9, 11, 13, 15, 17} {
		if !s.Match(time.Date(2026, 5, 4, hr, 0, 0, 0, time.UTC)) {
			t.Errorf("expected match at %02d:00 Monday", hr)
		}
	}
	for _, hr := range []int{10, 12, 14, 16, 18} {
		if s.Match(time.Date(2026, 5, 4, hr, 0, 0, 0, time.UTC)) {
			t.Errorf("did not expect match at %02d:00", hr)
		}
	}
	// Saturday — DOW restricts.
	if s.Match(time.Date(2026, 5, 9, 9, 0, 0, 0, time.UTC)) {
		t.Error("did not expect Saturday match")
	}
}

func TestCronSchedule_NilSafe(t *testing.T) {
	var s *CronSchedule
	if s.Match(time.Now()) {
		t.Error("nil Match should return false")
	}
	if !s.Next(time.Now()).IsZero() {
		t.Error("nil Next should return zero time")
	}
}
