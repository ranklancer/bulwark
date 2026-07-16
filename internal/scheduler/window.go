package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Window is a parsed maintenance window. Times are stored as minutes
// since midnight (0..1439); days as a bitmask over time.Weekday.
//
// A window with `Start == End` is treated as zero-length (no firings).
// A window with `Start > End` wraps midnight and matches "after Start
// today OR before End tomorrow" — i.e. a 22:00–04:00 window covers the
// late-night period that crosses midnight.
type Window struct {
	StartMin int     // 0..1439
	EndMin   int     // 0..1439
	Days     dayMask // bit 0 = Sunday, ... bit 6 = Saturday
	Original string  // for log/diagnostic output
}

// dayMask is a bitfield indexed by time.Weekday (Sunday=0).
type dayMask uint8

// ParseWindow reads a window from "HH:MM"/"HH:MM"/days. days is a
// case-insensitive comma-list of {sun,mon,...,sat} or {sunday,...,saturday}.
// An empty `days` list defaults to "every day" — the principle of
// least surprise for windows configured purely by time-of-day.
func ParseWindow(start, end string, days []string) (Window, error) {
	startMin, err := parseClock(start)
	if err != nil {
		return Window{}, fmt.Errorf("window: start %q: %w", start, err)
	}
	endMin, err := parseClock(end)
	if err != nil {
		return Window{}, fmt.Errorf("window: end %q: %w", end, err)
	}
	mask, err := parseDays(days)
	if err != nil {
		return Window{}, err
	}
	return Window{
		StartMin: startMin,
		EndMin:   endMin,
		Days:     mask,
		Original: fmt.Sprintf("%s-%s on %v", start, end, days),
	}, nil
}

// IsActive reports whether t falls inside the window. The check uses
// the location of t (use t.In(loc) at the call site to evaluate in a
// specific timezone).
//
// Wrap-around windows (Start>End) match "today's late side OR tomorrow's
// early side"; the day mask gates by today's weekday in both halves so a
// "Friday 22:00–04:00" window matches Friday 23:00 and Saturday 02:00 —
// the boundary case homelab operators want.
func (w Window) IsActive(t time.Time) bool {
	if w.StartMin == w.EndMin {
		return false
	}
	min := t.Hour()*60 + t.Minute()
	weekday := t.Weekday()

	if w.StartMin < w.EndMin {
		// Same-day window. Day mask gated.
		return w.Days.has(weekday) && min >= w.StartMin && min < w.EndMin
	}
	// Wrap-around. The "late side" runs from Start to midnight on a
	// matching weekday; the "early side" runs from midnight to End on
	// the day AFTER a matching weekday.
	if min >= w.StartMin {
		return w.Days.has(weekday)
	}
	if min < w.EndMin {
		// Yesterday's weekday must match.
		yesterday := (int(weekday) + 6) % 7
		return w.Days.has(time.Weekday(yesterday))
	}
	return false
}

// AnyActive returns true if any of the supplied windows is active at t.
// Empty list returns false (no windows configured ⇒ no active period).
// A nil/empty slice means "no maintenance window gating" — callers
// usually short-circuit before calling AnyActive in that case.
func AnyActive(t time.Time, windows []Window) bool {
	for _, w := range windows {
		if w.IsActive(t) {
			return true
		}
	}
	return false
}

func (m dayMask) has(d time.Weekday) bool { return m&(1<<uint(d)) != 0 }

// parseClock accepts "HH:MM" with HH ∈ [0..24] and MM ∈ [0..59]. "24:00" is
// permitted as an end-of-day sentinel (1440 minutes), which is convenient
// for "00:00–24:00 every day" full-coverage windows.
func parseClock(s string) (int, error) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("expected HH:MM")
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("hour: %w", err)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("minute: %w", err)
	}
	if h < 0 || h > 24 {
		return 0, fmt.Errorf("hour out of range")
	}
	if m < 0 || m > 59 {
		return 0, fmt.Errorf("minute out of range")
	}
	if h == 24 && m != 0 {
		return 0, fmt.Errorf("24:%02d is invalid (only 24:00 is allowed)", m)
	}
	return h*60 + m, nil
}

// parseDays accepts a slice of day names (3-letter or full). Empty slice
// defaults to every day. Unknown names error so a typo doesn't silently
// disable the window on the day the operator cared about.
func parseDays(days []string) (dayMask, error) {
	if len(days) == 0 {
		return 0b01111111, nil // sun..sat
	}
	var m dayMask
	for _, d := range days {
		w, err := parseDay(d)
		if err != nil {
			return 0, err
		}
		m |= 1 << uint(w)
	}
	return m, nil
}

func parseDay(s string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sun", "sunday":
		return time.Sunday, nil
	case "mon", "monday":
		return time.Monday, nil
	case "tue", "tues", "tuesday":
		return time.Tuesday, nil
	case "wed", "weds", "wednesday":
		return time.Wednesday, nil
	case "thu", "thur", "thurs", "thursday":
		return time.Thursday, nil
	case "fri", "friday":
		return time.Friday, nil
	case "sat", "saturday":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("unknown weekday %q", s)
	}
}
