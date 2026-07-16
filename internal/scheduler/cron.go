package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CronSchedule is a parsed 5-field cron expression. Fields are stored as
// bitmasks for fast Match: the bit at position N is set when the field
// matches value N.
//
// Supported syntax (subset of POSIX cron):
//   - any value
//     N           single value
//     N-M         inclusive range
//     N,M,P       list of values (each part follows the same rules)
//     */K         every K-th value starting from the field's minimum
//     N-M/K       every K-th value in the range
//
// Predefined macros (@hourly, @daily, etc.) are not supported.
//
// Vixie-cron DOM/DOW semantics: when *both* day-of-month and day-of-week
// are restricted (neither is "*"), a date matches if it satisfies *either*
// (logical OR). When only one is restricted, normal AND semantics apply.
type CronSchedule struct {
	minute   uint64 // 0-59
	hour     uint32 // 0-23
	dom      uint32 // 1-31
	month    uint16 // 1-12
	dow      uint8  // 0-6, Sunday=0
	domStar  bool   // true if day-of-month was "*"
	dowStar  bool   // true if day-of-week was "*"
	original string
}

// String returns the original cron expression as parsed.
func (c *CronSchedule) String() string { return c.original }

// ParseCron compiles a 5-field cron expression. Whitespace between fields
// can be any number of spaces or tabs.
func ParseCron(expr string) (*CronSchedule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("cron: expression is empty")
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron: expected 5 fields, got %d in %q", len(fields), expr)
	}

	min, err := parseField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("cron: minute: %w", err)
	}
	hr, err := parseField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("cron: hour: %w", err)
	}
	dom, err := parseField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("cron: day-of-month: %w", err)
	}
	mon, err := parseField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("cron: month: %w", err)
	}
	dow, err := parseField(fields[4], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("cron: day-of-week: %w", err)
	}

	c := &CronSchedule{
		minute:   min,
		hour:     uint32(hr),
		dom:      uint32(dom),
		month:    uint16(mon),
		dow:      uint8(dow),
		domStar:  fields[2] == "*",
		dowStar:  fields[4] == "*",
		original: expr,
	}
	return c, nil
}

// Match reports whether the given time satisfies the schedule. Seconds and
// sub-second precision are ignored — cron fires at minute resolution.
func (c *CronSchedule) Match(t time.Time) bool {
	if c == nil {
		return false
	}
	if c.minute&(1<<uint(t.Minute())) == 0 {
		return false
	}
	if c.hour&(1<<uint(t.Hour())) == 0 {
		return false
	}
	if c.month&(1<<uint(int(t.Month()))) == 0 {
		return false
	}

	domMatch := c.dom&(1<<uint(t.Day())) != 0
	dowMatch := c.dow&(1<<uint(int(t.Weekday()))) != 0

	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return dowMatch
	case c.dowStar:
		return domMatch
	default:
		// Both restricted — Vixie-cron OR semantics so that
		// expressions like "0 3 1,15 * 0" mean "1st, 15th, OR every Sunday".
		return domMatch || dowMatch
	}
}

// Next returns the smallest time strictly greater than after that satisfies
// the schedule. If no match is found within five years, the zero time is
// returned (signalling a schedule that effectively never fires —
// e.g. "0 0 31 2 *").
//
// Sub-minute precision in the input is dropped before searching.
func (c *CronSchedule) Next(after time.Time) time.Time {
	if c == nil {
		return time.Time{}
	}
	t := after.Truncate(time.Minute).Add(time.Minute)
	deadline := t.Add(5 * 365 * 24 * time.Hour)
	for t.Before(deadline) {
		if c.Match(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

// parseField parses a single cron field into a bitmask. Values must lie
// within [min, max]; ranges and steps that fall outside the bounds error.
func parseField(s string, min, max int) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty field")
	}
	var bits uint64
	for _, part := range strings.Split(s, ",") {
		b, err := parsePart(strings.TrimSpace(part), min, max)
		if err != nil {
			return 0, fmt.Errorf("field %q: %w", s, err)
		}
		bits |= b
	}
	return bits, nil
}

// parsePart parses a single comma-separated component of a cron field.
func parsePart(s string, min, max int) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty part")
	}
	step := 1
	rest := s

	// Trailing "/K" applies a step. Handle it first so the remaining
	// substring can be processed as range-or-value.
	if i := strings.Index(rest, "/"); i >= 0 {
		k, err := strconv.Atoi(rest[i+1:])
		if err != nil || k <= 0 {
			return 0, fmt.Errorf("invalid step %q", rest)
		}
		step = k
		rest = rest[:i]
	}

	var lo, hi int
	switch {
	case rest == "*":
		lo, hi = min, max
	case strings.Contains(rest, "-"):
		parts := strings.SplitN(rest, "-", 2)
		a, errA := strconv.Atoi(parts[0])
		b, errB := strconv.Atoi(parts[1])
		if errA != nil || errB != nil {
			return 0, fmt.Errorf("invalid range %q", rest)
		}
		if a > b {
			return 0, fmt.Errorf("invalid range %q (start > end)", rest)
		}
		lo, hi = a, b
	default:
		v, err := strconv.Atoi(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid value %q", rest)
		}
		// "N/K" without a range means "every K starting from N up to max"
		// per common cron extensions; keep the strict subset here and only
		// permit step on "*" or explicit ranges.
		if step != 1 {
			return 0, fmt.Errorf("step requires range or *: %q", s)
		}
		lo, hi = v, v
	}
	if lo < min || hi > max {
		return 0, fmt.Errorf("value out of range [%d,%d] in %q", min, max, s)
	}
	var out uint64
	for i := lo; i <= hi; i += step {
		out |= 1 << uint(i)
	}
	return out, nil
}
