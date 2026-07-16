package cve

import (
	"sort"

	"github.com/ranklancer/bulwark/pkg/types"
)

// AssessUpgrade computes the security-urgency of replacing the current image
// with the candidate, considering ONLY the vulnerabilities the upgrade
// *closes* (present in current, absent in candidate) at or above threshold.
// CVEs the candidate newly introduces are ignored here — that's a separate
// "regression" concern (future work). The returned assessment carries no
// Source; the caller stamps it.
func AssessUpgrade(current, candidate []Vuln, threshold Severity) types.SecurityAssessment {
	if threshold == SeverityUnknown {
		threshold = SeverityHigh
	}
	candIDs := make(map[string]bool, len(candidate))
	for _, v := range candidate {
		candIDs[v.ID] = true
	}
	var (
		closed     []types.ClosedVuln
		seen       = map[string]bool{}
		crit, high int
		highest    = SeverityUnknown
	)
	for _, v := range current {
		if v.ID == "" || seen[v.ID] || candIDs[v.ID] {
			continue
		}
		if v.Severity < threshold {
			continue
		}
		seen[v.ID] = true
		closed = append(closed, types.ClosedVuln{
			ID:       v.ID,
			Severity: v.Severity.String(),
			PkgName:  v.PkgName,
			Title:    v.Title,
		})
		switch v.Severity {
		case SeverityCritical:
			crit++
		case SeverityHigh:
			high++
		}
		if v.Severity > highest {
			highest = v.Severity
		}
	}
	sort.Slice(closed, func(i, j int) bool {
		si, sj := ParseSeverity(closed[i].Severity), ParseSeverity(closed[j].Severity)
		if si != sj {
			return si > sj
		}
		return closed[i].ID < closed[j].ID
	})
	urg := types.UrgencyNone
	switch {
	case highest >= SeverityCritical:
		urg = types.UrgencyUrgent
	case highest >= SeverityHigh:
		urg = types.UrgencyRecommended
	}
	highestStr := ""
	if highest != SeverityUnknown {
		highestStr = highest.String()
	}
	return types.SecurityAssessment{
		Urgency:         urg,
		ClosedCount:     len(closed),
		CriticalClosed:  crit,
		HighClosed:      high,
		HighestSeverity: highestStr,
		Closed:          closed,
	}
}
