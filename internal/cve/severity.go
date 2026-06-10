// Package cve adds a security-urgency axis to Bulwark's update decisioning,
// orthogonal to the stability classification. A pluggable Source supplies the
// vulnerabilities present in an image (Trivy first), and AssessUpgrade diffs a
// current image against a candidate to surface the CVEs an update closes.
package cve

import "strings"

// Severity is a CVE severity, ordered so that higher values are more severe.
// The ordering is what makes threshold comparisons (>=) and "highest closed"
// reductions work.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ParseSeverity parses Trivy/NVD-style severity strings (case-insensitive).
// Unrecognized input becomes SeverityUnknown.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}
