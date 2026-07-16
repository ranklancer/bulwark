// Package types defines the core data types shared across Bulwark packages
// and exposed to plugin authors.
package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RiskLevel represents Bulwark's three-tier classification of a pending update.
type RiskLevel int

const (
	RiskUnknown RiskLevel = iota
	RiskSafe
	RiskReview
	RiskBreaking
)

func (r RiskLevel) String() string {
	switch r {
	case RiskSafe:
		return "safe"
	case RiskReview:
		return "review"
	case RiskBreaking:
		return "breaking"
	default:
		return "unknown"
	}
}

// ParseRiskLevel parses a case-insensitive string into a RiskLevel.
// Returns RiskUnknown for unrecognized values.
func ParseRiskLevel(s string) RiskLevel {
	switch s {
	case "safe", "SAFE", "Safe":
		return RiskSafe
	case "review", "REVIEW", "Review":
		return RiskReview
	case "breaking", "BREAKING", "Breaking":
		return RiskBreaking
	default:
		return RiskUnknown
	}
}

// MarshalJSON renders RiskLevel as its lowercase string form.
func (r RiskLevel) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(r.String())), nil
}

// UnmarshalJSON accepts both the string form (produced by MarshalJSON) and
// the legacy numeric form. Unknown values become RiskUnknown rather than
// erroring — persisted data should never break loads.
func (r *RiskLevel) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*r = RiskUnknown
		return nil
	}
	if b[0] == '"' {
		s, err := strconv.Unquote(string(b))
		if err != nil {
			return err
		}
		*r = ParseRiskLevel(s)
		return nil
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*r = RiskLevel(n)
	return nil
}

// ChangeKind classifies what kind of version change a pending update represents.
// This is independent of RiskLevel — policy maps ChangeKind to RiskLevel.
type ChangeKind int

const (
	ChangeUnknown     ChangeKind = iota
	ChangeDigest                 // same tag, new digest (rebuild without version bump)
	ChangePatch                  // x.y.Z bump
	ChangeMinor                  // x.Y.z bump
	ChangeMajor                  // X.y.z bump
	ChangePrerelease             // pre-release identifier changed but base version same
	ChangeLSIORebuild            // LinuxServer.io -ls<n> suffix bumped, upstream unchanged
	ChangeLatest                 // :latest tag — semver cannot be inferred
	ChangeNone                   // versions are identical (no update needed)
)

func (c ChangeKind) String() string {
	switch c {
	case ChangeDigest:
		return "digest"
	case ChangePatch:
		return "patch"
	case ChangeMinor:
		return "minor"
	case ChangeMajor:
		return "major"
	case ChangePrerelease:
		return "prerelease"
	case ChangeLSIORebuild:
		return "lsio-rebuild"
	case ChangeLatest:
		return "latest"
	case ChangeNone:
		return "none"
	default:
		return "unknown"
	}
}

// MarshalJSON renders ChangeKind as its lowercase string form.
func (c ChangeKind) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(c.String())), nil
}

// UnmarshalJSON accepts the string form produced by MarshalJSON, and the
// numeric form for legacy data.
func (c *ChangeKind) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*c = ChangeUnknown
		return nil
	}
	if b[0] == '"' {
		s, err := strconv.Unquote(string(b))
		if err != nil {
			return err
		}
		*c = parseChangeKind(s)
		return nil
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*c = ChangeKind(n)
	return nil
}

func parseChangeKind(s string) ChangeKind {
	switch s {
	case "digest":
		return ChangeDigest
	case "patch":
		return ChangePatch
	case "minor":
		return ChangeMinor
	case "major":
		return ChangeMajor
	case "prerelease":
		return ChangePrerelease
	case "lsio-rebuild":
		return ChangeLSIORebuild
	case "latest":
		return ChangeLatest
	case "none":
		return ChangeNone
	default:
		return ChangeUnknown
	}
}

// Confidence describes how reliable a risk assessment is, given the evidence available.
type Confidence int

const (
	ConfidenceUnknown Confidence = iota
	ConfidenceLow                // digest-only or :latest tag — semver cannot be inferred
	ConfidenceMedium             // semver delta resolved, but no release notes were parsed
	ConfidenceHigh               // semver delta plus parsed release notes
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return "unknown"
	}
}

// MarshalJSON renders Confidence as its lowercase string form.
func (c Confidence) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(c.String())), nil
}

// UnmarshalJSON accepts the string form produced by MarshalJSON.
func (c *Confidence) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*c = ConfidenceUnknown
		return nil
	}
	if b[0] == '"' {
		s, err := strconv.Unquote(string(b))
		if err != nil {
			return err
		}
		switch s {
		case "low":
			*c = ConfidenceLow
		case "medium":
			*c = ConfidenceMedium
		case "high":
			*c = ConfidenceHigh
		default:
			*c = ConfidenceUnknown
		}
		return nil
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*c = Confidence(n)
	return nil
}

// ImageInfo describes a specific image revision: where it lives, which tag points
// at it, and the digest that uniquely identifies its content.
type ImageInfo struct {
	Repository string // e.g., "lscr.io/linuxserver/sonarr"
	Tag        string // e.g., "4.0.10" or "4.0.10-ls45"
	Digest     string // e.g., "sha256:abcdef..."
}

// Reference returns the canonical "repo:tag@digest" reference, omitting empty parts.
func (i ImageInfo) Reference() string {
	ref := i.Repository
	if i.Tag != "" {
		ref += ":" + i.Tag
	}
	if i.Digest != "" {
		ref += "@" + i.Digest
	}
	return ref
}

// VersionDelta describes the change between two image versions.
type VersionDelta struct {
	Kind ChangeKind
	From string // human-readable source version, e.g., "v4.0.9-ls45"
	To   string // human-readable target version, e.g., "v4.0.10-ls45"
}

// RiskAssessment is the classifier's verdict on a pending update.
type RiskAssessment struct {
	Level         RiskLevel
	Rationale     string
	Delta         VersionDelta
	Confidence    Confidence
	ReleaseURL    string
	Changelog     string // truncated excerpt suitable for notification rendering
	MatchedTokens []string

	// Security is the optional security-urgency verdict, attached when a
	// CVE source is configured. It is orthogonal to Level (stability):
	// it escalates attention but never lowers a stability gate. Nil when
	// no CVE source is wired or the update closes nothing at threshold.
	Security *SecurityAssessment `json:"Security,omitempty"`
}

// SecurityUrgency is the security-driven priority of an update, orthogonal
// to RiskLevel. It only escalates attention; it never lowers a gate.
type SecurityUrgency int

const (
	UrgencyNone        SecurityUrgency = iota
	UrgencyRecommended                 // update closes HIGH-severity CVEs
	UrgencyUrgent                      // update closes CRITICAL-severity CVEs
)

func (u SecurityUrgency) String() string {
	switch u {
	case UrgencyRecommended:
		return "recommended"
	case UrgencyUrgent:
		return "urgent"
	default:
		return "none"
	}
}

// MarshalJSON renders SecurityUrgency as its lowercase string form.
func (u SecurityUrgency) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(u.String())), nil
}

// UnmarshalJSON accepts the string form and the legacy numeric form.
func (u *SecurityUrgency) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*u = UrgencyNone
		return nil
	}
	if b[0] == '"' {
		s, err := strconv.Unquote(string(b))
		if err != nil {
			return err
		}
		switch s {
		case "recommended":
			*u = UrgencyRecommended
		case "urgent":
			*u = UrgencyUrgent
		default:
			*u = UrgencyNone
		}
		return nil
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*u = SecurityUrgency(n)
	return nil
}

// ClosedVuln is a single vulnerability an update closes (present in the
// current image, absent in the candidate). Severity is the lowercase
// string form so this core package stays free of any scanner enum.
type ClosedVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	PkgName  string `json:"pkg_name,omitempty"`
	Title    string `json:"title,omitempty"`
}

// SecurityAssessment describes which CVEs an update closes and how urgent
// applying it therefore is.
type SecurityAssessment struct {
	Urgency         SecurityUrgency `json:"urgency"`
	ClosedCount     int             `json:"closed_count"`
	CriticalClosed  int             `json:"critical_closed"`
	HighClosed      int             `json:"high_closed"`
	HighestSeverity string          `json:"highest_severity,omitempty"`
	Source          string          `json:"source,omitempty"`
	Closed          []ClosedVuln    `json:"closed,omitempty"`
}

// Summary renders a one-line human-readable summary, e.g.
// "security-urgent: closes 2 CRITICAL, 5 HIGH (trivy)". Returns "" when
// the update closes nothing.
func (s *SecurityAssessment) Summary() string {
	if s == nil || s.ClosedCount == 0 {
		return ""
	}
	var b strings.Builder
	switch s.Urgency {
	case UrgencyUrgent:
		b.WriteString("security-urgent: ")
	case UrgencyRecommended:
		b.WriteString("security-recommended: ")
	default:
		b.WriteString("security: ")
	}
	b.WriteString("closes ")
	parts := make([]string, 0, 2)
	if s.CriticalClosed > 0 {
		parts = append(parts, fmt.Sprintf("%d CRITICAL", s.CriticalClosed))
	}
	if s.HighClosed > 0 {
		parts = append(parts, fmt.Sprintf("%d HIGH", s.HighClosed))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d CVE", s.ClosedCount))
	}
	b.WriteString(strings.Join(parts, ", "))
	if s.Source != "" {
		b.WriteString(" (" + s.Source + ")")
	}
	return b.String()
}

// UpdateAction describes what was done (or would be done) for a pending update.
type UpdateAction int

const (
	ActionUnknown UpdateAction = iota
	ActionAutoUpdated
	ActionNeedsReview
	ActionBlocked
	ActionRolledBack
	ActionSkipped
	ActionStackSkipped
)

func (a UpdateAction) String() string {
	switch a {
	case ActionAutoUpdated:
		return "auto-updated"
	case ActionNeedsReview:
		return "needs-review"
	case ActionBlocked:
		return "blocked"
	case ActionRolledBack:
		return "rolled-back"
	case ActionSkipped:
		return "skipped"
	case ActionStackSkipped:
		return "stack-skipped"
	default:
		return "unknown"
	}
}

// HealthResult captures the outcome of a post-update health verification.
type HealthResult struct {
	Healthy   bool
	Checks    int
	Duration  time.Duration
	LastError string
}

// UpdateEvent carries the full context of an update for notification rendering
// and audit logging.
type UpdateEvent struct {
	Stack       string
	Container   string
	ImageFrom   string
	ImageTo     string
	Risk        RiskLevel
	Action      UpdateAction
	ReleaseURL  string
	Changelog   string
	SnapshotID  string
	HealthCheck *HealthResult
	Error       error
	Timestamp   time.Time
}
