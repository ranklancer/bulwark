// Package types defines the core data types shared across Bulwark packages
// and exposed to plugin authors.
package types

import (
	"strconv"
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

// ChangeKind classifies what kind of version change a pending update represents.
// This is independent of RiskLevel — policy maps ChangeKind to RiskLevel.
type ChangeKind int

const (
	ChangeUnknown ChangeKind = iota
	ChangeDigest             // same tag, new digest (rebuild without version bump)
	ChangePatch              // x.y.Z bump
	ChangeMinor              // x.Y.z bump
	ChangeMajor              // X.y.z bump
	ChangePrerelease         // pre-release identifier changed but base version same
	ChangeLSIORebuild        // LinuxServer.io -ls<n> suffix bumped, upstream unchanged
	ChangeLatest             // :latest tag — semver cannot be inferred
	ChangeNone               // versions are identical (no update needed)
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
