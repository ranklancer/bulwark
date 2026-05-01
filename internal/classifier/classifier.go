// Package classifier evaluates the risk of a pending Docker image update.
//
// Inputs: the currently-running image, the available image, and (optionally)
// release notes for the new version.
//
// Output: a RiskAssessment describing the change kind, risk level, confidence,
// and a human-readable rationale.
//
// The classifier is the core differentiator of Bulwark over Watchtower-class
// tools: instead of pulling-and-praying, it makes a defensible judgement about
// whether an update is safe to apply automatically, requires human review, or
// must be blocked outright.
package classifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// Policy maps each ChangeKind to a default RiskLevel. It is the user-facing
// configuration that controls how aggressively the classifier flags updates.
type Policy struct {
	Patch       types.RiskLevel
	Minor       types.RiskLevel
	Major       types.RiskLevel
	Digest      types.RiskLevel
	Latest      types.RiskLevel
	LSIORebuild types.RiskLevel
	Prerelease  types.RiskLevel
	Default     types.RiskLevel
}

// DefaultPolicy returns the policy described in section 4 of the project spec:
// patch=safe, minor=review, major=breaking, digest=safe, latest=review,
// lsio-rebuild=safe.
func DefaultPolicy() Policy {
	return Policy{
		Patch:       types.RiskSafe,
		Minor:       types.RiskReview,
		Major:       types.RiskBreaking,
		Digest:      types.RiskSafe,
		Latest:      types.RiskReview,
		LSIORebuild: types.RiskSafe,
		Prerelease:  types.RiskReview,
		Default:     types.RiskReview,
	}
}

// levelFor returns the policy-mapped risk level for the given change kind.
func (p Policy) levelFor(k types.ChangeKind) types.RiskLevel {
	switch k {
	case types.ChangePatch:
		return p.Patch
	case types.ChangeMinor:
		return p.Minor
	case types.ChangeMajor:
		return p.Major
	case types.ChangeDigest:
		return p.Digest
	case types.ChangeLatest:
		return p.Latest
	case types.ChangeLSIORebuild:
		return p.LSIORebuild
	case types.ChangePrerelease:
		return p.Prerelease
	case types.ChangeNone:
		return types.RiskSafe
	default:
		return p.Default
	}
}

// ReleaseNotes is the optional input to classification. When absent, the
// classifier still produces a verdict based on semver alone — at lower
// confidence.
type ReleaseNotes struct {
	URL      string
	Body     string
	Resolved bool // false if fetch was attempted but returned no content
}

// Config bundles the inputs that govern a classification.
type Config struct {
	Policy            Policy
	Keywords          *KeywordSet
	TrustedRebuilders []string // image-repository prefixes treated as LSIO-style rebuilders
	ChangelogMaxChars int      // truncation budget for excerpt rendering
}

// DefaultConfig returns sensible defaults — useful for tests and CLI use.
func DefaultConfig() Config {
	return Config{
		Policy:            DefaultPolicy(),
		Keywords:          NewKeywordSet(nil, nil, nil),
		TrustedRebuilders: append([]string(nil), defaultTrustedRebuilders...),
		ChangelogMaxChars: 500,
	}
}

// Classifier produces RiskAssessments for pending updates.
type Classifier struct {
	cfg Config
}

// New returns a Classifier configured with cfg. Nil sub-fields are replaced
// with defaults so callers can pass partially-populated configs.
func New(cfg Config) *Classifier {
	if cfg.Keywords == nil {
		cfg.Keywords = NewKeywordSet(nil, nil, nil)
	}
	if cfg.ChangelogMaxChars <= 0 {
		cfg.ChangelogMaxChars = 500
	}
	if (cfg.Policy == Policy{}) {
		cfg.Policy = DefaultPolicy()
	}
	if cfg.TrustedRebuilders == nil {
		cfg.TrustedRebuilders = append([]string(nil), defaultTrustedRebuilders...)
	}
	return &Classifier{cfg: cfg}
}

// Classify evaluates the pending update from current → available. Notes may
// be nil (or have empty Body) — the classifier degrades gracefully, returning
// medium-confidence verdicts based on semver alone.
//
// The returned RiskAssessment is never nil unless err is non-nil.
func (c *Classifier) Classify(_ context.Context, current, available types.ImageInfo, notes *ReleaseNotes) (*types.RiskAssessment, error) {
	if current.Repository != available.Repository && current.Repository != "" && available.Repository != "" {
		return nil, fmt.Errorf("classifier: repository mismatch: current=%q available=%q", current.Repository, available.Repository)
	}

	delta := formatDelta(current, available)

	// "trusted rebuilder" promotion: if the publisher uses an LSIO-style
	// rebuild scheme, treat a digest-only change against an unparseable tag
	// as a rebuild, not as an opaque update.
	repo := available.Repository
	if repo == "" {
		repo = current.Repository
	}
	if isTrustedRebuilder(repo, c.cfg.TrustedRebuilders) && delta.Kind == types.ChangeDigest {
		delta.Kind = types.ChangeLSIORebuild
	}

	level := c.cfg.Policy.levelFor(delta.Kind)
	confidence := types.ConfidenceMedium
	rationale := baseRationale(delta.Kind, current, available)

	switch delta.Kind {
	case types.ChangeNone:
		return &types.RiskAssessment{
			Level:      types.RiskSafe,
			Rationale:  "Image is already current.",
			Delta:      delta,
			Confidence: types.ConfidenceHigh,
		}, nil
	case types.ChangeUnknown:
		return &types.RiskAssessment{
			Level:      c.cfg.Policy.Default,
			Rationale:  "Unable to interpret the available tag; falling back to default risk policy.",
			Delta:      delta,
			Confidence: types.ConfidenceLow,
		}, nil
	case types.ChangeLatest, types.ChangeDigest:
		confidence = types.ConfidenceLow
	}

	var matched []KeywordMatch
	if notes != nil && notes.Body != "" {
		matched = c.cfg.Keywords.Scan(notes.Body)
		confidence = types.ConfidenceHigh
		level, rationale = applyKeywords(level, rationale, matched)
	}

	excerpt := ""
	releaseURL := ""
	if notes != nil {
		releaseURL = notes.URL
		excerpt = truncate(notes.Body, c.cfg.ChangelogMaxChars)
	}

	tokens := make([]string, 0, len(matched))
	for _, m := range matched {
		tokens = append(tokens, m.Token)
	}

	return &types.RiskAssessment{
		Level:         level,
		Rationale:     rationale,
		Delta:         delta,
		Confidence:    confidence,
		ReleaseURL:    releaseURL,
		Changelog:     excerpt,
		MatchedTokens: tokens,
	}, nil
}

func baseRationale(k types.ChangeKind, current, available types.ImageInfo) string {
	switch k {
	case types.ChangePatch:
		return fmt.Sprintf("Patch version bump (%s → %s).", current.Tag, available.Tag)
	case types.ChangeMinor:
		return fmt.Sprintf("Minor version bump (%s → %s) — review changelog before applying.", current.Tag, available.Tag)
	case types.ChangeMajor:
		return fmt.Sprintf("Major version bump (%s → %s) — likely breaking changes.", current.Tag, available.Tag)
	case types.ChangeDigest:
		return "Same tag, new image digest — image was rebuilt without a version bump."
	case types.ChangeLSIORebuild:
		return "LinuxServer.io rebuild — base image refreshed, upstream application unchanged."
	case types.ChangeLatest:
		return "Tag is :latest — semantic version cannot be inferred; treating per latest-tag policy."
	case types.ChangePrerelease:
		return fmt.Sprintf("Pre-release version change (%s → %s).", current.Tag, available.Tag)
	case types.ChangeNone:
		return "No change."
	default:
		return "Update kind could not be determined."
	}
}

// applyKeywords ratchets the risk level upward based on matched keywords.
// Risk is never lowered: a SAFE classification with breaking keywords becomes
// BREAKING; a BREAKING classification with security keywords stays BREAKING.
func applyKeywords(level types.RiskLevel, rationale string, matches []KeywordMatch) (types.RiskLevel, string) {
	if len(matches) == 0 {
		return level, rationale
	}

	var breakingTokens, migrationTokens, securityTokens []string
	for _, m := range matches {
		switch m.Class {
		case KeywordBreaking:
			breakingTokens = append(breakingTokens, m.Token)
		case KeywordMigration:
			migrationTokens = append(migrationTokens, m.Token)
		case KeywordSecurity:
			securityTokens = append(securityTokens, m.Token)
		}
	}

	notes := []string{rationale}
	if len(breakingTokens) > 0 {
		if level < types.RiskBreaking {
			level = types.RiskBreaking
		}
		notes = append(notes, fmt.Sprintf("Breaking keywords in release notes: %s.", strings.Join(quote(breakingTokens), ", ")))
	}
	if len(migrationTokens) > 0 {
		if level < types.RiskReview {
			level = types.RiskReview
		}
		notes = append(notes, fmt.Sprintf("Migration keywords in release notes: %s.", strings.Join(quote(migrationTokens), ", ")))
	}
	if len(securityTokens) > 0 {
		notes = append(notes, fmt.Sprintf("Security keywords noted: %s.", strings.Join(quote(securityTokens), ", ")))
	}
	return level, strings.Join(notes, " ")
}

func quote(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
