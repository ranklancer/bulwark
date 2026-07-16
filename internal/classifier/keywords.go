package classifier

import (
	"regexp"
	"strings"
)

// KeywordClass tags a matched keyword with the kind of risk signal it represents.
type KeywordClass int

const (
	KeywordBreaking  KeywordClass = iota // raises classification to BREAKING
	KeywordMigration                     // raises classification to at least REVIEW
	KeywordSecurity                      // annotates only; never raises or lowers risk
)

// KeywordMatch records that a particular keyword was found in the scanned text.
type KeywordMatch struct {
	Class KeywordClass
	Token string // the matched keyword in its canonical lowercase form
}

// KeywordSet contains the compiled regular expressions used to scan release notes.
// Patterns are matched case-insensitively with word boundaries to reduce false
// positives from substring collisions ("remove" inside "removed" is fine; but
// "remote" should not match "remoted").
type KeywordSet struct {
	breaking  []*regexp.Regexp
	migration []*regexp.Regexp
	security  []*regexp.Regexp

	rawBreaking  []string
	rawMigration []string
	rawSecurity  []string
}

// DefaultBreakingKeywords are the phrases that, when found in release notes,
// raise the risk classification to BREAKING. We deliberately err on the side
// of over-flagging: a false BREAKING means the user manually approves; a false
// SAFE could mean production data loss.
var DefaultBreakingKeywords = []string{
	"breaking change",
	"breaking changes",
	"incompatible",
	"no longer compatible",
	"action required",
	"manual intervention",
	"manual migration",
	"deprecated and removed",
	"removed support for",
	"backwards incompatible",
	"backward incompatible",
	"must upgrade",
	"must downgrade",
}

// DefaultMigrationKeywords raise classification to at least REVIEW.
var DefaultMigrationKeywords = []string{
	"migration required",
	"database migration",
	"schema change",
	"schema migration",
	"config change required",
	"configuration change required",
	"reindex required",
	"data migration",
}

// DefaultSecurityKeywords annotate the assessment but do not change the
// classification level. Users who want to fast-track security patches can
// configure an explicit policy override.
var DefaultSecurityKeywords = []string{
	"security fix",
	"security patch",
	"vulnerability",
	"vulnerabilities",
	"cve-",
}

// NewKeywordSet compiles the provided keyword lists. If any list is nil, the
// corresponding default list is used instead.
func NewKeywordSet(breaking, migration, security []string) *KeywordSet {
	if breaking == nil {
		breaking = DefaultBreakingKeywords
	}
	if migration == nil {
		migration = DefaultMigrationKeywords
	}
	if security == nil {
		security = DefaultSecurityKeywords
	}
	ks := &KeywordSet{
		rawBreaking:  cloneLower(breaking),
		rawMigration: cloneLower(migration),
		rawSecurity:  cloneLower(security),
	}
	ks.breaking = compileAll(ks.rawBreaking)
	ks.migration = compileAll(ks.rawMigration)
	ks.security = compileAll(ks.rawSecurity)
	return ks
}

func cloneLower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func compileAll(words []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(words))
	for _, w := range words {
		if w == "" {
			continue
		}
		// Only anchor with `\b` on a side whose first/last rune is a word
		// character. Otherwise the boundary would never match (e.g. `\bcve-\b`
		// would not match "cve- " because space is non-word and `-` is non-word).
		pat := regexp.QuoteMeta(w)
		if isWordByte(w[0]) {
			pat = `\b` + pat
		}
		if isWordByte(w[len(w)-1]) {
			pat = pat + `\b`
		}
		out = append(out, regexp.MustCompile(`(?i)`+pat))
	}
	return out
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

// Scan returns all keyword matches found in text. Order of returned matches is
// stable: breaking, then migration, then security, in the order each pattern
// was registered. Duplicate hits for the same pattern are reported once.
func (k *KeywordSet) Scan(text string) []KeywordMatch {
	if k == nil || text == "" {
		return nil
	}
	var matches []KeywordMatch
	matches = appendMatches(matches, text, k.breaking, k.rawBreaking, KeywordBreaking)
	matches = appendMatches(matches, text, k.migration, k.rawMigration, KeywordMigration)
	matches = appendMatches(matches, text, k.security, k.rawSecurity, KeywordSecurity)
	return matches
}

func appendMatches(dst []KeywordMatch, text string, patterns []*regexp.Regexp, raw []string, class KeywordClass) []KeywordMatch {
	for i, re := range patterns {
		if re.MatchString(text) {
			dst = append(dst, KeywordMatch{Class: class, Token: raw[i]})
		}
	}
	return dst
}
