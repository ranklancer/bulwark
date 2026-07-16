package classifier

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ranklancer/bulwark/pkg/types"
)

// version is a parsed semantic version with optional pre-release / build metadata
// and an optional LinuxServer.io rebuild number.
type version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string // identifiers after `-`, dot-separated; empty if none
	Build      string // identifiers after `+`; empty if none
	LSIO       int    // LinuxServer.io -ls<n> suffix; 0 if absent
	HasLSIO    bool
	Raw        string // the original tag, preserved for human-readable output
}

// strict semver core: major.minor.patch where each component has no leading zeros
// (except the literal "0"). Anchored to start.
var coreRE = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)`)

// LinuxServer.io rebuild suffix anchored to end (after optional +build).
var lsioSuffixRE = regexp.MustCompile(`-ls(\d+)$`)

// parseTag parses an image tag into a version. Returns ok=false for tags that
// cannot be interpreted as semver — callers should treat those as opaque
// (e.g., :latest, :stable, sha-based tags).
func parseTag(tag string) (version, bool) {
	if tag == "" {
		return version{}, false
	}

	v := version{Raw: tag}
	s := tag

	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		// strip leading v but only if what follows looks like a digit; "version-"
		// prefixes used by some images are handled below.
		if len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
			s = s[1:]
		}
	}
	// Some images publish tags like "version-1.2.3-ls45" — strip the prefix.
	s = strings.TrimPrefix(s, "version-")

	// Strip LSIO suffix first so it doesn't confuse the pre-release parser.
	if m := lsioSuffixRE.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			v.LSIO = n
			v.HasLSIO = true
			s = strings.TrimSuffix(s, m[0])
		}
	}

	// Build metadata is optional and trails the pre-release.
	if i := strings.Index(s, "+"); i >= 0 {
		v.Build = s[i+1:]
		s = s[:i]
	}

	loc := coreRE.FindStringSubmatchIndex(s)
	if loc == nil {
		return version{}, false
	}
	maj, _ := strconv.Atoi(s[loc[2]:loc[3]])
	min, _ := strconv.Atoi(s[loc[4]:loc[5]])
	pat, _ := strconv.Atoi(s[loc[6]:loc[7]])
	v.Major = maj
	v.Minor = min
	v.Patch = pat

	rest := s[loc[1]:]
	if rest == "" {
		return v, true
	}
	// Pre-release must start with `-` per semver. We're permissive of stray
	// suffixes: anything else after the core is treated as an opaque pre-release
	// label so we can still compare numerically with reasonable behavior.
	if rest[0] == '-' {
		v.Prerelease = rest[1:]
	} else {
		v.Prerelease = rest
	}
	return v, true
}

// compare returns -1, 0, or 1 for a < b, a == b, a > b.
// Comparison rules:
//  1. major / minor / patch numeric
//  2. a version with no pre-release outranks one with a pre-release (semver §11.3)
//  3. pre-release identifiers compared dot-by-dot (numeric < non-numeric, lower wins)
//  4. LSIO build numbers compared numerically last
func (a version) compare(b version) int {
	if a.Major != b.Major {
		return cmpInt(a.Major, b.Major)
	}
	if a.Minor != b.Minor {
		return cmpInt(a.Minor, b.Minor)
	}
	if a.Patch != b.Patch {
		return cmpInt(a.Patch, b.Patch)
	}
	if a.Prerelease == "" && b.Prerelease != "" {
		return 1
	}
	if a.Prerelease != "" && b.Prerelease == "" {
		return -1
	}
	if a.Prerelease != b.Prerelease {
		return comparePrerelease(a.Prerelease, b.Prerelease)
	}
	if a.LSIO != b.LSIO {
		return cmpInt(a.LSIO, b.LSIO)
	}
	return 0
}

// comparePrerelease compares two pre-release strings per semver §11.4.
// Numeric identifiers compare numerically; alphanumeric identifiers compare
// lexically; numeric identifiers have lower precedence than alphanumeric.
func comparePrerelease(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		aNum := errA == nil
		bNum := errB == nil
		switch {
		case aNum && bNum:
			if na != nb {
				return cmpInt(na, nb)
			}
		case aNum:
			return -1
		case bNum:
			return 1
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(pa), len(pb))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// classifyChange determines what kind of version transition `current → available`
// represents. It does not apply policy — callers translate ChangeKind to RiskLevel
// using a Policy.
func classifyChange(current, available types.ImageInfo) types.ChangeKind {
	// :latest tag — semver cannot be inferred from the tag alone.
	if current.Tag == "latest" || available.Tag == "latest" {
		if current.Digest != "" && available.Digest != "" && current.Digest != available.Digest {
			return types.ChangeLatest
		}
		if current.Tag == available.Tag && current.Digest == available.Digest {
			return types.ChangeNone
		}
		return types.ChangeLatest
	}

	cv, cOK := parseTag(current.Tag)
	av, aOK := parseTag(available.Tag)

	// Both tags unparseable — fall back to digest comparison.
	if !cOK && !aOK {
		if current.Digest == available.Digest && current.Tag == available.Tag {
			return types.ChangeNone
		}
		if current.Tag == available.Tag {
			return types.ChangeDigest
		}
		return types.ChangeUnknown
	}
	if !cOK || !aOK {
		// Mixed — one parseable, one not. Treat as unknown to be safe.
		return types.ChangeUnknown
	}

	cmp := cv.compare(av)
	if cmp == 0 {
		// Versions identical. Check digest for rebuild detection.
		if current.Digest != "" && available.Digest != "" && current.Digest != available.Digest {
			return types.ChangeDigest
		}
		return types.ChangeNone
	}
	if cmp > 0 {
		// Available is older than current — not an update.
		return types.ChangeNone
	}

	// Available is newer. Determine the kind.
	if cv.Major != av.Major {
		return types.ChangeMajor
	}
	if cv.Minor != av.Minor {
		return types.ChangeMinor
	}
	if cv.Patch != av.Patch {
		return types.ChangePatch
	}
	if cv.Prerelease != av.Prerelease {
		return types.ChangePrerelease
	}
	if cv.HasLSIO || av.HasLSIO {
		return types.ChangeLSIORebuild
	}
	return types.ChangeDigest
}

// formatDelta renders a human-readable "from → to" string for the given images.
func formatDelta(current, available types.ImageInfo) types.VersionDelta {
	from := current.Tag
	to := available.Tag
	if from == "" {
		from = shortDigest(current.Digest)
	}
	if to == "" {
		to = shortDigest(available.Digest)
	}
	return types.VersionDelta{
		Kind: classifyChange(current, available),
		From: from,
		To:   to,
	}
}

func shortDigest(d string) string {
	if d == "" {
		return ""
	}
	if i := strings.Index(d, ":"); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
