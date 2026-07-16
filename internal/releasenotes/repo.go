// Package releasenotes maps image references to release-notes sources and
// fetches the notes when possible. It is best-effort: when no source can be
// identified, callers should treat that as "no notes" rather than an error.
package releasenotes

import (
	"strings"

	"github.com/ranklancer/bulwark/internal/registry"
)

// Provider identifies the kind of upstream that hosts release notes.
type Provider string

const (
	ProviderGitHub Provider = "github"
)

// Source identifies a specific upstream that may hold release notes.
type Source struct {
	Provider Provider
	Owner    string
	Repo     string
}

// String returns "github.com/<owner>/<repo>" or similar — useful for logging.
func (s Source) String() string {
	switch s.Provider {
	case ProviderGitHub:
		return "github.com/" + s.Owner + "/" + s.Repo
	default:
		return string(s.Provider) + ":" + s.Owner + "/" + s.Repo
	}
}

// Mapper resolves image references to release-notes sources. The default
// mapper handles GHCR and the LinuxServer.io repository conventions; users
// can add explicit overrides via Add().
type Mapper struct {
	overrides map[string]Source // image prefix → source (longest-match wins)
}

// NewMapper returns a mapper with no overrides.
func NewMapper() *Mapper {
	return &Mapper{overrides: make(map[string]Source)}
}

// Add registers an explicit prefix → source mapping. The prefix is matched
// case-insensitively against the image's full name (registry/repository).
// The longest matching prefix wins, so users can refine inherited defaults.
func (m *Mapper) Add(imagePrefix string, source Source) {
	if imagePrefix == "" {
		return
	}
	m.overrides[strings.ToLower(imagePrefix)] = source
}

// Map returns the source for ref, or false if none could be inferred.
//
// Resolution order:
//  1. Longest user-configured override prefix.
//  2. LinuxServer.io heuristic — lscr.io/linuxserver/X and
//     ghcr.io/linuxserver/X both map to github.com/linuxserver/docker-X.
//  3. GHCR heuristic — ghcr.io/<owner>/<repo> maps to github.com/<owner>/<repo>.
func (m *Mapper) Map(ref registry.Reference) (Source, bool) {
	full := strings.ToLower(ref.Registry + "/" + ref.Repository)

	if m != nil {
		var bestPrefix string
		var bestSource Source
		for prefix, src := range m.overrides {
			if !strings.HasPrefix(full, prefix) {
				continue
			}
			if len(prefix) > len(bestPrefix) {
				bestPrefix = prefix
				bestSource = src
			}
		}
		if bestPrefix != "" {
			return bestSource, true
		}
	}

	if isLSIO(ref) {
		// linuxserver/sonarr → docker-sonarr; the org always uses this prefix
		// for image-build repos.
		_, name, ok := splitOwnerRepo(ref.Repository)
		if ok && name != "" {
			return Source{Provider: ProviderGitHub, Owner: "linuxserver", Repo: "docker-" + name}, true
		}
	}

	if strings.EqualFold(ref.Registry, "ghcr.io") {
		owner, repo, ok := splitOwnerRepo(ref.Repository)
		if ok {
			return Source{Provider: ProviderGitHub, Owner: owner, Repo: repo}, true
		}
	}

	return Source{}, false
}

func isLSIO(ref registry.Reference) bool {
	host := strings.ToLower(ref.Registry)
	repo := strings.ToLower(ref.Repository)
	switch host {
	case "lscr.io", "ghcr.io", "docker.io", "registry-1.docker.io":
		return strings.HasPrefix(repo, "linuxserver/")
	}
	return false
}

func splitOwnerRepo(repository string) (owner, repo string, ok bool) {
	i := strings.Index(repository, "/")
	if i < 0 {
		return "", "", false
	}
	owner = repository[:i]
	repo = repository[i+1:]
	if strings.Contains(repo, "/") {
		// We treat only the first segment as owner; deeper paths aren't valid
		// "owner/repo" pairs on GitHub (those would be paths inside a repo).
		return "", "", false
	}
	return owner, repo, owner != "" && repo != ""
}

// CandidateTags returns the GitHub release tags to try, in priority order, for
// the given Docker image tag. We toggle the "v" prefix and, for LSIO-style
// "X.Y.Z-ls<n>" tags, also try the stripped upstream version. Callers should
// fetch in order until one succeeds (or all fail, meaning "no notes available").
func CandidateTags(imageTag string) []string {
	if imageTag == "" {
		return nil
	}
	if strings.EqualFold(imageTag, "latest") {
		return nil
	}

	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	add(imageTag)
	add(togglePrefix(imageTag))

	if base, ok := stripLSIOSuffix(imageTag); ok {
		add(base)
		add(togglePrefix(base))
	}

	return out
}

func togglePrefix(s string) string {
	if strings.HasPrefix(s, "v") && len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
		return s[1:]
	}
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		return "v" + s
	}
	return ""
}

func stripLSIOSuffix(s string) (string, bool) {
	i := strings.LastIndex(s, "-ls")
	if i < 0 {
		return "", false
	}
	suffix := s[i+3:]
	if suffix == "" {
		return "", false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return s[:i], true
}
