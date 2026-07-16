package classifier

import "strings"

// defaultTrustedRebuilders is the built-in list of registry prefixes whose
// images use a non-semver "rebuild" tagging scheme. For these images, a tag
// bump that only changes the rebuild number indicates a base-image refresh
// (security patches) rather than upstream application changes.
var defaultTrustedRebuilders = []string{
	"lscr.io/linuxserver/",
	"ghcr.io/linuxserver/",
	"docker.io/linuxserver/",
	"linuxserver/",
}

// isTrustedRebuilder reports whether the given image repository is published
// by a known LSIO-style rebuilder. The match is a case-insensitive prefix
// against the configured list.
func isTrustedRebuilder(repository string, prefixes []string) bool {
	if repository == "" {
		return false
	}
	repo := strings.ToLower(repository)
	for _, p := range prefixes {
		if strings.HasPrefix(repo, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
