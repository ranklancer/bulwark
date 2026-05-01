// Package registry provides a thin client over the OCI distribution API.
// It can resolve a tag to a manifest digest and list the tags published
// for a repository — enough for Bulwark to detect updates without taking
// a dependency on the (heavyweight) Docker SDK.
package registry

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// DefaultRegistry is the host substituted when a reference omits one
// (e.g. "nginx" or "library/redis"). The Docker Hub registry endpoint is
// `registry-1.docker.io`; the legacy `index.docker.io` is also accepted.
const DefaultRegistry = "registry-1.docker.io"

// Reference is a parsed Docker / OCI image reference, decomposed into the
// pieces needed to make HTTP requests against the registry.
type Reference struct {
	Registry   string // host[:port], e.g. "lscr.io" or "registry-1.docker.io"
	Repository string // path, e.g. "linuxserver/sonarr" or "library/nginx"
	Tag        string // e.g. "4.0.10-ls45"; empty if reference is digest-only
	Digest     string // e.g. "sha256:abc..."; empty if not specified
}

// String renders the reference back into its canonical "registry/repo:tag@digest"
// form, omitting empty parts.
func (r Reference) String() string {
	out := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		out += ":" + r.Tag
	}
	if r.Digest != "" {
		out += "@" + r.Digest
	}
	return out
}

// FullName is the canonical image name without any tag or digest suffix —
// suitable for the Repository field of types.ImageInfo.
func (r Reference) FullName() string {
	return r.Registry + "/" + r.Repository
}

// ToImageInfo lifts a Reference into the types.ImageInfo used by the
// classifier. The classifier doesn't need the registry/repository split,
// so we collapse them back into a single FullName.
func (r Reference) ToImageInfo() types.ImageInfo {
	return types.ImageInfo{
		Repository: r.FullName(),
		Tag:        r.Tag,
		Digest:     r.Digest,
	}
}

// Parse parses a Docker / OCI image reference. The accepted forms are:
//
//	[registry[:port]/]repository[:tag][@digest]
//
// When the registry is omitted, DefaultRegistry is used and a single-segment
// repository is namespaced under "library/" (so "nginx" resolves to
// "library/nginx" on Docker Hub).
//
// Defaults:
//   - Tag defaults to "latest" when neither tag nor digest is provided.
//   - Tag is left empty when only a digest is provided (digest pin).
func Parse(ref string) (Reference, error) {
	if ref == "" {
		return Reference{}, errors.New("registry: empty reference")
	}
	var r Reference
	rest := ref

	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest = rest[i+1:]
		rest = rest[:i]
	}

	// Determine whether the first segment is a registry host. Per the Docker
	// reference grammar, it qualifies if it contains "." or ":", or is exactly
	// "localhost". Anything else is treated as part of the repository name on
	// the default registry.
	if i := strings.Index(rest, "/"); i >= 0 {
		first := rest[:i]
		if isRegistryHost(first) {
			r.Registry = first
			rest = rest[i+1:]
		}
	}
	if r.Registry == "" {
		r.Registry = DefaultRegistry
	} else if r.Registry == "index.docker.io" || r.Registry == "docker.io" {
		r.Registry = DefaultRegistry
	}

	// Tag is the part after the LAST colon, but only if that colon comes after
	// the last slash — otherwise we'd misinterpret a port number ("registry:5000/x").
	slash := strings.LastIndex(rest, "/")
	colon := strings.LastIndex(rest, ":")
	if colon > slash {
		r.Tag = rest[colon+1:]
		rest = rest[:colon]
	}
	r.Repository = rest

	if r.Repository == "" {
		return Reference{}, fmt.Errorf("registry: missing repository in %q", ref)
	}

	if r.Registry == DefaultRegistry && !strings.Contains(r.Repository, "/") {
		r.Repository = "library/" + r.Repository
	}

	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}

	return r, nil
}

func isRegistryHost(s string) bool {
	if s == "" {
		return false
	}
	if s == "localhost" {
		return true
	}
	return strings.ContainsAny(s, ".:")
}
