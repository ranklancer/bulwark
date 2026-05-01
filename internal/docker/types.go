package docker

import (
	"strings"
	"time"
)

// Container is the normalized form of a Docker container as Bulwark consumes it.
type Container struct {
	ID        string
	Name      string            // first name with the leading slash stripped
	Image     string            // image reference as recorded by Docker
	ImageID   string            // local image ID (e.g. "sha256:abc...")
	State     string            // "running", "exited", "paused", etc.
	Status    string            // human-readable status, e.g. "Up 2 hours"
	Labels    map[string]string // never nil; empty map when no labels
	CreatedAt time.Time
}

// ComposeProject returns the Docker Compose project this container belongs to,
// inferred from the standard "com.docker.compose.project" label. Empty when
// the container was not created by Compose.
func (c Container) ComposeProject() string {
	return c.Labels["com.docker.compose.project"]
}

// ComposeService returns the Compose service name. Empty for non-Compose
// containers.
func (c Container) ComposeService() string {
	return c.Labels["com.docker.compose.service"]
}

// ImageInspect carries the small subset of /images/<id>/json that Bulwark needs.
type ImageInspect struct {
	ID          string
	RepoTags    []string
	RepoDigests []string
}

// DigestFor returns the registry-side digest from RepoDigests for the given
// repository, if present. Docker records each pull as
// "<repository>@sha256:<hex>" — so when the user pulled
// "lscr.io/linuxserver/sonarr:4.0.10-ls45" the inspect output contains
// "lscr.io/linuxserver/sonarr@sha256:abc...".
//
// Returns "" when no matching digest is recorded — the caller should treat
// that as "running digest unknown" rather than as an error.
func (i *ImageInspect) DigestFor(repository string) string {
	if i == nil {
		return ""
	}
	prefix := repository + "@"
	for _, d := range i.RepoDigests {
		if strings.HasPrefix(d, prefix) {
			return strings.TrimPrefix(d, prefix)
		}
	}
	return ""
}
