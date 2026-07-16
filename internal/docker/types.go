package docker

import (
	"encoding/json"
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

// HealthStatus is the parsed value of /containers/<id>/json's State.Health.Status.
// Docker uses one of: "starting", "healthy", "unhealthy". Containers without a
// HEALTHCHECK have no Health field and yield HealthNone.
type HealthStatus int

const (
	HealthNone HealthStatus = iota
	HealthStarting
	HealthHealthy
	HealthUnhealthy
)

func (h HealthStatus) String() string {
	switch h {
	case HealthStarting:
		return "starting"
	case HealthHealthy:
		return "healthy"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "none"
	}
}

// ContainerInspect is the subset of /containers/<id>/json needed to drive
// recreate-with-rollback. Config + HostConfig + NetworkSettings are kept as
// json.RawMessage pass-throughs; we don't introspect them but pass them
// back into POST /containers/create when recreating with a new image.
type ContainerInspect struct {
	ID              string
	Name            string // includes the leading slash exactly as Docker returns it
	Image           string // e.g. "sha256:abc..."
	ImageRef        string // the human-readable ref (e.g. "lscr.io/.../sonarr:4.0.10")
	Running         bool
	Health          HealthStatus
	Config          json.RawMessage // Cmd, Env, Labels, ExposedPorts, Image, etc.
	HostConfig      json.RawMessage // Binds, RestartPolicy, NetworkMode, etc.
	NetworkSettings json.RawMessage // Networks (used to rebuild NetworkingConfig.EndpointsConfig)
}

// NameWithoutSlash returns Name with the leading "/" stripped, matching
// Container.Name semantics.
func (c *ContainerInspect) NameWithoutSlash() string {
	if c == nil {
		return ""
	}
	return strings.TrimPrefix(c.Name, "/")
}

// HealthcheckStartPeriod returns the StartPeriod field of the
// container's Healthcheck config, when one is defined. The value is
// parsed straight out of the Config raw JSON Bulwark already keeps
// around for re-creation; we don't need a second inspect call.
//
// Returns (0, false) when there's no Healthcheck, no StartPeriod, or
// the JSON is malformed. Bulwark's caller treats false as "no
// override" — fall through to the daemon-wide StartupGrace default.
func (c *ContainerInspect) HealthcheckStartPeriod() (time.Duration, bool) {
	if c == nil || len(c.Config) == 0 {
		return 0, false
	}
	var cfg struct {
		Healthcheck *struct {
			StartPeriod time.Duration `json:"StartPeriod"`
		} `json:"Healthcheck"`
	}
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return 0, false
	}
	if cfg.Healthcheck == nil || cfg.Healthcheck.StartPeriod <= 0 {
		return 0, false
	}
	return cfg.Healthcheck.StartPeriod, true
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
