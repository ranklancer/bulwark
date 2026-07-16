// Package docker is a minimal client for the local Docker Engine socket.
// It speaks the documented HTTP API directly rather than depending on the
// Docker SDK — the SDK pulls in containerd, gRPC, and friends, which would
// roughly 10x our binary size for the three endpoints we actually use.
//
// We support only the read-only operations Bulwark needs at this stage:
// listing containers and inspecting their images. Update operations (pull,
// stop, start, recreate) come in a later phase.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultSocketPath is where the Docker daemon listens on Linux. macOS Desktop
// and Podman expose the socket at different paths; users override via Config.
const DefaultSocketPath = "/var/run/docker.sock"

// Client talks to a Docker Engine over either a Unix socket (production) or
// an HTTP endpoint (BaseURL — used by tests against an httptest.Server).
type Client struct {
	HTTPClient *http.Client
	BaseURL    string // e.g. "http://docker" for socket transport, or the test server URL
}

// New returns a Client configured to talk to Docker. The host may be:
//
//   - ""                 the local Unix socket at DefaultSocketPath
//   - "/path/docker.sock" a Unix socket at that path
//   - "unix:///path"      a Unix socket at that path
//   - "tcp://host:port"   a TCP endpoint, e.g. a docker-socket-proxy
//   - "http(s)://host"    an HTTP endpoint (also used by tests)
//
// TCP/HTTP endpoints let Bulwark reach the daemon through a
// docker-socket-proxy instead of bind-mounting the raw /var/run/docker.sock,
// so a compromised Bulwark cannot drive the Docker daemon directly.
func New(host string) *Client {
	if host == "" {
		host = DefaultSocketPath
	}
	switch {
	case strings.HasPrefix(host, "tcp://"):
		return &Client{
			HTTPClient: &http.Client{
				Transport: &http.Transport{IdleConnTimeout: 30 * time.Second},
				Timeout:   30 * time.Second,
			},
			BaseURL: "http://" + strings.TrimPrefix(host, "tcp://"),
		}
	case strings.HasPrefix(host, "http://"), strings.HasPrefix(host, "https://"):
		return &Client{
			HTTPClient: &http.Client{
				Transport: &http.Transport{IdleConnTimeout: 30 * time.Second},
				Timeout:   30 * time.Second,
			},
			BaseURL: strings.TrimRight(host, "/"),
		}
	}
	// Unix-socket transport (production default). The "unix://" scheme, if
	// present, is stripped to the bare socket path.
	socketPath := strings.TrimPrefix(host, "unix://")
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{
		HTTPClient: &http.Client{Transport: t, Timeout: 30 * time.Second},
		// The host portion is meaningless for Unix-socket transports; Docker
		// ignores it. "http://docker" makes it obvious in logs this is the
		// daemon and not a generic localhost service.
		BaseURL: "http://docker",
	}
}

// Ping verifies the Docker daemon is reachable. Useful as a health check on
// startup so we can give a clean error message ("permission denied — add the
// running user to the docker group") instead of a confusing late failure.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, "GET", "/_ping", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: ping: %s", resp.Status)
	}
	return nil
}

// ListContainers returns the containers managed by the daemon. When all is
// false, only running containers are returned (matching `docker ps`).
func (c *Client) ListContainers(ctx context.Context, all bool) ([]Container, error) {
	q := url.Values{}
	if all {
		q.Set("all", "true")
	}
	path := "/containers/json"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	resp, err := c.do(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: list containers: %s", resp.Status)
	}

	var raw []containerListItem
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("docker: decode list response: %w", err)
	}
	out := make([]Container, 0, len(raw))
	for _, item := range raw {
		out = append(out, item.normalize())
	}
	return out, nil
}

// InspectImage returns the digest-bearing metadata for an image, identified
// by either its sha256 ID or a name. Returns (nil, nil) if Docker reports
// 404 — useful for distinguishing "image not present locally" from genuine
// errors.
func (c *Client) InspectImage(ctx context.Context, idOrRef string) (*ImageInspect, error) {
	if idOrRef == "" {
		return nil, errors.New("docker: InspectImage requires a non-empty id or reference")
	}
	resp, err := c.do(ctx, "GET", "/images/"+url.PathEscape(idOrRef)+"/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: inspect image %s: %s", idOrRef, resp.Status)
	}

	var raw imageInspect
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("docker: read inspect response: %w", err)
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("docker: decode inspect response: %w", err)
	}
	return raw.normalize(), nil
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, normalizeNetError(err)
	}
	return resp, nil
}

// normalizeNetError translates the most common confusing transport errors
// into messages users can act on.
func normalizeNetError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connect: permission denied"):
		return fmt.Errorf("docker: permission denied connecting to socket — add the running user to the docker group, or run with appropriate permissions: %w", err)
	case strings.Contains(msg, "connect: no such file or directory"):
		return fmt.Errorf("docker: socket not found — is the Docker daemon running? Override the path with --docker-host: %w", err)
	default:
		return err
	}
}

// containerListItem mirrors the on-the-wire JSON returned by /containers/json.
// We keep the wire shape internal and expose only the normalized Container
// type to callers, so changes upstream don't ripple through Bulwark.
type containerListItem struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Command string            `json:"Command"`
	Created int64             `json:"Created"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
}

func (item containerListItem) normalize() Container {
	name := ""
	if len(item.Names) > 0 {
		name = strings.TrimPrefix(item.Names[0], "/")
	}
	labels := item.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return Container{
		ID:        item.ID,
		Name:      name,
		Image:     item.Image,
		ImageID:   item.ImageID,
		State:     item.State,
		Status:    item.Status,
		Labels:    labels,
		CreatedAt: time.Unix(item.Created, 0).UTC(),
	}
}

// imageInspect mirrors /images/<id>/json. We extract only what we need.
type imageInspect struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

func (i imageInspect) normalize() *ImageInspect {
	return &ImageInspect{
		ID:          i.ID,
		RepoTags:    append([]string(nil), i.RepoTags...),
		RepoDigests: append([]string(nil), i.RepoDigests...),
	}
}
