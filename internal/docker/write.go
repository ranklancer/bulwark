package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PullImage pulls the image referenced by ref from its registry. The Docker
// API streams newline-delimited JSON progress messages; if the final
// message contains "errorDetail", the pull failed.
//
// Authentication is not implemented at this layer — public registries only.
// Private-registry pulls require the X-Registry-Auth header per the Docker
// engine docs and will be added when Bulwark grows credential management.
func (c *Client) PullImage(ctx context.Context, ref string) error {
	if ref == "" {
		return errors.New("docker: PullImage requires a reference")
	}
	// The endpoint takes "fromImage" (everything before ":") and "tag"
	// separately. Anything after the LAST colon (only if it comes after
	// the last slash) is the tag — same heuristic as registry.Parse.
	fromImage, tag := splitImageTag(ref)
	q := url.Values{}
	q.Set("fromImage", fromImage)
	if tag != "" {
		q.Set("tag", tag)
	}
	resp, err := c.do(ctx, "POST", "/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("docker: pull %s: %s — %s", ref, resp.Status, strings.TrimSpace(string(body)))
	}
	return drainPullStream(resp.Body)
}

func splitImageTag(ref string) (fromImage, tag string) {
	// Strip any digest part — pull-by-digest goes through fromImage with
	// the @sha256:... suffix attached, which the Docker API accepts.
	at := strings.LastIndex(ref, "@")
	if at >= 0 {
		// Pulling by digest: keep the digest in fromImage, no tag.
		return ref, ""
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, "latest"
}

// drainPullStream reads newline-delimited JSON progress messages and returns
// any error reported by the engine. Non-fatal status messages are discarded.
func drainPullStream(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			// Engine sometimes emits non-JSON whitespace; ignore.
			continue
		}
		if msg.Error != "" {
			return fmt.Errorf("docker: pull failed: %s", msg.Error)
		}
		if msg.ErrorDetail.Message != "" {
			return fmt.Errorf("docker: pull failed: %s", msg.ErrorDetail.Message)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("docker: read pull stream: %w", err)
	}
	return nil
}

// InspectContainer returns the full container metadata required to recreate
// it with a new image. The Config, HostConfig, and NetworkSettings blocks
// are returned as json.RawMessage so callers can pass them back into
// CreateContainer without a lossy round-trip through Bulwark's structs.
func (c *Client) InspectContainer(ctx context.Context, id string) (*ContainerInspect, error) {
	if id == "" {
		return nil, errors.New("docker: InspectContainer requires an id")
	}
	resp, err := c.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: inspect container %s: %s", id, resp.Status)
	}
	var raw struct {
		ID              string          `json:"Id"`
		Name            string          `json:"Name"`
		Image           string          `json:"Image"`
		Config          json.RawMessage `json:"Config"`
		HostConfig      json.RawMessage `json:"HostConfig"`
		NetworkSettings json.RawMessage `json:"NetworkSettings"`
		State           struct {
			Running bool `json:"Running"`
			Health  *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("docker: read inspect response: %w", err)
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("docker: decode inspect response: %w", err)
	}
	out := &ContainerInspect{
		ID:              raw.ID,
		Name:            raw.Name,
		Image:           raw.Image,
		Config:          raw.Config,
		HostConfig:      raw.HostConfig,
		NetworkSettings: raw.NetworkSettings,
		Running:         raw.State.Running,
		Health:          parseHealthStatus(raw.State.Health),
	}
	// The Config block contains an "Image" field — extract it for callers
	// that want the human-readable reference.
	out.ImageRef = imageRefFromConfig(raw.Config)
	return out, nil
}

func parseHealthStatus(h *struct {
	Status string `json:"Status"`
}) HealthStatus {
	if h == nil {
		return HealthNone
	}
	switch h.Status {
	case "starting":
		return HealthStarting
	case "healthy":
		return HealthHealthy
	case "unhealthy":
		return HealthUnhealthy
	default:
		return HealthNone
	}
}

func imageRefFromConfig(cfg json.RawMessage) string {
	var probe struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(cfg, &probe); err != nil {
		return ""
	}
	return probe.Image
}

// StopContainer stops the container with a per-container stop-timeout
// (seconds). Pass 0 for the engine default. 304 (already stopped) is
// treated as success.
func (c *Client) StopContainer(ctx context.Context, id string, timeoutSec int) error {
	q := url.Values{}
	if timeoutSec > 0 {
		q.Set("t", strconv.Itoa(timeoutSec))
	}
	path := "/containers/" + url.PathEscape(id) + "/stop"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return c.expectNoBody(ctx, "POST", path, http.StatusNoContent, http.StatusNotModified)
}

// StartContainer starts an existing stopped container. 304 (already
// running) is treated as success.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.expectNoBody(ctx, "POST",
		"/containers/"+url.PathEscape(id)+"/start",
		http.StatusNoContent, http.StatusNotModified)
}

// RemoveContainer deletes a container. force=true allows removal of running
// containers (Docker will SIGKILL first); volumes are NOT removed (we never
// want to drop user data on rollback).
func (c *Client) RemoveContainer(ctx context.Context, id string, force bool) error {
	q := url.Values{}
	if force {
		q.Set("force", "true")
	}
	q.Set("v", "false") // never auto-remove anonymous volumes
	return c.expectNoBody(ctx, "DELETE",
		"/containers/"+url.PathEscape(id)+"?"+q.Encode(),
		http.StatusNoContent)
}

// RenameContainer renames an existing container. Used during recreate to
// preserve the old container under a "<name>-bulwark-old" handle so we can
// restore it on health failure.
func (c *Client) RenameContainer(ctx context.Context, id, newName string) error {
	q := url.Values{}
	q.Set("name", newName)
	return c.expectNoBody(ctx, "POST",
		"/containers/"+url.PathEscape(id)+"/rename?"+q.Encode(),
		http.StatusNoContent)
}

// CreateContainerConfig is the body of POST /containers/create. We expose
// it as a typed struct rather than a bare map so callers can construct it
// from an inspect output via NewCreateConfigFromInspect.
type CreateContainerConfig struct {
	// Embed the inspect's Config block directly — Docker's create endpoint
	// accepts the same fields (Image, Cmd, Env, Labels, ExposedPorts,
	// WorkingDir, etc.) at the top level.
	Config           json.RawMessage `json:"-"` // populated via NewCreateConfigFromInspect
	HostConfig       json.RawMessage `json:"HostConfig,omitempty"`
	NetworkingConfig json.RawMessage `json:"NetworkingConfig,omitempty"`
}

// NewCreateConfigFromInspect builds a create body from an existing
// container's inspect output, substituting newImage for the original
// Config.Image. NetworkingConfig is rebuilt from NetworkSettings.Networks
// so the recreated container rejoins the same networks.
func NewCreateConfigFromInspect(insp *ContainerInspect, newImage string) (CreateContainerConfig, error) {
	if insp == nil {
		return CreateContainerConfig{}, errors.New("docker: NewCreateConfigFromInspect requires an inspect result")
	}

	// Decode Config so we can swap the Image field.
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(insp.Config, &cfg); err != nil {
		return CreateContainerConfig{}, fmt.Errorf("docker: decode Config: %w", err)
	}
	imgBytes, _ := json.Marshal(newImage)
	cfg["Image"] = imgBytes

	// Re-marshal merged Config.
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return CreateContainerConfig{}, fmt.Errorf("docker: encode merged Config: %w", err)
	}

	// Build NetworkingConfig.EndpointsConfig from NetworkSettings.Networks.
	// The shape of an Endpoints entry is the same in inspect and create —
	// we just have to wrap it under the right key.
	var ns struct {
		Networks json.RawMessage `json:"Networks"`
	}
	_ = json.Unmarshal(insp.NetworkSettings, &ns)
	var netCfg json.RawMessage
	if len(ns.Networks) > 0 && string(ns.Networks) != "null" {
		netCfg, _ = json.Marshal(map[string]json.RawMessage{
			"EndpointsConfig": ns.Networks,
		})
	}

	return CreateContainerConfig{
		Config:           cfgBytes,
		HostConfig:       insp.HostConfig,
		NetworkingConfig: netCfg,
	}, nil
}

// CreateContainer creates a new container with the given name and config,
// returning the new container ID.
func (c *Client) CreateContainer(ctx context.Context, name string, cfg CreateContainerConfig) (string, error) {
	if name == "" {
		return "", errors.New("docker: CreateContainer requires a name")
	}

	// Build the body: Config fields at the top level, plus HostConfig and
	// NetworkingConfig under their own keys.
	merged := map[string]json.RawMessage{}
	if err := json.Unmarshal(cfg.Config, &merged); err != nil {
		return "", fmt.Errorf("docker: encode create Config: %w", err)
	}
	if len(cfg.HostConfig) > 0 {
		merged["HostConfig"] = cfg.HostConfig
	}
	if len(cfg.NetworkingConfig) > 0 {
		merged["NetworkingConfig"] = cfg.NetworkingConfig
	}
	body, err := json.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("docker: marshal create body: %w", err)
	}

	q := url.Values{}
	q.Set("name", name)
	resp, err := c.do(ctx, "POST", "/containers/create?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("docker: create container %s: %s — %s", name, resp.Status, strings.TrimSpace(string(errBody)))
	}
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("docker: decode create response: %w", err)
	}
	return out.ID, nil
}

// expectNoBody wraps the common pattern of issuing a body-less POST/DELETE
// and asserting the response status is one of `expected`. The response body
// is drained and closed.
func (c *Client) expectNoBody(ctx context.Context, method, path string, expected ...int) error {
	resp, err := c.do(ctx, method, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for _, want := range expected {
		if resp.StatusCode == want {
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("docker: %s %s: %s — %s", method, path, resp.Status, strings.TrimSpace(string(body)))
}
