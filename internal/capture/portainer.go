package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PortainerSource is the API/DB-managed adapter for Portainer. Portainer keeps
// its stacks in its own database (and, for git-backed stacks, in a git repo), so
// bulwark pins them through the Portainer API — it NEVER edits files on disk.
// Kind() is KindManaged, which the capture core uses to enforce that split.
//
// A verified pin is applied by fetching the stack's current compose text,
// splicing the digest into the target image line (with the same fail-closed,
// drift-checked splice the file adapters use), and pushing the new content back
// via the API, which redeploys the stack. Git-backed stacks are refused: their
// source of truth is the git repo, and overwriting via the API would fight it —
// bulwark reports them instead of blind-writing.
type PortainerSource struct {
	// API is the Portainer client. An interface so tests inject a fake without a
	// live Portainer, and so the concrete HTTP client is swappable.
	API PortainerAPI
	// EndpointID, when non-zero, restricts discovery to a single Portainer
	// environment (endpoint). Zero means all endpoints.
	EndpointID int
}

// Kind reports Portainer as an API/DB-managed backend (pinned via the API).
func (s *PortainerSource) Kind() SourceKind { return KindManaged }

// Discover lists the stacks Portainer manages (optionally filtered to one
// endpoint), one Target per stack. Target.Path carries the numeric stack id.
func (s *PortainerSource) Discover(ctx context.Context) ([]Target, error) {
	stacks, err := s.API.ListStacks(ctx)
	if err != nil {
		return nil, err
	}
	var targets []Target
	for _, st := range stacks {
		if s.EndpointID != 0 && st.EndpointID != s.EndpointID {
			continue
		}
		targets = append(targets, Target{Name: st.Name, Path: strconv.Itoa(st.ID), Kind: KindManaged})
	}
	return targets, nil
}

// LocateImageRefs fetches the stack's compose text from Portainer and extracts
// its image references (shared parser). No .env is applied here — Portainer
// resolves stack environment at deploy time.
func (s *PortainerSource) LocateImageRefs(ctx context.Context, t Target) ([]ImageRef, error) {
	id, err := strconv.Atoi(strings.TrimSpace(t.Path))
	if err != nil {
		return nil, fmt.Errorf("portainer: invalid stack id %q: %w", t.Path, err)
	}
	content, err := s.API.StackFile(ctx, id)
	if err != nil {
		return nil, err
	}
	return imageRefsFromComposeBytes([]byte(content), nil)
}

// ProposePin computes the pin edit without applying it (shared, adapter-agnostic).
func (s *PortainerSource) ProposePin(_ context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error) {
	return computePinProposal(t, ref, pin)
}

// WritePin applies a proposal through the Portainer API: it re-fetches the stack
// (freshness + git check), splices the digest into the current compose text
// (fail-closed on drift), and pushes it back. Git-backed stacks are refused.
func (s *PortainerSource) WritePin(ctx context.Context, p Proposal) (Applied, error) {
	res := Applied{Path: p.Path, Line: p.Line, OldValue: p.OldValue, NewValue: p.NewValue}
	if p.NoOp {
		res.NoOp = true
		return res, nil
	}
	id, err := strconv.Atoi(strings.TrimSpace(p.Path))
	if err != nil {
		return res, fmt.Errorf("portainer: invalid stack id %q: %w", p.Path, err)
	}
	st, err := s.API.Stack(ctx, id)
	if err != nil {
		return res, err
	}
	if st.Git {
		return res, fmt.Errorf("portainer: stack %q (id %d) is git-managed; pin it in its git source, not via the API — refusing to overwrite git-tracked content", st.Name, id)
	}
	// Defensive contract check (the adapter is built to the documented API but
	// not yet integration-tested live): a well-formed Portainer stack returns its
	// Env array (empty [] is fine; nil means the response shape is not what we
	// expect). Pushing a nil Env back could clear the stack environment on
	// redeploy — refuse until a live smoke test confirms the contract.
	if st.Env == nil {
		return res, fmt.Errorf("portainer: stack %q (id %d) returned no Env field; refusing to update (would risk clearing the stack environment) — confirm the API contract with a live smoke test", st.Name, id)
	}
	content, err := s.API.StackFile(ctx, id)
	if err != nil {
		return res, err
	}
	newContent, noOp, err := spliceImageValue(content, p.Line, p.OldValue, p.NewValue)
	if err != nil {
		return res, fmt.Errorf("portainer: stack %d: %w", id, err)
	}
	if noOp {
		res.NoOp = true
		return res, nil
	}
	if err := s.API.UpdateStackFile(ctx, st, newContent); err != nil {
		return res, err
	}
	return res, nil
}

// PortainerStack is the subset of a Portainer stack the adapter needs.
type PortainerStack struct {
	ID         int
	Name       string
	EndpointID int
	Type       int // 1 = swarm, 2 = compose (standalone)
	Git        bool
	Env        []PortainerEnvVar
}

// PortainerEnvVar is a stack environment variable, preserved verbatim on update.
type PortainerEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PortainerAPI is the minimal Portainer API surface the adapter uses. Kept as an
// interface so the Source is unit-testable with a fake and the transport is
// swappable.
type PortainerAPI interface {
	ListStacks(ctx context.Context) ([]PortainerStack, error)
	Stack(ctx context.Context, id int) (PortainerStack, error)
	StackFile(ctx context.Context, id int) (string, error)
	UpdateStackFile(ctx context.Context, st PortainerStack, content string) error
}

// PortainerConfig configures the concrete HTTP client.
type PortainerConfig struct {
	BaseURL            string // e.g. https://portainer.example:9443
	APIKey             string // sent as X-API-Key; never logged
	CAFile             string // optional PEM bundle to trust a private issuing CA
	InsecureSkipVerify bool   // explicit opt-in; logs a warning. Prefer CAFile
	AllowInsecureHTTP  bool   // opt-in to a cleartext http:// base to a non-loopback host
	HTTPClient         *http.Client
	Logger             *slog.Logger
}

// httpPortainerClient talks to a real Portainer instance.
type httpPortainerClient struct {
	base   string
	apiKey string
	hc     *http.Client
}

const portainerBodyCap = 8 << 20 // 8 MiB: stack files are small; cap to stay safe

// NewPortainerClient validates the config and builds an HTTP Portainer client.
func NewPortainerClient(cfg PortainerConfig) (PortainerAPI, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("portainer: base url is required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("portainer: url is malformed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("portainer: url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("portainer: url must include a host")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("portainer: api key is required (configure a creds_ref; never inline the secret)")
	}
	if err := checkCleartextBase("portainer", u, cfg.AllowInsecureHTTP, cfg.Logger); err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tlsCfg, err := managedTLSConfig("portainer", cfg.InsecureSkipVerify, cfg.CAFile, cfg.Logger)
		if err != nil {
			return nil, err
		}
		hc = &http.Client{
			Timeout:       30 * time.Second,
			Transport:     guardedTransport(tlsCfg),
			CheckRedirect: refuseCrossHostRedirect,
		}
	}
	return &httpPortainerClient{base: base, apiKey: cfg.APIKey, hc: hc}, nil
}

func (c *httpPortainerClient) ListStacks(ctx context.Context) ([]PortainerStack, error) {
	var raw []portainerStackJSON
	if err := c.do(ctx, http.MethodGet, "/api/stacks", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]PortainerStack, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.toStack())
	}
	return out, nil
}

func (c *httpPortainerClient) Stack(ctx context.Context, id int) (PortainerStack, error) {
	var r portainerStackJSON
	if err := c.do(ctx, http.MethodGet, "/api/stacks/"+strconv.Itoa(id), nil, &r); err != nil {
		return PortainerStack{}, err
	}
	return r.toStack(), nil
}

func (c *httpPortainerClient) StackFile(ctx context.Context, id int) (string, error) {
	var r struct {
		StackFileContent string `json:"StackFileContent"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/stacks/"+strconv.Itoa(id)+"/file", nil, &r); err != nil {
		return "", err
	}
	return r.StackFileContent, nil
}

func (c *httpPortainerClient) UpdateStackFile(ctx context.Context, st PortainerStack, content string) error {
	body := map[string]any{
		"stackFileContent": content,
		"env":              st.Env,
		"prune":            false,
	}
	path := "/api/stacks/" + strconv.Itoa(st.ID)
	if st.EndpointID != 0 {
		path += "?endpointId=" + strconv.Itoa(st.EndpointID)
	}
	return c.do(ctx, http.MethodPut, path, body, nil)
}

// portainerStackJSON mirrors the Portainer stack JSON we consume. GitConfig is a
// pointer so we can detect a git-backed stack (source of truth = git).
type portainerStackJSON struct {
	ID         int               `json:"Id"`
	Name       string            `json:"Name"`
	EndpointID int               `json:"EndpointId"`
	Type       int               `json:"Type"`
	GitConfig  *json.RawMessage  `json:"GitConfig"`
	Env        []PortainerEnvVar `json:"Env"`
}

func (r portainerStackJSON) toStack() PortainerStack {
	return PortainerStack{
		ID: r.ID, Name: r.Name, EndpointID: r.EndpointID, Type: r.Type,
		Git: gitConfigHasRepo(r.GitConfig), Env: r.Env,
	}
}

// gitConfigHasRepo reports whether a stack is git-managed using a POSITIVE
// signal: a GitConfig carrying a repository URL. A present-but-unparseable
// GitConfig is treated as git-managed (fail-closed: never overwrite something
// that might be git-tracked). A nil GitConfig is not git-managed.
func gitConfigHasRepo(raw *json.RawMessage) bool {
	if raw == nil {
		return false
	}
	var g struct {
		URL string `json:"URL"`
	}
	if err := json.Unmarshal(*raw, &g); err != nil {
		return true // present but unparseable -> fail closed (treat as git)
	}
	return strings.TrimSpace(g.URL) != ""
}

// do issues an authenticated request and decodes a 2xx JSON response into out
// (nil out = discard body). The API key is never included in errors.
func (c *httpPortainerClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("portainer: encode request: %w", err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return fmt.Errorf("portainer: build request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("portainer: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, portainerBodyCap))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("portainer: %s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("portainer: decode %s response: %w", path, err)
	}
	return nil
}
