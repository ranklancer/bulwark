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
	"strings"
	"time"
)

// KomodoSource is the API/DB-managed adapter for Komodo. Komodo keeps each Stack
// in its own database (UI-defined stacks store the compose text in the DB), or in
// a git repo (resource-sync / repo-backed stacks), or as files on the managed
// server. Bulwark pins Komodo stacks THROUGH THE KOMODO API and NEVER edits files
// on disk; Kind() is KindManaged so the core enforces that split.
//
// Only UI-defined stacks (compose text in the DB) are pinnable. Repo-backed
// stacks (source of truth = git) and files-on-server stacks are REFUSED — bulwark
// reports them and pins nothing, rather than fighting the real source of truth.
type KomodoSource struct {
	API KomodoAPI
}

// Kind reports Komodo as an API/DB-managed backend.
func (s *KomodoSource) Kind() SourceKind { return KindManaged }

// Discover lists the stacks Komodo manages, one Target per stack (Path = stack id).
func (s *KomodoSource) Discover(ctx context.Context) ([]Target, error) {
	stacks, err := s.API.ListStacks(ctx)
	if err != nil {
		return nil, err
	}
	var targets []Target
	for _, st := range stacks {
		id := st.ID
		if strings.TrimSpace(id) == "" {
			id = st.Name
		}
		targets = append(targets, Target{Name: st.Name, Path: id, Kind: KindManaged})
	}
	return targets, nil
}

// LocateImageRefs fetches the stack's compose text (file_contents) from Komodo and
// extracts its image references (shared parser). Repo-backed / files-on-server
// stacks have no DB file_contents, so they naturally yield no pinnable refs.
func (s *KomodoSource) LocateImageRefs(ctx context.Context, t Target) ([]ImageRef, error) {
	st, err := s.API.GetStack(ctx, t.Path)
	if err != nil {
		return nil, err
	}
	return imageRefsFromComposeBytes([]byte(st.FileContents), nil)
}

// ProposePin computes the pin edit without applying it (shared, adapter-agnostic).
func (s *KomodoSource) ProposePin(_ context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error) {
	return computePinProposal(t, ref, pin)
}

// WritePin applies a proposal through the Komodo API: re-fetch the stack (freshness
// + source check), splice the digest into the current file_contents (fail-closed
// on drift), and push it back via a PARTIAL UpdateStack (only file_contents), which
// preserves the stack's environment and other config. Repo-backed and
// files-on-server stacks are refused.
func (s *KomodoSource) WritePin(ctx context.Context, p Proposal) (Applied, error) {
	res := Applied{Path: p.Path, Line: p.Line, OldValue: p.OldValue, NewValue: p.NewValue}
	if p.NoOp {
		res.NoOp = true
		return res, nil
	}
	st, err := s.API.GetStack(ctx, p.Path)
	if err != nil {
		return res, err
	}
	if st.Git {
		return res, fmt.Errorf("komodo: stack %q is repo/resource-sync-backed; pin it in its git source, not via the API — refusing to overwrite git-tracked content", st.Name)
	}
	if st.FilesOnHost {
		return res, fmt.Errorf("komodo: stack %q is files-on-server; its compose lives on the managed host, not the Komodo DB — pin it there (file adapter), refusing an API write", st.Name)
	}
	// Defensive (no live Komodo to integration-test): a UI-defined stack must have
	// non-empty file_contents. An empty value means the stack is not DB-defined (or
	// the response shape is unexpected); refuse rather than push an empty compose.
	if strings.TrimSpace(st.FileContents) == "" {
		return res, fmt.Errorf("komodo: stack %q has empty file_contents; refusing to update (not a UI-defined stack, or unexpected API shape) — confirm the contract with a live smoke test", st.Name)
	}
	newContent, noOp, err := spliceImageValue(st.FileContents, p.Line, p.OldValue, p.NewValue)
	if err != nil {
		return res, fmt.Errorf("komodo: stack %q: %w", st.Name, err)
	}
	if noOp {
		res.NoOp = true
		return res, nil
	}
	if err := s.API.UpdateStackFileContents(ctx, st.ID, newContent); err != nil {
		return res, err
	}
	return res, nil
}

// KomodoStack is the subset of a Komodo stack the adapter needs.
type KomodoStack struct {
	ID           string
	Name         string
	FileContents string
	Git          bool // repo / resource-sync backed (source of truth = git)
	FilesOnHost  bool // compose lives on the managed server's filesystem
}

// KomodoAPI is the minimal Komodo API surface the adapter uses.
type KomodoAPI interface {
	ListStacks(ctx context.Context) ([]KomodoStack, error)
	GetStack(ctx context.Context, idOrName string) (KomodoStack, error)
	UpdateStackFileContents(ctx context.Context, id, content string) error
}

// KomodoConfig configures the concrete HTTP client. Komodo authenticates with an
// API key + secret pair (X-Api-Key / X-Api-Secret).
type KomodoConfig struct {
	BaseURL            string // e.g. https://komodo.example:9120
	APIKey             string // X-Api-Key; never logged
	APISecret          string // X-Api-Secret; never logged
	CAFile             string
	InsecureSkipVerify bool
	AllowInsecureHTTP  bool
	HTTPClient         *http.Client
	Logger             *slog.Logger
}

type httpKomodoClient struct {
	base      string
	apiKey    string
	apiSecret string
	hc        *http.Client
}

const komodoBodyCap = 8 << 20 // 8 MiB

// NewKomodoClient validates the config and builds an HTTP Komodo client, reusing
// the shared managed-backend TLS / cleartext / redirect / SSRF hardening.
func NewKomodoClient(cfg KomodoConfig) (KomodoAPI, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("komodo: base url is required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("komodo: url is malformed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("komodo: url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("komodo: url must include a host")
	}
	if strings.TrimSpace(cfg.APIKey) == "" || strings.TrimSpace(cfg.APISecret) == "" {
		return nil, errors.New("komodo: api key and secret are required (configure a creds_ref; never inline the secret)")
	}
	if err := checkCleartextBase("komodo", u, cfg.AllowInsecureHTTP, cfg.Logger); err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tlsCfg, err := managedTLSConfig("komodo", cfg.InsecureSkipVerify, cfg.CAFile, cfg.Logger)
		if err != nil {
			return nil, err
		}
		hc = &http.Client{
			Timeout:       30 * time.Second,
			Transport:     guardedTransport(tlsCfg),
			CheckRedirect: refuseCrossHostRedirect,
		}
	}
	return &httpKomodoClient{base: base, apiKey: cfg.APIKey, apiSecret: cfg.APISecret, hc: hc}, nil
}

func (c *httpKomodoClient) ListStacks(ctx context.Context) ([]KomodoStack, error) {
	var raw []komodoStackJSON
	if err := c.call(ctx, "/read", "ListStacks", map[string]any{}, &raw); err != nil {
		return nil, err
	}
	out := make([]KomodoStack, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.toStack())
	}
	return out, nil
}

func (c *httpKomodoClient) GetStack(ctx context.Context, idOrName string) (KomodoStack, error) {
	var r komodoStackJSON
	if err := c.call(ctx, "/read", "GetStack", map[string]any{"stack": idOrName}, &r); err != nil {
		return KomodoStack{}, err
	}
	return r.toStack(), nil
}

func (c *httpKomodoClient) UpdateStackFileContents(ctx context.Context, id, content string) error {
	params := map[string]any{
		"id":     id,
		"config": map[string]any{"file_contents": content},
	}
	return c.call(ctx, "/write", "UpdateStack", params, nil)
}

// komodoStackJSON mirrors the Komodo stack JSON we consume. config is a pointer so
// list items (which omit it) and full stacks are both handled.
type komodoStackJSON struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Config *struct {
		FileContents string `json:"file_contents"`
		Repo         string `json:"repo"`
		LinkedRepo   string `json:"linked_repo"`
		FilesOnHost  bool   `json:"files_on_host"`
	} `json:"config"`
}

func (r komodoStackJSON) toStack() KomodoStack {
	st := KomodoStack{ID: r.ID, Name: r.Name}
	if r.Config != nil {
		st.FileContents = r.Config.FileContents
		st.Git = strings.TrimSpace(r.Config.Repo) != "" || strings.TrimSpace(r.Config.LinkedRepo) != ""
		st.FilesOnHost = r.Config.FilesOnHost
	}
	return st
}

// call issues an authenticated Komodo typed request (POST {type,params}) and
// decodes a 2xx JSON response into out (nil out = discard). Credentials are never
// included in errors.
func (c *httpKomodoClient) call(ctx context.Context, endpoint, reqType string, params, out any) error {
	body, err := json.Marshal(map[string]any{"type": reqType, "params": params})
	if err != nil {
		return fmt.Errorf("komodo: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("komodo: build request: %w", err)
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("X-Api-Secret", c.apiSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("komodo: %s %s: %w", reqType, endpoint, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, komodoBodyCap))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("komodo: %s %s: %s", reqType, endpoint, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("komodo: decode %s response: %w", reqType, err)
	}
	return nil
}
