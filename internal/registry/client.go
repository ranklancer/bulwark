package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Manifest media types accepted when resolving a tag. Listing all four covers
// both single-arch and multi-arch (index/list) manifests across the OCI and
// legacy Docker schemas.
var manifestAcceptHeader = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

// Client is a minimal OCI distribution client. It supports anonymous reads
// against any compliant registry and follows Bearer challenges for registries
// that require token exchange (Docker Hub, GHCR, Quay, LSCR).
type Client struct {
	HTTPClient *http.Client
	UserAgent  string

	// BaseURL overrides the registry's URL scheme/host when set. Used by tests
	// to point all requests at an httptest.Server. Production usage leaves
	// this unset, in which case the client speaks https://<reference.Registry>.
	BaseURL string

	// Auth, when set, supplies credentials for private registries. The
	// host argument passed to Auth.Lookup is the bare DNS name as it
	// appears in image references. Anonymous lookups continue to work
	// when Auth is nil or returns ok=false.
	Auth Authenticator

	tokensMu sync.Mutex
	tokens   map[string]string // key: host|scope
}

// New returns a Client with sensible defaults: 30s HTTP timeout and a
// "bulwark/<version>" User-Agent.
func New() *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		UserAgent:  "bulwark/dev",
		tokens:     make(map[string]string),
	}
}

// Resolve returns the manifest digest currently advertised for ref.Tag.
// The returned value is in the form "sha256:..." and is sourced from the
// Docker-Content-Digest response header, which every compliant registry sets.
func (c *Client) Resolve(ctx context.Context, ref Reference) (string, error) {
	if ref.Tag == "" && ref.Digest != "" {
		// Already pinned to a digest — nothing to resolve.
		if !IsSHA256Digest(strings.ToLower(strings.TrimSpace(ref.Digest))) {
			return "", fmt.Errorf("registry: pinned reference has a malformed digest %q", ref.Digest)
		}
		return ref.Digest, nil
	}
	if ref.Tag == "" {
		return "", errors.New("registry: Resolve requires either a tag or a digest")
	}
	endpoint := c.endpoint(ref.Registry, "/v2/"+ref.Repository+"/manifests/"+ref.Tag)
	resp, err := c.doManifest(ctx, "HEAD", endpoint, ref.Registry, ref.Repository)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry: HEAD %s: %s", endpoint, resp.Status)
	}
	digest := strings.ToLower(strings.TrimSpace(resp.Header.Get("Docker-Content-Digest")))
	if digest == "" {
		return "", fmt.Errorf("registry: response from %s missing Docker-Content-Digest header", endpoint)
	}
	if !IsSHA256Digest(digest) {
		return "", fmt.Errorf("registry: %s returned a malformed content digest %q", endpoint, digest)
	}
	return digest, nil
}

// Ping verifies that the registry's /v2/ root is reachable and responds in a
// way consistent with the OCI distribution spec. Useful as a smoke test from
// CLI / health checks.
func (c *Client) Ping(ctx context.Context, registry string) error {
	endpoint := c.endpoint(registry, "/v2/")
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("registry: ping %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	// 200 (no auth required) or 401 (auth required) both indicate a working
	// /v2/ endpoint per the spec. Anything else is a problem.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("registry: ping %s: %s", endpoint, resp.Status)
	}
	return nil
}

func (c *Client) endpoint(registry, path string) string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/") + path
	}
	return "https://" + registry + path
}

func (c *Client) doManifest(ctx context.Context, method, endpoint, registry, repository string) (*http.Response, error) {
	scope := "repository:" + repository + ":pull"

	build := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", manifestAcceptHeader)
		req.Header.Set("User-Agent", c.UserAgent)
		if tok := c.cachedToken(registry, scope); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		return req, nil
	}

	req, err := build()
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Got 401 — exchange a Bearer or Basic challenge for credentials and retry once.
	challenge := resp.Header.Get("WWW-Authenticate")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	scheme, params := parseChallenge(challenge)
	switch scheme {
	case "bearer":
		if params["realm"] == "" {
			return nil, fmt.Errorf("registry: Bearer challenge missing realm: %q", challenge)
		}
		if params["scope"] == "" {
			params["scope"] = scope
		}

		tok, err := c.fetchBearerToken(ctx, registry, params)
		if err != nil {
			return nil, err
		}
		c.cacheToken(registry, scope, tok)

		req2, err := build()
		if err != nil {
			return nil, err
		}
		req2.Header.Set("Authorization", "Bearer "+tok)
		return c.HTTPClient.Do(req2)

	case "basic":
		// Private registries protected by htpasswd / mod_auth_basic
		// reply with a Basic challenge directly. We retry once with
		// the credentials from the configured Authenticator. With no
		// Authenticator (or no creds for this host), we surface the
		// 401 as an explicit error rather than retrying anonymously
		// in a loop.
		creds, ok := c.lookupAuth(registry)
		if !ok || creds.Empty() {
			return nil, fmt.Errorf("registry: %s requires Basic auth but no credentials are configured", registry)
		}
		req2, err := build()
		if err != nil {
			return nil, err
		}
		req2.SetBasicAuth(creds.Username, creds.Password)
		return c.HTTPClient.Do(req2)

	default:
		return nil, fmt.Errorf("registry: 401 with unsupported challenge %q", challenge)
	}
}

// lookupAuth is a nil-safe wrapper around c.Auth.Lookup so the call
// sites stay readable.
func (c *Client) lookupAuth(host string) (Credentials, bool) {
	if c.Auth == nil {
		return Credentials{}, false
	}
	return c.Auth.Lookup(host)
}

func (c *Client) cachedToken(registry, scope string) string {
	c.tokensMu.Lock()
	defer c.tokensMu.Unlock()
	return c.tokens[registry+"|"+scope]
}

func (c *Client) cacheToken(registry, scope, tok string) {
	c.tokensMu.Lock()
	defer c.tokensMu.Unlock()
	c.tokens[registry+"|"+scope] = tok
}

// fetchBearerToken exchanges a WWW-Authenticate challenge for a token by
// performing a GET against the realm with service+scope as query params.
// When credentials are configured for the registry host, they are sent
// as Basic auth on the token request — that's the standard flow for
// authenticated pulls from private GHCR images, Docker Hub PATs, etc.
func (c *Client) fetchBearerToken(ctx context.Context, host string, params map[string]string) (string, error) {
	u, err := url.Parse(params["realm"])
	if err != nil {
		return "", fmt.Errorf("registry: parse realm: %w", err)
	}
	q := u.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	if s := params["scope"]; s != "" {
		q.Set("scope", s)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if creds, ok := c.lookupAuth(host); ok {
		switch {
		case creds.IdentityToken != "":
			// OAuth2 refresh-token flow: registries (notably GHCR)
			// accept the token via the password slot of HTTP Basic
			// when the username is meaningless.
			req.SetBasicAuth("<token>", creds.IdentityToken)
		case creds.Username != "" || creds.Password != "":
			req.SetBasicAuth(creds.Username, creds.Password)
		}
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry: token request: %s", resp.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("registry: decode token response: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("registry: token response had neither `token` nor `access_token`")
}

// parseChallenge extracts the scheme and params from a WWW-Authenticate header
// value. It only handles the simple "Bearer k=v,k=\"v\"" form used by
// registries — not the full RFC 7235 grammar.
func parseChallenge(header string) (scheme string, params map[string]string) {
	params = make(map[string]string)
	header = strings.TrimSpace(header)
	if header == "" {
		return "", params
	}
	sp := strings.IndexByte(header, ' ')
	if sp < 0 {
		return strings.ToLower(header), params
	}
	scheme = strings.ToLower(header[:sp])
	rest := strings.TrimSpace(header[sp+1:])

	for rest != "" {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimSpace(rest[eq+1:])

		var val string
		if strings.HasPrefix(rest, `"`) {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				break
			}
			val = rest[1 : 1+end]
			rest = rest[1+end+1:]
		} else if comma := strings.IndexByte(rest, ','); comma < 0 {
			val = strings.TrimSpace(rest)
			rest = ""
		} else {
			val = strings.TrimSpace(rest[:comma])
			rest = rest[comma:]
		}
		params[key] = val
		rest = strings.TrimLeft(rest, ", \t")
	}
	return scheme, params
}
