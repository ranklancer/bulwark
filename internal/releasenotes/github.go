package releasenotes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GitHubAPI is the GitHub REST API root. The hostname is overridable via
// BaseURL on a Client to point tests at an httptest server, or to support
// GitHub Enterprise.
const GitHubAPI = "https://api.github.com"

// release is the subset of the GitHub Releases response we care about.
type release struct {
	HTMLURL string    `json:"html_url"`
	TagName string    `json:"tag_name"`
	Body    string    `json:"body"`
	Draft   bool      `json:"draft"`
	Created time.Time `json:"created_at"`
}

// Notes is the resolved release notes for a particular tag.
type Notes struct {
	URL  string
	Body string
	Tag  string // the upstream tag that satisfied the lookup
}

// GitHubClient fetches release notes from GitHub Releases.
type GitHubClient struct {
	HTTPClient *http.Client
	BaseURL    string // overrides GitHubAPI when set; useful for tests / GHE
	UserAgent  string
	Token      string // optional GitHub PAT for higher rate limits
}

// NewGitHubClient returns a client with sensible defaults: 15s HTTP timeout,
// a "bulwark/<version>" User-Agent, and no auth token (anonymous, 60 req/hr).
func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		UserAgent:  "bulwark/dev",
	}
}

// FetchByTag attempts to retrieve a release for owner/repo at exactly the
// given tag. Returns (nil, nil) if no release exists for that tag (404),
// distinguishing "no notes" from a transport error.
func (c *GitHubClient) FetchByTag(ctx context.Context, owner, repo, tag string) (*Notes, error) {
	if owner == "" || repo == "" || tag == "" {
		return nil, errors.New("releasenotes: owner/repo/tag are required")
	}
	endpoint := c.base() + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/releases/tags/" + url.PathEscape(tag)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("releasenotes: GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, nil
	case http.StatusForbidden:
		// Most commonly: rate-limited. Surface a typed error so the caller can
		// decide whether to back off or proceed without notes.
		return nil, &RateLimitedError{Endpoint: endpoint, Status: resp.Status}
	default:
		return nil, fmt.Errorf("releasenotes: GET %s: %s", endpoint, resp.Status)
	}

	var rel release
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("releasenotes: read response: %w", err)
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("releasenotes: decode response: %w", err)
	}
	if rel.Draft {
		return nil, nil
	}
	return &Notes{URL: rel.HTMLURL, Body: rel.Body, Tag: rel.TagName}, nil
}

// FetchAny tries each tag candidate in order and returns the first hit.
// Returns (nil, nil) if none of the candidates resolve to a release.
func (c *GitHubClient) FetchAny(ctx context.Context, owner, repo string, tagCandidates []string) (*Notes, error) {
	var lastErr error
	for _, tag := range tagCandidates {
		notes, err := c.FetchByTag(ctx, owner, repo, tag)
		if err != nil {
			// If we hit a rate-limit, stop trying the other candidates — they
			// will fail too and waste API budget.
			var rl *RateLimitedError
			if errors.As(err, &rl) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if notes != nil {
			return notes, nil
		}
	}
	return nil, lastErr
}

func (c *GitHubClient) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return GitHubAPI
}

// RateLimitedError is returned when GitHub responds with 403, which most
// commonly indicates the anonymous rate-limit (60 req/hr) was exhausted.
type RateLimitedError struct {
	Endpoint string
	Status   string
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("releasenotes: rate-limited or forbidden: %s (endpoint=%s)", e.Status, e.Endpoint)
}
