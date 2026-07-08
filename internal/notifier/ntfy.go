package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// NtfyNotifier delivers events to an ntfy server using its JSON publish
// API. Self-hosted ntfy is common in homelabs; ntfy.sh is the hosted
// fallback. Both speak the same HTTP shape.
//
// Threat model: the access token (when present) is the only secret —
// treat it as bearer-equivalent. The server URL itself isn't a secret
// but we scrub it from error messages anyway because operators often
// embed it in private topic paths.
//
// Bulwark risk levels map to ntfy priorities + tags as a fixed
// per-event policy (the package-private ntfyPriorityFor / ntfyTagsFor
// helpers). Per-operator priority overrides are deliberately deferred
// to a follow-up — the hardcoded mapping is conservative enough that
// most operators won't want to tune it.
type NtfyNotifier struct {
	HTTPClient  *http.Client
	ServerURL   string
	Topic       string
	Token       string
	Min         types.RiskLevel
	channelName string
}

// NewNtfy constructs an NtfyNotifier. serverURL and topic are required;
// token is optional (public topics work without auth). Validation:
//
//   - serverURL must parse with http or https scheme and a non-empty
//     host. Trailing slash is normalised away.
//   - topic must be non-empty and contain no slashes (ntfy topic names
//     are bare strings; subpath addressing isn't a real thing).
func NewNtfy(serverURL, topic, token string, min types.RiskLevel, name string) (*NtfyNotifier, error) {
	if serverURL == "" {
		return nil, fmt.Errorf("ntfy: %w", ErrEmptyURL)
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("ntfy: server_url is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("ntfy: server_url scheme must be http or https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("ntfy: server_url must include a host")
	}
	if strings.TrimSpace(topic) == "" {
		return nil, fmt.Errorf("ntfy: topic is required")
	}
	if strings.ContainsAny(topic, "/ \t") {
		return nil, fmt.Errorf("ntfy: topic %q must not contain slashes or whitespace", topic)
	}
	if name == "" {
		name = "ntfy"
	}
	if min == types.RiskUnknown {
		min = types.RiskReview
	}
	return &NtfyNotifier{
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
		ServerURL:   strings.TrimRight(serverURL, "/"),
		Topic:       topic,
		Token:       token,
		Min:         min,
		channelName: name,
	}, nil
}

func (n *NtfyNotifier) Name() string              { return n.channelName }
func (n *NtfyNotifier) MinLevel() types.RiskLevel { return n.Min }

// Notify POSTs each event as a JSON message to ntfy's publish endpoint
// at <serverURL>/. The JSON API takes one message per call; we
// iterate over the batch so each notification keeps its own title,
// priority, and click action. A single failing event aborts the
// batch — the dispatcher logs the partial outcome.
func (n *NtfyNotifier) Notify(ctx context.Context, events []Event) error {
	for _, e := range events {
		if err := n.sendOne(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// ntfyMessage is the JSON payload shape documented at
// https://docs.ntfy.sh/publish/#publish-as-json. Only the fields
// Bulwark populates are listed.
type ntfyMessage struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title,omitempty"`
	Message  string   `json:"message"`
	Priority int      `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Click    string   `json:"click,omitempty"`
}

func (n *NtfyNotifier) sendOne(ctx context.Context, e Event) error {
	payload := ntfyMessage{
		Topic:    n.Topic,
		Title:    titleFor(e),
		Message:  ntfyBodyFor(e),
		Priority: ntfyPriorityFor(e),
		Tags:     ntfyTagsFor(e),
		Click:    e.ReleaseURL,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ntfy: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", n.ServerURL+"/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ntfy: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: publish failed: %w", scrubURL(err, n.ServerURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet := readSnippet(resp.Body, 256)
		return fmt.Errorf("ntfy: server returned %s: %s", resp.Status, snippet)
	}
	return nil
}

// ntfyBodyFor builds the message body. We keep it terse — title
// carries the headline already, so the body adds version + rationale
// for context without overwhelming a phone-pop notification.
func ntfyBodyFor(e Event) string {
	var b strings.Builder
	b.WriteString(nonempty(e.Image, "(unknown image)"))
	if e.From != "" || e.To != "" {
		fmt.Fprintf(&b, "\n%s → %s", nonempty(e.From, "?"), nonempty(e.To, "?"))
	}
	if e.ComposeProject != "" {
		fmt.Fprintf(&b, "\nstack: %s", e.ComposeProject)
	}
	if e.Rationale != "" {
		b.WriteString("\n\n")
		b.WriteString(e.Rationale)
	}
	return b.String()
}

// ntfyPriorityFor maps a Bulwark event onto an ntfy priority value
// (1=min, 3=default, 5=max). Action takes precedence over risk so a
// post-failure rollback fires at max even when the original level
// was REVIEW.
func ntfyPriorityFor(e Event) int {
	switch e.Action {
	case types.ActionRolledBack, types.ActionBlocked:
		return 5
	case types.ActionStackSkipped, types.ActionNeedsReview:
		return 4
	}
	switch e.Risk {
	case types.RiskBreaking:
		return 5
	case types.RiskReview:
		return 4
	case types.RiskSafe:
		return 3
	}
	return 3
}

// ntfyTagsFor returns ntfy emoji tags that prefix the title in
// recipients' notification UIs. We pick one tag per event so the
// notification stays visually distinct without being noisy.
func ntfyTagsFor(e Event) []string {
	if e.Synthetic {
		return []string{"test_tube"}
	}
	switch e.Action {
	case types.ActionRolledBack:
		return []string{"rotating_light"}
	case types.ActionStackSkipped:
		return []string{"warning"}
	case types.ActionBlocked:
		return []string{"rotating_light"}
	}
	switch e.Risk {
	case types.RiskBreaking:
		return []string{"rotating_light"}
	case types.RiskReview:
		return []string{"warning"}
	case types.RiskSafe:
		return []string{"package"}
	}
	return nil
}
