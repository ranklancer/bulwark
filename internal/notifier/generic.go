package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// GenericNotifier delivers events to an arbitrary HTTP endpoint as a flat
// JSON array. Useful for Home Assistant REST sensors, n8n workflow triggers,
// IFTTT-style services, and ad-hoc internal dashboards.
//
// Authentication is provided by an optional set of headers (typically
// "Authorization: Bearer <token>" for HA, "X-API-Key: ..." for custom apps).
// The headers are sent verbatim — secrets stored there must come from
// environment-variable substitution at config-load time.
type GenericNotifier struct {
	HTTPClient  *http.Client
	URL         string
	Method      string // defaults to POST
	Headers     map[string]string
	Min         types.RiskLevel
	channelName string
}

// NewGeneric constructs a GenericNotifier. url is required.
func NewGeneric(url, method string, headers map[string]string, min types.RiskLevel, name string) (*GenericNotifier, error) {
	if url == "" {
		return nil, fmt.Errorf("generic: %w", ErrEmptyURL)
	}
	if name == "" {
		name = "generic"
	}
	if method == "" {
		method = "POST"
	}
	if min == types.RiskUnknown {
		min = types.RiskReview
	}
	// Defensive copy so subsequent mutations to the caller's map don't leak
	// into our headers.
	hcopy := make(map[string]string, len(headers))
	for k, v := range headers {
		hcopy[k] = v
	}
	return &GenericNotifier{
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
		URL:         url,
		Method:      method,
		Headers:     hcopy,
		Min:         min,
		channelName: name,
	}, nil
}

func (g *GenericNotifier) Name() string              { return g.channelName }
func (g *GenericNotifier) MinLevel() types.RiskLevel { return g.Min }

// genericEvent is the wire shape — explicitly named fields so JSON consumers
// don't depend on Event's internal naming. Empty fields are omitted to keep
// payloads small and grep-friendly.
type genericEvent struct {
	Container      string `json:"container,omitempty"`
	Image          string `json:"image,omitempty"`
	ComposeProject string `json:"compose_project,omitempty"`
	Risk           string `json:"risk"`
	Action         string `json:"action,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Confidence     string `json:"confidence,omitempty"`
	Rationale      string `json:"rationale,omitempty"`
	ReleaseURL     string `json:"release_url,omitempty"`
	Changelog      string `json:"changelog,omitempty"`
	NotesSource    string `json:"notes_source,omitempty"`
	LocalDigest    string `json:"local_digest,omitempty"`
	RegistryDigest string `json:"registry_digest,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	Synthetic      bool   `json:"synthetic,omitempty"`
}

// Notify sends events as a single JSON-array body. Most receivers want a
// batched payload; one-event-per-call is achievable by sending one at a
// time (callers that need this can issue multiple Notify calls).
func (g *GenericNotifier) Notify(ctx context.Context, events []Event) error {
	wire := make([]genericEvent, 0, len(events))
	for _, e := range events {
		wire = append(wire, genericEvent{
			Container:      e.Container,
			Image:          e.Image,
			ComposeProject: e.ComposeProject,
			Risk:           e.Risk.String(),
			Action:         e.Action.String(),
			From:           e.From,
			To:             e.To,
			Kind:           e.Kind.String(),
			Confidence:     e.Confidence.String(),
			Rationale:      e.Rationale,
			ReleaseURL:     e.ReleaseURL,
			Changelog:      e.Changelog,
			NotesSource:    e.NotesSource,
			LocalDigest:    e.LocalDigest,
			RegistryDigest: e.RegistryDigest,
			Timestamp:      eventTimestamp(e),
			Synthetic:      e.Synthetic,
		})
	}
	body, err := json.Marshal(map[string]any{"events": wire, "source": "bulwark"})
	if err != nil {
		return fmt.Errorf("generic: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, g.Method, g.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("generic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range g.Headers {
		req.Header.Set(k, v)
	}
	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("generic: %s %s failed: %w", g.Method, "<endpoint>", scrubURL(err, g.URL))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet := readSnippet(resp.Body, 256)
		return fmt.Errorf("generic: webhook returned %s: %s", resp.Status, snippet)
	}
	return nil
}

func eventTimestamp(e Event) string {
	if e.Timestamp.IsZero() {
		return ""
	}
	return e.Timestamp.UTC().Format(time.RFC3339)
}
