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

// TeamsNotifier delivers events to a Microsoft Teams Incoming Webhook
// using the Adaptive Card v1.4 payload format. Each Notify call sends one
// HTTP POST containing every event in the batch as separate cards (Teams
// renders multiple cards in a single attachment array nicely).
//
// Threat model is the same as Slack/Discord: the webhook URL is the only
// secret; treat it as bearer-equivalent. Error messages scrub the URL
// before logging.
type TeamsNotifier struct {
	HTTPClient  *http.Client
	WebhookURL  string
	Min         types.RiskLevel
	channelName string
}

// NewTeams constructs a TeamsNotifier. webhookURL is required.
func NewTeams(webhookURL string, min types.RiskLevel, name string) (*TeamsNotifier, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("teams: %w", ErrEmptyURL)
	}
	if name == "" {
		name = "teams"
	}
	if min == types.RiskUnknown {
		min = types.RiskReview
	}
	return &TeamsNotifier{
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
		WebhookURL:  webhookURL,
		Min:         min,
		channelName: name,
	}, nil
}

func (t *TeamsNotifier) Name() string              { return t.channelName }
func (t *TeamsNotifier) MinLevel() types.RiskLevel { return t.Min }

// Notify renders every event as its own Adaptive Card attachment and
// POSTs them in a single message. Teams Incoming Webhooks accept up to
// ~25 KB per request; cards are bounded by Bulwark's batch size so this
// is comfortable in practice.
func (t *TeamsNotifier) Notify(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	attachments := make([]map[string]any, 0, len(events))
	for _, e := range events {
		attachments = append(attachments, teamsAttachment(e))
	}
	payload := map[string]any{
		"type":        "message",
		"attachments": attachments,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("teams: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", t.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("teams: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("teams: webhook POST failed: %w", scrubURL(err, t.WebhookURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet := readSnippet(resp.Body, 256)
		return fmt.Errorf("teams: webhook returned %s: %s", resp.Status, snippet)
	}
	return nil
}

func teamsAttachment(e Event) map[string]any {
	facts := []map[string]any{
		{"title": "Image", "value": nonempty(e.Image, "(unknown)")},
	}
	if e.From != "" || e.To != "" {
		facts = append(facts, map[string]any{
			"title": "Version",
			"value": fmt.Sprintf("%s → %s", nonempty(e.From, "?"), nonempty(e.To, "?")),
		})
	}
	facts = append(facts, map[string]any{
		"title": "Risk",
		"value": fmt.Sprintf("%s (%s)", e.Risk, e.Kind),
	})
	if e.ComposeProject != "" {
		facts = append(facts, map[string]any{"title": "Stack", "value": e.ComposeProject})
	}
	body := []map[string]any{
		{
			"type":   "TextBlock",
			"size":   "Medium",
			"weight": "Bolder",
			"text":   titleFor(e),
			"color":  teamsColor(e.Risk),
			"wrap":   true,
		},
		{
			"type":  "FactSet",
			"facts": facts,
		},
	}
	if e.Rationale != "" {
		body = append(body, map[string]any{
			"type": "TextBlock",
			"text": e.Rationale,
			"wrap": true,
		})
	}
	actions := []map[string]any{}
	if e.ReleaseURL != "" {
		actions = append(actions, map[string]any{
			"type":  "Action.OpenUrl",
			"title": "Release notes",
			"url":   e.ReleaseURL,
		})
	}
	card := map[string]any{
		"type":    "AdaptiveCard",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"version": "1.4",
		"body":    body,
	}
	if len(actions) > 0 {
		card["actions"] = actions
	}
	return map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"content":     card,
	}
}

// teamsColor maps a risk level to one of the Adaptive Card colour tokens.
// Teams only supports a small fixed palette (default/dark/light/accent/
// good/warning/attention); we map roughly to the same intent as Discord's
// numeric embed colours.
func teamsColor(r types.RiskLevel) string {
	switch r {
	case types.RiskBreaking:
		return "attention"
	case types.RiskReview:
		return "warning"
	case types.RiskSafe:
		return "good"
	default:
		return "default"
	}
}
