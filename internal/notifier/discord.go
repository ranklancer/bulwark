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

// Discord embed colour values (decimal RGB).
const (
	colorBreaking = 0xE74C3C // red
	colorReview   = 0xF1C40F // yellow
	colorSafe     = 0x2ECC71 // green
	colorUnknown  = 0x95A5A6 // grey
)

// DiscordNotifier delivers events to a Discord channel webhook using rich
// embeds. Discord allows up to 10 embeds per message, so we batch up to 10
// events per HTTP call.
type DiscordNotifier struct {
	HTTPClient  *http.Client
	WebhookURL  string
	Min         types.RiskLevel
	channelName string
}

// NewDiscord constructs a DiscordNotifier. webhookURL is required.
func NewDiscord(webhookURL string, min types.RiskLevel, name string) (*DiscordNotifier, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("discord: %w", ErrEmptyURL)
	}
	if name == "" {
		name = "discord"
	}
	if min == types.RiskUnknown {
		min = types.RiskReview
	}
	return &DiscordNotifier{
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
		WebhookURL:  webhookURL,
		Min:         min,
		channelName: name,
	}, nil
}

func (d *DiscordNotifier) Name() string             { return d.channelName }
func (d *DiscordNotifier) MinLevel() types.RiskLevel { return d.Min }

// Notify sends events as Discord embeds. Up to 10 embeds per message; we
// chunk if a batch exceeds that.
func (d *DiscordNotifier) Notify(ctx context.Context, events []Event) error {
	const maxEmbedsPerMessage = 10
	for i := 0; i < len(events); i += maxEmbedsPerMessage {
		end := i + maxEmbedsPerMessage
		if end > len(events) {
			end = len(events)
		}
		if err := d.send(ctx, events[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (d *DiscordNotifier) send(ctx context.Context, events []Event) error {
	embeds := make([]map[string]any, 0, len(events))
	for _, e := range events {
		embeds = append(embeds, embedFor(e))
	}
	payload := map[string]any{"embeds": embeds}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("discord: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord: webhook POST failed: %w", scrubURL(err, d.WebhookURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet := readSnippet(resp.Body, 256)
		return fmt.Errorf("discord: webhook returned %s: %s", resp.Status, snippet)
	}
	return nil
}

func embedFor(e Event) map[string]any {
	embed := map[string]any{
		"title": titleFor(e),
		"color": colorFor(e.Risk),
	}
	if e.ReleaseURL != "" {
		embed["url"] = e.ReleaseURL
	}
	if e.Rationale != "" {
		embed["description"] = e.Rationale
	}
	fields := []map[string]any{
		{"name": "Image", "value": "`" + nonempty(e.Image, "(unknown)") + "`", "inline": true},
	}
	if e.From != "" || e.To != "" {
		fields = append(fields, map[string]any{
			"name":   "Version",
			"value":  fmt.Sprintf("`%s → %s`", nonempty(e.From, "?"), nonempty(e.To, "?")),
			"inline": true,
		})
	}
	fields = append(fields, map[string]any{
		"name":   "Risk",
		"value":  fmt.Sprintf("**%s** (%s)", e.Risk, e.Kind),
		"inline": true,
	})
	if e.ComposeProject != "" {
		fields = append(fields, map[string]any{"name": "Stack", "value": e.ComposeProject, "inline": true})
	}
	if e.NotesSource != "" {
		fields = append(fields, map[string]any{"name": "Notes", "value": e.NotesSource, "inline": false})
	}
	embed["fields"] = fields
	if !e.Timestamp.IsZero() {
		embed["timestamp"] = e.Timestamp.UTC().Format(time.RFC3339)
	}
	return embed
}

func colorFor(r types.RiskLevel) int {
	switch r {
	case types.RiskBreaking:
		return colorBreaking
	case types.RiskReview:
		return colorReview
	case types.RiskSafe:
		return colorSafe
	default:
		return colorUnknown
	}
}
