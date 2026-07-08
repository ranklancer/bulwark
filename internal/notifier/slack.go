package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// SlackNotifier delivers events to a Slack incoming webhook using Block Kit
// for rich formatting. Each Notify call sends one webhook POST containing a
// digest of all events.
type SlackNotifier struct {
	HTTPClient *http.Client
	WebhookURL string
	// Channel optionally overrides the channel the webhook posts to. Slack
	// only honours this for legacy webhook configurations; modern webhooks
	// post wherever they were configured. Bulwark sends it anyway when set,
	// so older deployments keep working.
	Channel string
	Min     types.RiskLevel
	// channelName is the user-visible identifier used in logs and errors.
	channelName string
}

// NewSlack constructs a SlackNotifier. The webhook URL is required; callers
// supply it from configuration (typically via env-var substitution).
func NewSlack(webhookURL, channelOverride string, min types.RiskLevel, name string) (*SlackNotifier, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("slack: %w", ErrEmptyURL)
	}
	if name == "" {
		name = "slack"
	}
	if min == types.RiskUnknown {
		min = types.RiskReview
	}
	return &SlackNotifier{
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
		WebhookURL:  webhookURL,
		Channel:     channelOverride,
		Min:         min,
		channelName: name,
	}, nil
}

func (s *SlackNotifier) Name() string              { return s.channelName }
func (s *SlackNotifier) MinLevel() types.RiskLevel { return s.Min }

// Notify renders events as a single Block Kit message and POSTs it.
func (s *SlackNotifier) Notify(ctx context.Context, events []Event) error {
	payload := s.payload(events)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		// Strip any echoed URL from the error to avoid leaking webhook
		// secrets via logs.
		return fmt.Errorf("slack: webhook POST failed: %w", scrubURL(err, s.WebhookURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet := readSnippet(resp.Body, 256)
		return fmt.Errorf("slack: webhook returned %s: %s", resp.Status, snippet)
	}
	return nil
}

// payload constructs the Block Kit JSON body for a batch of events.
func (s *SlackNotifier) payload(events []Event) map[string]any {
	blocks := make([]map[string]any, 0, len(events)*4)

	header := "Bulwark"
	if len(events) == 1 {
		header = titleFor(events[0])
	} else {
		header = fmt.Sprintf("Bulwark scan: %d update(s)", len(events))
	}
	blocks = append(blocks, map[string]any{
		"type": "header",
		"text": map[string]any{"type": "plain_text", "text": header, "emoji": true},
	})

	for i, e := range events {
		if i > 0 {
			blocks = append(blocks, map[string]any{"type": "divider"})
		}
		fields := []map[string]any{
			{"type": "mrkdwn", "text": "*Container:*\n`" + nonempty(e.Container, "(unknown)") + "`"},
			{"type": "mrkdwn", "text": "*Image:*\n`" + nonempty(e.Image, "(unknown)") + "`"},
		}
		if e.From != "" || e.To != "" {
			fields = append(fields, map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Version:*\n`%s → %s`", nonempty(e.From, "?"), nonempty(e.To, "?")),
			})
		}
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*Risk:*\n%s (%s)", riskBadge(e.Risk), e.Kind),
		})
		blocks = append(blocks, map[string]any{
			"type":   "section",
			"fields": fields,
		})
		if e.Rationale != "" {
			blocks = append(blocks, map[string]any{
				"type": "context",
				"elements": []map[string]any{
					{"type": "mrkdwn", "text": e.Rationale},
				},
			})
		}
		if e.ReleaseURL != "" {
			blocks = append(blocks, map[string]any{
				"type": "actions",
				"elements": []map[string]any{
					{
						"type": "button",
						"text": map[string]any{"type": "plain_text", "text": "Release notes"},
						"url":  e.ReleaseURL,
					},
				},
			})
		}
	}

	out := map[string]any{"blocks": blocks}
	if s.Channel != "" {
		out["channel"] = s.Channel
	}
	return out
}

func riskBadge(r types.RiskLevel) string {
	switch r {
	case types.RiskBreaking:
		return ":red_circle: BREAKING"
	case types.RiskReview:
		return ":large_yellow_circle: REVIEW"
	case types.RiskSafe:
		return ":large_green_circle: SAFE"
	default:
		return ":white_circle: " + strings.ToUpper(r.String())
	}
}

func nonempty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// scrubURL returns an error wrapping err that has the secret URL redacted.
// It only kicks in when the URL appears verbatim in the error message —
// transport errors typically include it as part of "Post URL: dial ...".
func scrubURL(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, secret) {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(msg, secret, "<redacted>"))
}

func readSnippet(r io.Reader, n int) string {
	buf := make([]byte, n)
	read, _ := io.ReadFull(r, buf)
	return strings.TrimSpace(string(buf[:read]))
}
