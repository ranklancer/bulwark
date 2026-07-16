package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/pkg/types"
)

// HomeAssistantNotifier fires REST calls to a Home Assistant instance's
// notify services. The per-risk-level + rollback config from
// config.HAConfig is honoured: each outcome category can independently
// hit the persistent_notification dashboard, the push service, and the
// iOS critical-alert override that bypasses Do Not Disturb.
//
// Internal filtering is done per-event rather than via Dispatcher's
// MinLevel mechanism, because Rollback events are categorised by Action
// (not Risk) and would otherwise be filtered out before HA had a chance
// to see them. We therefore advertise MinLevel=RiskSafe and decide
// per-event whether to fire any HTTP calls.
type HomeAssistantNotifier struct {
	HTTPClient  *http.Client
	BaseURL     string
	Token       string
	PushService string // notify service name for push; defaults to "notify"
	Safe        config.HANotifyLevel
	Review      config.HANotifyLevel
	Breaking    config.HANotifyLevel
	Rollback    config.HANotifyLevel
	channelName string
}

// NewHomeAssistant constructs an HA notifier. URL + Token are required.
// At least one of Safe/Review/Breaking/Rollback must enable Persistent
// or Push, otherwise the notifier wouldn't fire on any event.
func NewHomeAssistant(c config.HAConfig, name string) (*HomeAssistantNotifier, error) {
	if c.URL == "" {
		return nil, fmt.Errorf("homeassistant: %w", ErrEmptyURL)
	}
	if c.Token == "" {
		return nil, errors.New("homeassistant: token is required")
	}
	parsed, err := url.Parse(c.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("homeassistant: invalid url: %s", c.URL)
	}
	if !haConfiguredAtAll(c) {
		return nil, errors.New("homeassistant: no level enables persistent or push; nothing would fire")
	}
	if name == "" {
		name = "homeassistant"
	}
	return &HomeAssistantNotifier{
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
		BaseURL:     strings.TrimRight(c.URL, "/"),
		Token:       c.Token,
		PushService: "notify",
		Safe:        c.Safe,
		Review:      c.Review,
		Breaking:    c.Breaking,
		Rollback:    c.Rollback,
		channelName: name,
	}, nil
}

func (h *HomeAssistantNotifier) Name() string              { return h.channelName }
func (h *HomeAssistantNotifier) MinLevel() types.RiskLevel { return types.RiskSafe }

// Notify routes each event to the HA services configured for its
// effective category. Per-call failures are accumulated into a single
// joined error so one bad service name doesn't silence the rest.
func (h *HomeAssistantNotifier) Notify(ctx context.Context, events []Event) error {
	var errs []error
	for _, e := range events {
		level := h.levelFor(e)
		if !level.Persistent && !level.Push {
			continue
		}
		title := titleFor(e)
		message := haBody(e)
		if level.Persistent {
			if err := h.callService(ctx, "persistent_notification", title, message, false); err != nil {
				errs = append(errs, fmt.Errorf("homeassistant: persistent_notification for %s: %w", e.Container, err))
			}
		}
		if level.Push {
			if err := h.callService(ctx, h.pushService(), title, message, level.Critical); err != nil {
				errs = append(errs, fmt.Errorf("homeassistant: %s for %s: %w", h.pushService(), e.Container, err))
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func (h *HomeAssistantNotifier) pushService() string {
	if h.PushService == "" {
		return "notify"
	}
	return h.PushService
}

// levelFor maps an event to its HA-config category. Rollback is its own
// category — independent of the original Risk classification — so a
// SAFE→ROLLBACK event still fires the Rollback channel.
func (h *HomeAssistantNotifier) levelFor(e Event) config.HANotifyLevel {
	if e.Action == types.ActionRolledBack {
		return h.Rollback
	}
	switch e.Risk {
	case types.RiskBreaking:
		return h.Breaking
	case types.RiskReview:
		return h.Review
	case types.RiskSafe:
		return h.Safe
	default:
		return config.HANotifyLevel{}
	}
}

// callService POSTs to /api/services/notify/<service>. The Critical flag
// adds the iOS-companion-app sound.critical override that bypasses Do
// Not Disturb. Non-2xx status → error with body snippet.
func (h *HomeAssistantNotifier) callService(ctx context.Context, service, title, message string, critical bool) error {
	payload := map[string]any{
		"title":   title,
		"message": message,
	}
	if critical {
		// HA Companion app on iOS reads data.push.sound.critical to
		// bypass Do Not Disturb. Volume 1.0 is the loudest the OS
		// allows. The exact schema is documented at
		// https://companion.home-assistant.io/docs/notifications/critical-notifications/
		payload["data"] = map[string]any{
			"push": map[string]any{
				"sound": map[string]any{
					"name":     "default",
					"critical": 1,
					"volume":   1.0,
				},
			},
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	endpoint := h.BaseURL + "/api/services/notify/" + service
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", scrubURL(err, endpoint))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HA returned %s: %s", resp.Status, readSnippet(resp.Body, 256))
	}
	return nil
}

// haBody renders the message body. Plain text is best for HA — its
// notification surfaces (mobile push, persistent dashboard banner) all
// flatten anything richer. Multi-line is fine; HA preserves newlines.
func haBody(e Event) string {
	var b strings.Builder
	if e.Image != "" {
		b.WriteString(e.Image)
		b.WriteByte('\n')
	}
	if e.From != "" || e.To != "" {
		fmt.Fprintf(&b, "%s → %s", nonempty(e.From, "?"), nonempty(e.To, "?"))
		if e.Kind != types.ChangeUnknown {
			fmt.Fprintf(&b, " (%s)", e.Kind)
		}
		b.WriteByte('\n')
	}
	if e.Rationale != "" {
		b.WriteString(e.Rationale)
		b.WriteByte('\n')
	}
	if e.ReleaseURL != "" {
		b.WriteString(e.ReleaseURL)
	}
	return strings.TrimRight(b.String(), "\n")
}

// haConfiguredAtAll reports whether at least one HANotifyLevel block has
// Persistent or Push enabled. Without that, the notifier would receive
// events but never fire any HTTP — a misconfiguration we'd rather catch
// at startup than silently absorb at runtime.
func haConfiguredAtAll(c config.HAConfig) bool {
	for _, lv := range []config.HANotifyLevel{c.Safe, c.Review, c.Breaking, c.Rollback} {
		if lv.Persistent || lv.Push {
			return true
		}
	}
	return false
}
