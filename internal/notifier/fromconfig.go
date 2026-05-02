package notifier

import (
	"errors"
	"fmt"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// FromConfig builds the set of notifiers indicated by the loaded YAML config.
// Disabled blocks are skipped. Each channel's MinLevel is parsed from the
// "min_level" YAML key — empty or unrecognised values default to RiskReview
// (the same default the constructors apply).
//
// The first error encountered is returned along with whatever channels were
// successfully built up to that point — partial success is intentional, so
// a typo in one webhook URL doesn't disable the rest.
func FromConfig(c *config.Config) ([]Notifier, error) {
	if c == nil {
		return nil, nil
	}
	var (
		out  []Notifier
		errs []error
	)

	if c.Notifications.Slack.Enabled {
		min := parseMin(c.Notifications.Slack.MinLevel)
		n, err := NewSlack(c.Notifications.Slack.WebhookURL, c.Notifications.Slack.Channel, min, "slack")
		if err != nil {
			errs = append(errs, fmt.Errorf("notifications.slack: %w", err))
		} else {
			out = append(out, n)
		}
	}
	if c.Notifications.Discord.Enabled {
		min := parseMin(c.Notifications.Discord.MinLevel)
		n, err := NewDiscord(c.Notifications.Discord.WebhookURL, min, "discord")
		if err != nil {
			errs = append(errs, fmt.Errorf("notifications.discord: %w", err))
		} else {
			out = append(out, n)
		}
	}
	for i, gc := range c.Notifications.Generic {
		if !gc.Enabled {
			continue
		}
		name := gc.Name
		if name == "" {
			name = fmt.Sprintf("generic[%d]", i)
		}
		n, err := NewGeneric(gc.URL, gc.Method, gc.Headers, parseMin(gc.MinLevel), name)
		if err != nil {
			errs = append(errs, fmt.Errorf("notifications.generic[%s]: %w", name, err))
			continue
		}
		out = append(out, n)
	}

	if len(errs) > 0 {
		return out, errors.Join(errs...)
	}
	return out, nil
}

// parseMin maps a YAML string to a RiskLevel, falling back to RiskReview
// (the default per-channel threshold) for missing or invalid values.
func parseMin(s string) types.RiskLevel {
	if s == "" {
		return types.RiskReview
	}
	if lvl := types.ParseRiskLevel(s); lvl != types.RiskUnknown {
		return lvl
	}
	return types.RiskReview
}
