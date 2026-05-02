package notifier

import (
	"testing"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestFromConfig_NilSafe(t *testing.T) {
	got, err := FromConfig(nil)
	if err != nil {
		t.Fatalf("nil config: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil notifiers, got %+v", got)
	}
}

func TestFromConfig_BuildsEnabledChannels(t *testing.T) {
	c := config.Defaults()
	c.Notifications.Slack.Enabled = true
	c.Notifications.Slack.WebhookURL = "https://slack.example.com/hooks/X"
	c.Notifications.Slack.MinLevel = "breaking"

	c.Notifications.Discord.Enabled = true
	c.Notifications.Discord.WebhookURL = "https://discord.example.com/hooks/Y"

	c.Notifications.Generic = []config.GenericConfig{
		{
			Enabled:  true,
			Name:     "homeassistant",
			URL:      "https://hass.example.com/api/webhook/bulwark",
			Headers:  map[string]string{"Authorization": "Bearer ${HASS_TOKEN}"},
			MinLevel: "review",
		},
		{Enabled: false, Name: "disabled-one", URL: "https://noop.example.com/"},
	}

	got, err := FromConfig(c)
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("notifier count = %d, want 3 (slack + discord + 1 enabled generic)", len(got))
	}
	// Order: slack, discord, generic.
	if got[0].Name() != "slack" {
		t.Errorf("got[0].Name = %q", got[0].Name())
	}
	if got[0].MinLevel() != types.RiskBreaking {
		t.Errorf("slack min = %v, want Breaking", got[0].MinLevel())
	}
	if got[1].Name() != "discord" {
		t.Errorf("got[1].Name = %q", got[1].Name())
	}
	// Discord with no min_level set should default to RiskReview.
	if got[1].MinLevel() != types.RiskReview {
		t.Errorf("discord default min = %v, want Review", got[1].MinLevel())
	}
	if got[2].Name() != "homeassistant" {
		t.Errorf("got[2].Name = %q", got[2].Name())
	}
}

func TestFromConfig_PartialFailureReturnsBuiltChannelsPlusError(t *testing.T) {
	c := config.Defaults()
	c.Notifications.Slack.Enabled = true
	c.Notifications.Slack.WebhookURL = "https://slack.example.com/hooks/X"
	c.Notifications.Discord.Enabled = true
	c.Notifications.Discord.WebhookURL = "" // misconfigured

	got, err := FromConfig(c)
	if err == nil {
		t.Fatal("expected partial-failure error")
	}
	if len(got) != 1 || got[0].Name() != "slack" {
		t.Errorf("expected slack only on partial failure, got %+v", got)
	}
}

func TestParseMin_Defaults(t *testing.T) {
	if got := parseMin(""); got != types.RiskReview {
		t.Errorf("empty = %v, want Review", got)
	}
	if got := parseMin("garbage"); got != types.RiskReview {
		t.Errorf("garbage = %v, want Review", got)
	}
	if got := parseMin("breaking"); got != types.RiskBreaking {
		t.Errorf("breaking = %v", got)
	}
}
