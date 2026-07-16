package docker

import (
	"encoding/json"
	"testing"
	"time"
)

func TestContainerInspect_HealthcheckStartPeriod(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var c *ContainerInspect
		if d, ok := c.HealthcheckStartPeriod(); ok || d != 0 {
			t.Errorf("nil receiver: got (%v, %v), want (0, false)", d, ok)
		}
	})

	t.Run("empty config", func(t *testing.T) {
		c := &ContainerInspect{}
		if _, ok := c.HealthcheckStartPeriod(); ok {
			t.Error("empty config should yield false")
		}
	})

	t.Run("no healthcheck", func(t *testing.T) {
		c := &ContainerInspect{Config: json.RawMessage(`{"Image":"x"}`)}
		if _, ok := c.HealthcheckStartPeriod(); ok {
			t.Error("no healthcheck should yield false")
		}
	})

	t.Run("healthcheck without start period", func(t *testing.T) {
		c := &ContainerInspect{Config: json.RawMessage(
			`{"Healthcheck":{"Test":["CMD","true"],"Interval":1000000000}}`,
		)}
		if _, ok := c.HealthcheckStartPeriod(); ok {
			t.Error("healthcheck w/o StartPeriod should yield false")
		}
	})

	t.Run("zero start period", func(t *testing.T) {
		c := &ContainerInspect{Config: json.RawMessage(
			`{"Healthcheck":{"StartPeriod":0}}`,
		)}
		if _, ok := c.HealthcheckStartPeriod(); ok {
			t.Error("StartPeriod=0 should yield false")
		}
	})

	t.Run("60-second start period", func(t *testing.T) {
		// 60 seconds in nanoseconds.
		c := &ContainerInspect{Config: json.RawMessage(
			`{"Healthcheck":{"StartPeriod":60000000000}}`,
		)}
		got, ok := c.HealthcheckStartPeriod()
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != 60*time.Second {
			t.Errorf("got %v, want 60s", got)
		}
	})

	t.Run("malformed config", func(t *testing.T) {
		c := &ContainerInspect{Config: json.RawMessage(`{"Healthcheck":not-json`)}
		if _, ok := c.HealthcheckStartPeriod(); ok {
			t.Error("malformed JSON should yield false (not panic)")
		}
	})
}
