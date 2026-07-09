package config

import "testing"

func TestValidateCapture_ComposeSourceOK(t *testing.T) {
	c := &Config{}
	c.Classification.DefaultRisk = "review"
	c.Sources = []SourceConfig{{Name: "dockge", Type: "compose", Autodiscover: true}}
	c.Capture.ComposePinStyle = "inline"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid compose source must pass: %v", err)
	}
}

func TestValidateCapture_RejectsManagedAndBadStyle(t *testing.T) {
	base := func() *Config {
		c := &Config{}
		c.Classification.DefaultRisk = "review"
		return c
	}
	c := base()
	c.Sources = []SourceConfig{{Name: "p", Type: "portainer", Endpoint: "http://x"}}
	if err := c.Validate(); err == nil {
		t.Error("managed backend must be rejected until its adapter ships")
	}
	c = base()
	c.Sources = []SourceConfig{{Name: "d", Type: "compose"}} // no paths, no autodiscover
	if err := c.Validate(); err == nil {
		t.Error("compose source with no paths and no autodiscover must be rejected")
	}
	c = base()
	c.Capture.ComposePinStyle = "sideways"
	if err := c.Validate(); err == nil {
		t.Error("bad compose_pin_style must be rejected")
	}
	c = base()
	c.Sources = []SourceConfig{{Name: "x", Type: "compose", Autodiscover: true}, {Name: "x", Type: "compose", Autodiscover: true}}
	if err := c.Validate(); err == nil {
		t.Error("duplicate source names must be rejected")
	}
}
