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
	c.Sources = []SourceConfig{{Name: "p", Type: "portainer", Endpoint: "http://x"}} // no creds_ref
	if err := c.Validate(); err == nil {
		t.Error("portainer without creds_ref must be rejected (secret must not be inline)")
	}
	c = base()
	c.Sources = []SourceConfig{{Name: "k", Type: "komodo", Endpoint: "http://x"}}
	if err := c.Validate(); err == nil {
		t.Error("a not-yet-implemented managed backend (komodo) must be rejected")
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

func TestValidateCapture_PortainerOK(t *testing.T) {
	c := &Config{}
	c.Classification.DefaultRisk = "review"
	c.Capture.ComposePinStyle = "inline"
	c.Sources = []SourceConfig{{Name: "portainer", Type: "portainer", Endpoint: "https://portainer.example:9443", CredsRef: "PORTAINER_API_KEY"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("a portainer source with endpoint + creds_ref must pass: %v", err)
	}
}
