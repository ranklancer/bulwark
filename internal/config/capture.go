package config

import (
	"fmt"
	"strings"
)

// CaptureConfig configures the digest pinning digest-pin capture layer (the digest-pin capture design §8.2).
type CaptureConfig struct {
	RequireIndex    bool   `yaml:"require_index"`     // multi-arch pins must be index digests
	Lockfile        string `yaml:"lockfile"`          // pins.json name under --data-dir
	ComposePinStyle string `yaml:"compose_pin_style"` // inline | lockfile-only (an internal note: inline authoritative)
	BackupDir       string `yaml:"backup_dir"`        // default <data-dir>/pin-backups
	Apply           bool   `yaml:"apply"`             // dry-run by default; CLI --apply overrides per run
}

// SourceConfig declares one container-management backend to capture from. Only
// the file-based "compose" type is implemented in digest pinning; managed backends
// (portainer/ix-apps/komodo/swarm) are recognised by the validator but rejected
// until their adapter ships, so a config can be forward-declared safely.
type SourceConfig struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`         // compose (file) | portainer | ix-apps | komodo | swarm (future)
	Autodiscover bool     `yaml:"autodiscover"` // detect Dockge/compose layouts on the host
	Paths        []string `yaml:"paths"`        // dirs / globs / compose files
	Endpoint     string   `yaml:"endpoint"`     // managed adapters only (API URL)
	CredsRef     string   `yaml:"creds_ref"`    // Vaultwarden item id (never an inline secret)

	// Dockge (type: dockge) — Paths are stacks roots and Autodiscover enables
	// probing well-known Dockge locations. ExtraRoots adds candidate roots
	// (e.g. a TrueNAS ix-dockge apps path); DockgeCompose is an optional Dockge
	// compose file whose stacks bind-mount locates the host stacks root.
	ExtraRoots    []string `yaml:"extra_roots"`
	DockgeCompose string   `yaml:"dockge_compose"`
}

// validateCapture checks the capture/sources block. No-op when unset.
func (c *Config) validateCapture() error {
	switch strings.ToLower(strings.TrimSpace(c.Capture.ComposePinStyle)) {
	case "", "inline", "lockfile-only":
	default:
		return fmt.Errorf("capture.compose_pin_style %q is not inline|lockfile-only", c.Capture.ComposePinStyle)
	}
	seen := map[string]bool{}
	for i, src := range c.Sources {
		name := strings.TrimSpace(src.Name)
		if name == "" {
			return fmt.Errorf("sources[%d].name must not be empty", i)
		}
		if seen[name] {
			return fmt.Errorf("sources: duplicate source name %q", name)
		}
		seen[name] = true
		switch strings.ToLower(strings.TrimSpace(src.Type)) {
		case "", "compose":
			if len(src.Paths) == 0 && !src.Autodiscover {
				return fmt.Errorf("sources[%q]: a compose source needs paths or autodiscover: true", name)
			}
		case "dockge":
			if len(src.Paths) == 0 && !src.Autodiscover {
				return fmt.Errorf("sources[%q]: a dockge source needs paths (stacks roots) or autodiscover: true", name)
			}
		case "portainer", "ix-apps", "komodo", "swarm":
			return fmt.Errorf("sources[%q]: type %q is a managed backend not yet implemented (digest pinning ships the file-based compose adapter only)", name, strings.ToLower(src.Type))
		default:
			return fmt.Errorf("sources[%q]: unknown type %q", name, src.Type)
		}
	}
	return nil
}
