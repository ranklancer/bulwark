package configstore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// SettingsOverride captures the UI-mutable subset of bulwark.yaml.
// Every field is a pointer so "field unset" round-trips cleanly through
// JSON (and through Mutate diffs); a nil field tells the merge code to
// fall back to whatever the yaml file said.
//
// Why pointers: a `Schedule.CheckCron == ""` reading is ambiguous —
// is it "operator cleared the field" or "operator never set it"? With
// a pointer, `nil` means "yaml wins" and `&""` means "clear the value".
// JSON omitempty leans on the same convention.
//
// Fields explicitly left out (and the reason):
//   - api.listen — needs a server restart; "edit in yaml" instead.
//   - api.auth.* — secrets live in yaml/env, not in the store schema.
//   - docker.host — same reasoning: identity of the host is bootstrap-time.
//   - registries, hooks — large scope, future phase.
type SettingsOverride struct {
	Schedule       *ScheduleOverride       `json:"schedule,omitempty"`
	Classification *ClassificationOverride `json:"classification,omitempty"`
	Health         *HealthOverride         `json:"health,omitempty"`
	Logging        *LoggingOverride        `json:"logging,omitempty"`
	Snapshots      *SnapshotsOverride      `json:"snapshots,omitempty"`
	UpdatedAt      time.Time               `json:"updated_at"`
}

// ScheduleOverride is the editable subset of config.ScheduleConfig.
// `CheckCron` is the cron expression used to drive periodic scans;
// empty string (`&""`) disables the cron path and falls back to the
// fixed `scan_interval` CLI flag.
type ScheduleOverride struct {
	CheckCron *string `json:"check,omitempty"`
}

// ClassificationOverride is the editable subset of
// config.ClassificationConfig. PolicyOverride mirrors the policies map
// — each field optional so the dashboard can change one row at a time
// without forcing the operator to re-key the full set.
type ClassificationOverride struct {
	DefaultRisk       *string         `json:"default_risk,omitempty"`
	Policies          *PolicyOverride `json:"policies,omitempty"`
	ChangelogMaxChars *int            `json:"changelog_max_chars,omitempty"`
}

// PolicyOverride mirrors config.PolicyConfig. Empty strings (`&""`)
// fall through to the yaml-configured default.
type PolicyOverride struct {
	Patch       *string `json:"patch,omitempty"`
	Minor       *string `json:"minor,omitempty"`
	Major       *string `json:"major,omitempty"`
	Digest      *string `json:"digest,omitempty"`
	Latest      *string `json:"latest,omitempty"`
	LSIORebuild *string `json:"lsio_rebuild,omitempty"`
	Prerelease  *string `json:"prerelease,omitempty"`
}

// HealthOverride mirrors the editable subset of config.HealthConfig
// (the post-update health-check tuning). Hot-reloadable: scanJob
// re-reads these per cycle and updates the Updater's HealthTimeout.
type HealthOverride struct {
	// Timeout is the post-recreate "container must report healthy"
	// budget; the updater rolls back when this elapses. Accepts any
	// duration string Go's time.ParseDuration handles (e.g. "180s").
	Timeout *string `json:"timeout,omitempty"`
	// Interval is how often the updater polls the container's health
	// status during the wait window.
	Interval *string `json:"interval,omitempty"`
	// Threshold is the consecutive-healthy-polls count required
	// before declaring the container truly up.
	Threshold *int `json:"threshold,omitempty"`
	// GracePeriod is the post-start "ignore unhealthy status"
	// window so apps that start slow don't trigger a roll-back at
	// boot. Honours the container's HEALTHCHECK start_period when
	// the container declares one; this is the daemon-wide minimum.
	GracePeriod *string `json:"grace_period,omitempty"`
}

// LoggingOverride mirrors config.LoggingConfig. Restart-required:
// the slog logger's level is set once at startup; flipping it at
// runtime needs a slog.LevelVar refactor that's deferred to a
// follow-up phase.
type LoggingOverride struct {
	Level  *string `json:"level,omitempty"`  // "debug" | "info" | "warn" | "error"
	Format *string `json:"format,omitempty"` // "text" | "json"
}

// SnapshotsOverride captures the UI-mutable parts of the snapshots
// section. For v1 only Proxmox is exposed here (its API token is a
// secret that benefits from encrypted-at-rest storage); ZFS / Btrfs /
// Restic stay yaml-only because their configuration is mostly
// non-secret paths.
type SnapshotsOverride struct {
	// Backend, when set, overrides snapshots.backend in yaml. Empty
	// string explicitly disables all snapshot backends.
	Backend *string `json:"backend,omitempty"`
	// Proxmox, when set, replaces snapshots.proxmox.* yaml fields
	// non-nil-field-by-non-nil-field. Token is treated as a secret
	// for the dashboard's redaction pass.
	Proxmox *ProxmoxOverride `json:"proxmox,omitempty"`
}

// ProxmoxOverride mirrors config.SnapshotsConfig.Proxmox. All fields
// optional so the UI can patch one field at a time.
type ProxmoxOverride struct {
	URL         *string `json:"url,omitempty"`
	Token       *string `json:"token,omitempty"`
	Node        *string `json:"node,omitempty"`
	VMID        *int    `json:"vmid,omitempty"`
	Kind        *string `json:"kind,omitempty"`
	InsecureTLS *bool   `json:"insecure_tls,omitempty"`
}

// SettingsSection describes one UI-editable section: the wire name +
// whether changing it takes effect immediately or requires a daemon
// restart. The dashboard renders a "restart required" banner for
// sections where RestartRequired is true.
type SettingsSection struct {
	Name            string `json:"name"`
	RestartRequired bool   `json:"restart_required"`
}

// SettingsSections enumerates every section the API accepts on
// PATCH /api/v1/config/{section}. Exposed as a slice so tests + the
// dashboard can enumerate them without re-keying the strings.
//
// Sections marked RestartRequired persist immediately but only take
// effect on the next daemon start; the dashboard surfaces this clearly
// so operators know what to expect.
//
//	classification — reloads live (scanCycleConfig is rebuilt per scan
//	                 from the merged config).
//	schedule       — reloads live (scheduler.SetCron is called from
//	                 ReloadConfig).
//	health         — reloads live (scanJob updates Updater.HealthTimeout
//	                 each cycle from the merged effective config).
//	logging        — restart required (slog handler level is set once
//	                 at startup; LevelVar refactor is a future phase).
//	snapshots      — restart required (the backend pointer is wired
//	                 into StateHandler + Updater at startup).
var SettingsSections = []SettingsSection{
	{Name: "schedule", RestartRequired: false},
	{Name: "classification", RestartRequired: false},
	{Name: "health", RestartRequired: false},
	{Name: "logging", RestartRequired: true},
	{Name: "snapshots", RestartRequired: true},
}

// sectionNames returns the section names alone, for compact responses
// where the full metadata isn't required.
func sectionNames() []string {
	out := make([]string, len(SettingsSections))
	for i, s := range SettingsSections {
		out[i] = s.Name
	}
	return out
}

// Settings returns the currently-persisted settings override. A nil
// receiver yields a zero SettingsOverride so callers don't have to
// nil-guard.
func (s *Store) Settings() SettingsOverride {
	if s == nil {
		return SettingsOverride{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Settings.clone()
}

// SetSettings replaces the entire SettingsOverride atomically. The
// daemon's reload pipeline picks up the change on the next read.
func (s *Store) SetSettings(o SettingsOverride) error {
	if s == nil {
		return errors.New("configstore: nil store")
	}
	o.UpdatedAt = time.Now().UTC()
	if err := o.Validate(); err != nil {
		return err
	}
	_, err := s.Mutate(func(d *Data) error {
		d.Settings = o
		return nil
	})
	return err
}

// PatchSection applies a per-section update. Section is one of
// SettingsSections; raw is the JSON body of the request. The merge
// rule is "incoming wins for non-nil fields" — the dashboard can
// repeatedly PATCH a single field without re-sending the others.
//
// Returns the post-merge SettingsOverride so the handler can include
// it in the response.
func (s *Store) PatchSection(section string, raw []byte, decode func([]byte, any) error) (SettingsOverride, error) {
	if s == nil {
		return SettingsOverride{}, errors.New("configstore: nil store")
	}
	out, err := s.Mutate(func(d *Data) error {
		switch section {
		case "schedule":
			var incoming ScheduleOverride
			if err := decode(raw, &incoming); err != nil {
				return fmt.Errorf("decode schedule: %w", err)
			}
			if d.Settings.Schedule == nil {
				d.Settings.Schedule = &ScheduleOverride{}
			}
			if incoming.CheckCron != nil {
				d.Settings.Schedule.CheckCron = incoming.CheckCron
			}
		case "classification":
			var incoming ClassificationOverride
			if err := decode(raw, &incoming); err != nil {
				return fmt.Errorf("decode classification: %w", err)
			}
			if d.Settings.Classification == nil {
				d.Settings.Classification = &ClassificationOverride{}
			}
			if incoming.DefaultRisk != nil {
				d.Settings.Classification.DefaultRisk = incoming.DefaultRisk
			}
			if incoming.ChangelogMaxChars != nil {
				d.Settings.Classification.ChangelogMaxChars = incoming.ChangelogMaxChars
			}
			if incoming.Policies != nil {
				if d.Settings.Classification.Policies == nil {
					d.Settings.Classification.Policies = &PolicyOverride{}
				}
				mergePolicy(d.Settings.Classification.Policies, incoming.Policies)
			}
		case "health":
			var incoming HealthOverride
			if err := decode(raw, &incoming); err != nil {
				return fmt.Errorf("decode health: %w", err)
			}
			if d.Settings.Health == nil {
				d.Settings.Health = &HealthOverride{}
			}
			if incoming.Timeout != nil {
				d.Settings.Health.Timeout = incoming.Timeout
			}
			if incoming.Interval != nil {
				d.Settings.Health.Interval = incoming.Interval
			}
			if incoming.Threshold != nil {
				d.Settings.Health.Threshold = incoming.Threshold
			}
			if incoming.GracePeriod != nil {
				d.Settings.Health.GracePeriod = incoming.GracePeriod
			}
		case "logging":
			var incoming LoggingOverride
			if err := decode(raw, &incoming); err != nil {
				return fmt.Errorf("decode logging: %w", err)
			}
			if d.Settings.Logging == nil {
				d.Settings.Logging = &LoggingOverride{}
			}
			if incoming.Level != nil {
				d.Settings.Logging.Level = incoming.Level
			}
			if incoming.Format != nil {
				d.Settings.Logging.Format = incoming.Format
			}
		case "snapshots":
			var incoming SnapshotsOverride
			if err := decode(raw, &incoming); err != nil {
				return fmt.Errorf("decode snapshots: %w", err)
			}
			if d.Settings.Snapshots == nil {
				d.Settings.Snapshots = &SnapshotsOverride{}
			}
			if incoming.Backend != nil {
				d.Settings.Snapshots.Backend = incoming.Backend
			}
			if incoming.Proxmox != nil {
				if d.Settings.Snapshots.Proxmox == nil {
					d.Settings.Snapshots.Proxmox = &ProxmoxOverride{}
				}
				mergeProxmox(d.Settings.Snapshots.Proxmox, incoming.Proxmox)
			}
		default:
			return fmt.Errorf("unknown section %q (known: %s)", section, strings.Join(sectionNames(), ", "))
		}
		d.Settings.UpdatedAt = time.Now().UTC()
		return d.Settings.Validate()
	})
	if err != nil {
		return SettingsOverride{}, err
	}
	return out.Settings, nil
}

// mergeProxmox applies incoming non-nil fields onto target. Mirrors
// mergePolicy's "incoming wins" semantics so partial updates compose.
func mergeProxmox(target, incoming *ProxmoxOverride) {
	if incoming.URL != nil {
		target.URL = incoming.URL
	}
	if incoming.Token != nil {
		target.Token = incoming.Token
	}
	if incoming.Node != nil {
		target.Node = incoming.Node
	}
	if incoming.VMID != nil {
		target.VMID = incoming.VMID
	}
	if incoming.Kind != nil {
		target.Kind = incoming.Kind
	}
	if incoming.InsecureTLS != nil {
		target.InsecureTLS = incoming.InsecureTLS
	}
}

// mergePolicy applies incoming non-nil pointer fields onto target.
func mergePolicy(target, incoming *PolicyOverride) {
	if incoming.Patch != nil {
		target.Patch = incoming.Patch
	}
	if incoming.Minor != nil {
		target.Minor = incoming.Minor
	}
	if incoming.Major != nil {
		target.Major = incoming.Major
	}
	if incoming.Digest != nil {
		target.Digest = incoming.Digest
	}
	if incoming.Latest != nil {
		target.Latest = incoming.Latest
	}
	if incoming.LSIORebuild != nil {
		target.LSIORebuild = incoming.LSIORebuild
	}
	if incoming.Prerelease != nil {
		target.Prerelease = incoming.Prerelease
	}
}

// Validate enforces the risk-level / cron-expression invariants
// before a settings override is persisted. Bad inputs surface as 400s
// at the API boundary instead of as quiet "invalid" classifier output
// at scan time.
func (o SettingsOverride) Validate() error {
	if o.Classification != nil {
		if o.Classification.DefaultRisk != nil {
			if err := validateRiskLevel("classification.default_risk", *o.Classification.DefaultRisk); err != nil {
				return err
			}
		}
		if o.Classification.ChangelogMaxChars != nil && *o.Classification.ChangelogMaxChars < 0 {
			return fmt.Errorf("classification.changelog_max_chars must be >= 0, got %d", *o.Classification.ChangelogMaxChars)
		}
		if o.Classification.Policies != nil {
			for field, v := range map[string]*string{
				"patch":        o.Classification.Policies.Patch,
				"minor":        o.Classification.Policies.Minor,
				"major":        o.Classification.Policies.Major,
				"digest":       o.Classification.Policies.Digest,
				"latest":       o.Classification.Policies.Latest,
				"lsio_rebuild": o.Classification.Policies.LSIORebuild,
				"prerelease":   o.Classification.Policies.Prerelease,
			} {
				if v == nil {
					continue
				}
				if err := validateRiskLevel("classification.policies."+field, *v); err != nil {
					return err
				}
			}
		}
	}
	if o.Health != nil {
		for field, v := range map[string]*string{
			"health.timeout":      o.Health.Timeout,
			"health.interval":     o.Health.Interval,
			"health.grace_period": o.Health.GracePeriod,
		} {
			if v == nil || strings.TrimSpace(*v) == "" {
				continue
			}
			if err := validateDuration(field, *v); err != nil {
				return err
			}
		}
		if o.Health.Threshold != nil && *o.Health.Threshold < 1 {
			return fmt.Errorf("health.threshold must be >= 1, got %d", *o.Health.Threshold)
		}
	}
	if o.Logging != nil {
		if o.Logging.Level != nil && strings.TrimSpace(*o.Logging.Level) != "" {
			switch strings.ToLower(strings.TrimSpace(*o.Logging.Level)) {
			case "debug", "info", "warn", "error":
			default:
				return fmt.Errorf("logging.level %q is not one of debug|info|warn|error", *o.Logging.Level)
			}
		}
		if o.Logging.Format != nil && strings.TrimSpace(*o.Logging.Format) != "" {
			switch strings.ToLower(strings.TrimSpace(*o.Logging.Format)) {
			case "text", "json":
			default:
				return fmt.Errorf("logging.format %q is not one of text|json", *o.Logging.Format)
			}
		}
	}
	if o.Snapshots != nil {
		if o.Snapshots.Backend != nil && strings.TrimSpace(*o.Snapshots.Backend) != "" {
			switch strings.ToLower(strings.TrimSpace(*o.Snapshots.Backend)) {
			case "none", "zfs", "btrfs", "restic", "proxmox":
			default:
				return fmt.Errorf("snapshots.backend %q is not one of none|zfs|btrfs|restic|proxmox", *o.Snapshots.Backend)
			}
		}
		if o.Snapshots.Proxmox != nil {
			p := o.Snapshots.Proxmox
			if p.VMID != nil && *p.VMID < 0 {
				return fmt.Errorf("snapshots.proxmox.vmid must be >= 0 (got %d)", *p.VMID)
			}
			if p.Kind != nil && strings.TrimSpace(*p.Kind) != "" {
				switch strings.ToLower(strings.TrimSpace(*p.Kind)) {
				case "qemu", "lxc":
				default:
					return fmt.Errorf("snapshots.proxmox.kind %q is not 'qemu' or 'lxc'", *p.Kind)
				}
			}
		}
	}
	return nil
}

func validateDuration(field, v string) error {
	if _, err := time.ParseDuration(v); err != nil {
		return fmt.Errorf("%s %q is not a valid duration (e.g. '60s', '5m'): %w", field, v, err)
	}
	return nil
}

func validateRiskLevel(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty", field)
	}
	if types.ParseRiskLevel(value) == types.RiskUnknown {
		return fmt.Errorf("%s %q is not a valid risk level (safe|review|breaking)", field, value)
	}
	return nil
}

// ToUISettings translates the persisted SettingsOverride into the
// shape config.Config.WithUISettings consumes. Keeping the two types
// distinct avoids an import cycle (configstore→config is OK; the
// other direction is not).
func (o SettingsOverride) ToUISettings() *config.UISettings {
	out := &config.UISettings{}
	if o.Schedule != nil {
		out.Schedule = &config.ScheduleUISettings{CheckCron: o.Schedule.CheckCron}
	}
	if o.Classification != nil {
		c := &config.ClassificationUISettings{
			DefaultRisk:       o.Classification.DefaultRisk,
			ChangelogMaxChars: o.Classification.ChangelogMaxChars,
		}
		if o.Classification.Policies != nil {
			c.Policies = &config.PolicyUISettings{
				Patch:       o.Classification.Policies.Patch,
				Minor:       o.Classification.Policies.Minor,
				Major:       o.Classification.Policies.Major,
				Digest:      o.Classification.Policies.Digest,
				Latest:      o.Classification.Policies.Latest,
				LSIORebuild: o.Classification.Policies.LSIORebuild,
				Prerelease:  o.Classification.Policies.Prerelease,
			}
		}
		out.Classification = c
	}
	if o.Health != nil {
		out.Health = &config.HealthUISettings{
			Timeout:     o.Health.Timeout,
			Interval:    o.Health.Interval,
			Threshold:   o.Health.Threshold,
			GracePeriod: o.Health.GracePeriod,
		}
	}
	if o.Logging != nil {
		out.Logging = &config.LoggingUISettings{
			Level:  o.Logging.Level,
			Format: o.Logging.Format,
		}
	}
	if o.Snapshots != nil {
		s := &config.SnapshotsUISettings{Backend: o.Snapshots.Backend}
		if o.Snapshots.Proxmox != nil {
			s.Proxmox = &config.ProxmoxUISettings{
				URL:         o.Snapshots.Proxmox.URL,
				Token:       o.Snapshots.Proxmox.Token,
				Node:        o.Snapshots.Proxmox.Node,
				VMID:        o.Snapshots.Proxmox.VMID,
				Kind:        o.Snapshots.Proxmox.Kind,
				InsecureTLS: o.Snapshots.Proxmox.InsecureTLS,
			}
		}
		out.Snapshots = s
	}
	return out
}

func (o SettingsOverride) clone() SettingsOverride {
	out := SettingsOverride{UpdatedAt: o.UpdatedAt}
	if o.Schedule != nil {
		s := *o.Schedule
		if o.Schedule.CheckCron != nil {
			v := *o.Schedule.CheckCron
			s.CheckCron = &v
		}
		out.Schedule = &s
	}
	if o.Classification != nil {
		c := ClassificationOverride{}
		if o.Classification.DefaultRisk != nil {
			v := *o.Classification.DefaultRisk
			c.DefaultRisk = &v
		}
		if o.Classification.ChangelogMaxChars != nil {
			v := *o.Classification.ChangelogMaxChars
			c.ChangelogMaxChars = &v
		}
		if o.Classification.Policies != nil {
			p := *o.Classification.Policies
			c.Policies = &p
		}
		out.Classification = &c
	}
	if o.Health != nil {
		h := HealthOverride{}
		copyStringPtr(&h.Timeout, o.Health.Timeout)
		copyStringPtr(&h.Interval, o.Health.Interval)
		copyStringPtr(&h.GracePeriod, o.Health.GracePeriod)
		if o.Health.Threshold != nil {
			v := *o.Health.Threshold
			h.Threshold = &v
		}
		out.Health = &h
	}
	if o.Logging != nil {
		l := LoggingOverride{}
		copyStringPtr(&l.Level, o.Logging.Level)
		copyStringPtr(&l.Format, o.Logging.Format)
		out.Logging = &l
	}
	if o.Snapshots != nil {
		s := SnapshotsOverride{}
		copyStringPtr(&s.Backend, o.Snapshots.Backend)
		if o.Snapshots.Proxmox != nil {
			p := ProxmoxOverride{}
			copyStringPtr(&p.URL, o.Snapshots.Proxmox.URL)
			copyStringPtr(&p.Token, o.Snapshots.Proxmox.Token)
			copyStringPtr(&p.Node, o.Snapshots.Proxmox.Node)
			copyStringPtr(&p.Kind, o.Snapshots.Proxmox.Kind)
			if o.Snapshots.Proxmox.VMID != nil {
				v := *o.Snapshots.Proxmox.VMID
				p.VMID = &v
			}
			if o.Snapshots.Proxmox.InsecureTLS != nil {
				v := *o.Snapshots.Proxmox.InsecureTLS
				p.InsecureTLS = &v
			}
			s.Proxmox = &p
		}
		out.Snapshots = &s
	}
	return out
}

func copyStringPtr(dst **string, src *string) {
	if src == nil {
		return
	}
	v := *src
	*dst = &v
}
