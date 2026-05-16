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
//   * api.listen — needs a server restart; "edit in yaml" instead.
//   * api.auth.* — secrets live in yaml/env, not in the store schema.
//   * docker.host — same reasoning: identity of the host is bootstrap-time.
//   * snapshots, registries, hooks — large scope, future phase.
type SettingsOverride struct {
	Schedule       *ScheduleOverride       `json:"schedule,omitempty"`
	Classification *ClassificationOverride `json:"classification,omitempty"`
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
	DefaultRisk       *string          `json:"default_risk,omitempty"`
	Policies          *PolicyOverride  `json:"policies,omitempty"`
	ChangelogMaxChars *int             `json:"changelog_max_chars,omitempty"`
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
// so operators know what to expect. classification reloads live
// because scanCycleConfig is rebuilt from the merged config per scan;
// schedule reloads live because the scheduler exposes SetCron and the
// ReloadConfig hook calls it when this section is PATCHed.
var SettingsSections = []SettingsSection{
	{Name: "schedule", RestartRequired: false},
	{Name: "classification", RestartRequired: false},
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
				"patch":         o.Classification.Policies.Patch,
				"minor":         o.Classification.Policies.Minor,
				"major":         o.Classification.Policies.Major,
				"digest":        o.Classification.Policies.Digest,
				"latest":        o.Classification.Policies.Latest,
				"lsio_rebuild":  o.Classification.Policies.LSIORebuild,
				"prerelease":    o.Classification.Policies.Prerelease,
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
	return out
}
