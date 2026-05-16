package config

// UISettings carries the UI-mutable subset of a Config. Pointer fields
// signal "not set, fall back to the yaml-loaded value"; non-nil fields
// replace the corresponding yaml setting. Mirrors
// configstore.SettingsOverride one-for-one but lives in this package so
// config + configstore stay free of an import cycle.
//
// Why a separate type (vs. importing configstore here): config is
// imported by every package that touches a yaml field; configstore
// depends on config (for HA notify-level shape + Effective merge).
// Keeping the override type local keeps the dependency one-way.
//
// Distinct from the pre-existing Override type, which lives under
// Overrides{Stacks,Containers} and addresses per-Compose-stack or
// per-container risk overrides. The dashboard's Settings page is a
// different abstraction entirely (daemon-wide defaults).
type UISettings struct {
	Schedule       *ScheduleUISettings
	Classification *ClassificationUISettings
}

// ScheduleUISettings mirrors configstore.ScheduleOverride.
type ScheduleUISettings struct {
	CheckCron *string
}

// ClassificationUISettings mirrors configstore.ClassificationOverride.
type ClassificationUISettings struct {
	DefaultRisk       *string
	Policies          *PolicyUISettings
	ChangelogMaxChars *int
}

// PolicyUISettings mirrors configstore.PolicyOverride.
type PolicyUISettings struct {
	Patch       *string
	Minor       *string
	Major       *string
	Digest      *string
	Latest      *string
	LSIORebuild *string
	Prerelease  *string
}

// WithUISettings returns a copy of c with the override applied. nil
// override returns the input unchanged. The original *Config is never
// mutated — callers receive a fresh pointer so the yaml-loaded source
// of truth remains pristine for use cases that need it (e.g. the
// dashboard's "Advanced YAML view" tab).
func (c *Config) WithUISettings(o *UISettings) *Config {
	if c == nil {
		return nil
	}
	out := *c
	if o == nil {
		return &out
	}
	if o.Schedule != nil && o.Schedule.CheckCron != nil {
		out.Schedule.Check = *o.Schedule.CheckCron
	}
	if o.Classification != nil {
		if o.Classification.DefaultRisk != nil {
			out.Classification.DefaultRisk = *o.Classification.DefaultRisk
		}
		if o.Classification.ChangelogMaxChars != nil {
			out.Classification.ChangelogMaxChars = *o.Classification.ChangelogMaxChars
		}
		if o.Classification.Policies != nil {
			p := out.Classification.Policies
			if o.Classification.Policies.Patch != nil {
				p.Patch = *o.Classification.Policies.Patch
			}
			if o.Classification.Policies.Minor != nil {
				p.Minor = *o.Classification.Policies.Minor
			}
			if o.Classification.Policies.Major != nil {
				p.Major = *o.Classification.Policies.Major
			}
			if o.Classification.Policies.Digest != nil {
				p.Digest = *o.Classification.Policies.Digest
			}
			if o.Classification.Policies.Latest != nil {
				p.Latest = *o.Classification.Policies.Latest
			}
			if o.Classification.Policies.LSIORebuild != nil {
				p.LSIORebuild = *o.Classification.Policies.LSIORebuild
			}
			if o.Classification.Policies.Prerelease != nil {
				p.Prerelease = *o.Classification.Policies.Prerelease
			}
			out.Classification.Policies = p
		}
	}
	return &out
}
