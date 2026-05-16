package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/bulwark-docker/bulwark/internal/configstore"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// settingsResponse is the wire shape of GET /api/v1/config/settings and
// the post-patch echo. Sections lists every section the API accepts on
// PATCH (including the restart-required metadata) so the dashboard
// renders the right tab set without re-keying the enumeration.
type settingsResponse struct {
	Settings configstore.SettingsOverride `json:"settings"`
	Sections []configstore.SettingsSection `json:"sections"`
}

// effectiveConfigResponse is the wire shape of GET /api/v1/config/effective.
// It returns the post-merge yaml-style tree (secrets redacted) and a
// compact summary of which sections currently carry an override (so
// the dashboard can render "modified from yaml" badges).
type effectiveConfigResponse struct {
	Config              any      `json:"config"`
	OverriddenSections  []string `json:"overridden_sections"`
}

func (h *StateHandler) getSettings(w http.ResponseWriter, _ *http.Request) {
	if h.ConfigStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(errors.New("config store not configured")))
		return
	}
	writeJSON(w, http.StatusOK, settingsResponse{
		Settings: h.ConfigStore.Settings(),
		Sections: configstore.SettingsSections,
	})
}

func (h *StateHandler) getEffectiveConfig(w http.ResponseWriter, _ *http.Request) {
	if h.LoadedConfig == nil || h.ConfigStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(errors.New("config not exposed")))
		return
	}
	settings := h.ConfigStore.Settings()
	merged := h.LoadedConfig.WithUISettings(settings.ToUISettings())

	// Round-trip through yaml + redact secrets so the dashboard renders
	// snake_case keys (matching the operator's yaml) and never sees a
	// literal token even when it has been overridden by env-var
	// substitution.
	raw, err := yaml.Marshal(merged)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	redactSecrets(tree)

	writeJSON(w, http.StatusOK, effectiveConfigResponse{
		Config:             tree,
		OverriddenSections: overriddenSections(settings),
	})
}

func (h *StateHandler) patchSettingsSection(w http.ResponseWriter, r *http.Request) {
	if h.ConfigStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(errors.New("config store not configured")))
		return
	}
	section := r.PathValue("section")
	if section == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("section path parameter is required")))
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("read body: %w", err)))
		return
	}
	out, err := h.ConfigStore.PatchSection(section, raw, json.Unmarshal)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	if h.ReloadConfig != nil {
		h.ReloadConfig()
	}
	if h.Store != nil {
		h.Store.Audit(store.AuditEvent{
			Action: store.ActionConfigUpdated,
			Detail: fmt.Sprintf("section=%s", section),
		})
	}
	if h.Events != nil {
		h.Events.Publish(Event{
			Type:   EventConfigUpdated,
			Detail: "section=" + section,
		})
	}
	writeJSON(w, http.StatusOK, settingsResponse{
		Settings: out,
		Sections: configstore.SettingsSections,
	})
}

// overriddenSections returns the names of sections that currently carry
// at least one non-nil override field. The dashboard uses this to badge
// "modified from yaml" on tab headers.
func overriddenSections(s configstore.SettingsOverride) []string {
	out := make([]string, 0, 2)
	if s.Schedule != nil && (s.Schedule.CheckCron != nil) {
		out = append(out, "schedule")
	}
	if s.Classification != nil {
		c := s.Classification
		if c.DefaultRisk != nil || c.ChangelogMaxChars != nil ||
			(c.Policies != nil && hasAnyPolicy(c.Policies)) {
			out = append(out, "classification")
		}
	}
	return out
}

func hasAnyPolicy(p *configstore.PolicyOverride) bool {
	return p.Patch != nil || p.Minor != nil || p.Major != nil ||
		p.Digest != nil || p.Latest != nil ||
		p.LSIORebuild != nil || p.Prerelease != nil
}
