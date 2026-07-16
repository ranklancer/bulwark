package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ranklancer/bulwark/internal/configstore"
	"github.com/ranklancer/bulwark/internal/notifier"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/pkg/types"
)

// notifierCreateRequest is the wire shape POSTed to /api/v1/notifiers.
// It mirrors configstore.NotifierEntry minus the server-controlled fields
// (ID + timestamps); the server fills those in before persisting.
type notifierCreateRequest struct {
	Name          string                             `json:"name"`
	Kind          string                             `json:"kind"`
	MinLevel      string                             `json:"min_level,omitempty"`
	Enabled       bool                               `json:"enabled"`
	Slack         *configstore.SlackSettings         `json:"slack,omitempty"`
	Discord       *configstore.DiscordSettings       `json:"discord,omitempty"`
	Teams         *configstore.TeamsSettings         `json:"teams,omitempty"`
	SMTP          *configstore.SMTPSettings          `json:"smtp,omitempty"`
	HomeAssistant *configstore.HomeAssistantSettings `json:"homeassistant,omitempty"`
	Ntfy          *configstore.NtfySettings          `json:"ntfy,omitempty"`
}

// toEntry builds a configstore.NotifierEntry from the wire request.
// The server-side ID is generated here; created/updated timestamps are
// set to "now". Validation is the caller's responsibility (Registry.AddUI
// runs Validate() inside Mutate).
func (req notifierCreateRequest) toEntry() (configstore.NotifierEntry, error) {
	id, err := configstore.NewID()
	if err != nil {
		return configstore.NotifierEntry{}, err
	}
	now := time.Now().UTC()
	return configstore.NotifierEntry{
		ID:            id,
		Name:          strings.TrimSpace(req.Name),
		Kind:          configstore.NotifierKind(strings.ToLower(strings.TrimSpace(req.Kind))),
		MinLevel:      strings.ToLower(strings.TrimSpace(req.MinLevel)),
		Enabled:       req.Enabled,
		CreatedAt:     now,
		UpdatedAt:     now,
		Slack:         req.Slack,
		Discord:       req.Discord,
		Teams:         req.Teams,
		SMTP:          req.SMTP,
		HomeAssistant: req.HomeAssistant,
		Ntfy:          req.Ntfy,
	}, nil
}

func (h *StateHandler) createNotifier(w http.ResponseWriter, r *http.Request) {
	if h.Registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(notifier.ErrUIWritesDisabled))
		return
	}
	defer r.Body.Close()
	var req notifierCreateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("decode body: %w", err)))
		return
	}
	entry, err := req.toEntry()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	if err := h.Registry.AddUI(entry); err != nil {
		// Validation errors are client-facing — return them so the form
		// can render field-level feedback.
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	if h.Store != nil {
		h.Store.Audit(store.AuditEvent{
			Action:    store.ActionNotifierCreated,
			Container: entry.Name,
			Detail:    fmt.Sprintf("kind=%s id=%s", entry.Kind, entry.ID),
		})
	}
	if h.Events != nil {
		h.Events.Publish(notifierEventConfigChanged(entry.ID, "created"))
	}
	writeJSON(w, http.StatusCreated, notifierView{
		ID:       entry.ID,
		Source:   string(notifier.SourceUI),
		Name:     entry.Name,
		MinLevel: configstoreMinLevel(entry.MinLevel),
	})
}

// getNotifier returns the full editable shape of a single UI-managed
// notifier so the dashboard can pre-fill its edit form. Secrets are
// returned as-is here (no redaction) because the operator is the same
// person who created them; redaction lives in the YAML-config view
// instead. Yaml-defined notifiers are not addressable by ID and return
// 404 — operators edit those via the YAML file.
func (h *StateHandler) getNotifier(w http.ResponseWriter, r *http.Request) {
	if h.Registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(notifier.ErrUIWritesDisabled))
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("notifier id is required")))
		return
	}
	entry, ok := h.Registry.FindStoreEntry(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errEnvelope(fmt.Errorf("no notifier with id %q", id)))
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (h *StateHandler) updateNotifier(w http.ResponseWriter, r *http.Request) {
	if h.Registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(notifier.ErrUIWritesDisabled))
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("notifier id is required")))
		return
	}
	defer r.Body.Close()
	var req notifierCreateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("decode body: %w", err)))
		return
	}
	entry, err := req.toEntry()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	// Use the URL's ID, not whatever the client guessed (or didn't send).
	entry.ID = id
	if err := h.Registry.UpdateUI(entry); err != nil {
		// "no UI entry with id ..." → 404; everything else (validation)
		// → 400. The string-match is uglier than a typed error but the
		// Registry currently returns formatted errors and a typed
		// sentinel is a wider refactor than this hot patch deserves.
		if strings.Contains(err.Error(), "no UI entry") {
			writeJSON(w, http.StatusNotFound, errEnvelope(err))
			return
		}
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	if h.Store != nil {
		h.Store.Audit(store.AuditEvent{
			Action:    store.ActionNotifierUpdated,
			Container: entry.Name,
			Detail:    fmt.Sprintf("kind=%s id=%s", entry.Kind, entry.ID),
		})
	}
	if h.Events != nil {
		h.Events.Publish(notifierEventConfigChanged(entry.ID, "updated"))
	}
	writeJSON(w, http.StatusOK, notifierView{
		ID:       entry.ID,
		Source:   string(notifier.SourceUI),
		Name:     entry.Name,
		MinLevel: configstoreMinLevel(entry.MinLevel),
	})
}

func (h *StateHandler) deleteNotifier(w http.ResponseWriter, r *http.Request) {
	if h.Registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(notifier.ErrUIWritesDisabled))
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("notifier id is required")))
		return
	}
	if err := h.Registry.DeleteUI(id); err != nil {
		writeJSON(w, http.StatusNotFound, errEnvelope(err))
		return
	}
	if h.Store != nil {
		h.Store.Audit(store.AuditEvent{
			Action: store.ActionNotifierDeleted,
			Detail: fmt.Sprintf("id=%s", id),
		})
	}
	if h.Events != nil {
		h.Events.Publish(notifierEventConfigChanged(id, "deleted"))
	}
	w.WriteHeader(http.StatusNoContent)
}

// testEphemeralNotifier accepts the same body shape as createNotifier and
// dispatches a synthetic event without persisting anything. The dashboard
// uses this for the "Send test" button on the new-notifier form: an
// operator can confirm the webhook works before committing the config.
//
// The response shape mirrors a single-element DispatchResult so the UI
// can render success / per-channel error consistently with the persisted
// "send test" endpoint.
type testNotifierResponse struct {
	Sent int    `json:"sent"`
	Err  string `json:"error,omitempty"`
}

func (h *StateHandler) testEphemeralNotifier(w http.ResponseWriter, r *http.Request) {
	if h.Registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(notifier.ErrUIWritesDisabled))
		return
	}
	defer r.Body.Close()
	var req notifierCreateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("decode body: %w", err)))
		return
	}
	entry, err := req.toEntry()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	// Always treat ephemeral test as enabled (the user explicitly asked
	// to test it). Honour the supplied min_level but bypass via the
	// Synthetic flag on the event so the test always reaches the
	// channel.
	entry.Enabled = true
	if err := entry.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	built, err := notifier.BuildFromEntry(entry)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	ev := notifier.Event{
		Container: "bulwark-test",
		Image:     "synthetic/test:1.0",
		Risk:      types.RiskReview,
		Kind:      types.ChangeMinor,
		Synthetic: true,
		Timestamp: time.Now().UTC(),
	}
	resp := testNotifierResponse{Sent: 1}
	if err := built.Notify(r.Context(), []notifier.Event{ev}); err != nil {
		resp.Sent = 0
		resp.Err = err.Error()
		writeJSON(w, http.StatusBadGateway, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// configstoreMinLevel mirrors notifier.parseMin's default-to-review
// behaviour for an empty string, used when echoing back the persisted
// entry to the client.
func configstoreMinLevel(s string) string {
	if s == "" {
		return types.RiskReview.String()
	}
	lvl := types.ParseRiskLevel(s)
	if lvl == types.RiskUnknown {
		return types.RiskReview.String()
	}
	return lvl.String()
}

// notifierEventConfigChanged builds an Event payload for the
// "config-changed" SSE channel so dashboards refresh after a notifier
// is created or deleted.
func notifierEventConfigChanged(id, action string) Event {
	return Event{
		Type:   EventNotifierConfig,
		Time:   time.Now().UTC(),
		Detail: fmt.Sprintf("%s id=%s", action, id),
	}
}
