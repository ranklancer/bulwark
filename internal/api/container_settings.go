package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ranklancer/bulwark/internal/configstore"
	"github.com/ranklancer/bulwark/internal/store"
)

// containerSettingsView mirrors configstore.ContainerOverride on the
// wire. We keep it as a separate type so the API can evolve
// independently of the on-disk schema if needed (versioned migration,
// etc.).
type containerSettingsView struct {
	SnapshotAuto    *bool   `json:"snapshot_auto,omitempty"`
	SnapshotDataset *string `json:"snapshot_dataset,omitempty"`
}

func (h *StateHandler) listContainerSettings(w http.ResponseWriter, _ *http.Request) {
	if h.ConfigStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(errors.New("config store not configured")))
		return
	}
	out := h.ConfigStore.ContainerOverrides()
	// Map nil → empty so the dashboard always decodes an object.
	if out == nil {
		out = map[string]configstore.ContainerOverride{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *StateHandler) putContainerSettings(w http.ResponseWriter, r *http.Request) {
	if h.ConfigStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(errors.New("config store not configured")))
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("container name is required")))
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("read body: %w", err)))
		return
	}
	var req containerSettingsView
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("decode body: %w", err)))
		return
	}
	if err := h.ConfigStore.SetContainerOverride(name, configstore.ContainerOverride{
		SnapshotAuto:    req.SnapshotAuto,
		SnapshotDataset: req.SnapshotDataset,
	}); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	if h.Store != nil {
		h.Store.Audit(store.AuditEvent{
			Action:    store.ActionContainerSettings,
			Container: name,
			Detail:    summarizeContainerSettings(req),
		})
	}
	if h.Events != nil {
		h.Events.Publish(Event{
			Type:      EventConfigUpdated,
			Container: name,
			Detail:    "container-settings updated",
		})
	}
	got, _ := h.ConfigStore.ContainerOverride(name)
	writeJSON(w, http.StatusOK, got)
}

func (h *StateHandler) deleteContainerSettings(w http.ResponseWriter, r *http.Request) {
	if h.ConfigStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errEnvelope(errors.New("config store not configured")))
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("container name is required")))
		return
	}
	if err := h.ConfigStore.DeleteContainerOverride(name); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	if h.Store != nil {
		h.Store.Audit(store.AuditEvent{
			Action:    store.ActionContainerSettings,
			Container: name,
			Detail:    "cleared",
		})
	}
	if h.Events != nil {
		h.Events.Publish(Event{
			Type:      EventConfigUpdated,
			Container: name,
			Detail:    "container-settings cleared",
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func summarizeContainerSettings(v containerSettingsView) string {
	switch {
	case v.SnapshotDataset != nil && *v.SnapshotDataset != "":
		return "snapshot_dataset=" + *v.SnapshotDataset
	case v.SnapshotDataset != nil:
		return "snapshot disabled (explicit empty)"
	case v.SnapshotAuto != nil && *v.SnapshotAuto:
		return "snapshot_auto=true"
	case v.SnapshotAuto != nil:
		return "snapshot_auto=false"
	}
	return "cleared"
}
