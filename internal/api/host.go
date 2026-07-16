package api

import (
	"net/http"

	"github.com/ranklancer/bulwark/internal/snapshot/detect"
)

// hostView is the wire shape of GET /api/v1/host. The dashboard's
// Snapshots page uses it to render the "Detected platform" panel and
// to suggest a backend when the operator hasn't configured one.
type hostView struct {
	Platform          string   `json:"platform"`
	Version           string   `json:"version,omitempty"`
	Capabilities      []string `json:"capabilities"`
	SuggestedBackend  string   `json:"suggested_backend,omitempty"`
	ConfiguredBackend string   `json:"configured_backend,omitempty"`
}

func (h *StateHandler) getHost(w http.ResponseWriter, _ *http.Request) {
	result := detect.Detect()
	if h.HostDetection != nil {
		// In tests + dependency-injected runs we override the live probe
		// with a fixture so the response is deterministic.
		result = *h.HostDetection
	}
	caps := make([]string, len(result.Capabilities))
	for i, c := range result.Capabilities {
		caps[i] = string(c)
	}
	view := hostView{
		Platform:         string(result.Platform),
		Version:          result.VersionString,
		Capabilities:     caps,
		SuggestedBackend: result.SuggestedBackend,
	}
	if h.LoadedConfig != nil {
		view.ConfiguredBackend = h.LoadedConfig.Snapshots.Backend
	}
	writeJSON(w, http.StatusOK, view)
}
