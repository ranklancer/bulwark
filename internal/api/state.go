package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
)

// StateHandler exposes Bulwark's persistent state (scan history, approval
// queue, notification dedup) over HTTP.
//
// Auth is delegated to the configured Authenticator: AnonymousAuth (no
// auth — only safe for localhost listeners), BearerAuth (single shared
// secret), or ForwardProxyAuth (identity headers from a trusted reverse
// proxy that terminates SSO/MFA upstream — Authelia, Authentik, etc.).
// Nil Auth defaults to AnonymousAuth so existing tests / minimal
// deployments still work.
type StateHandler struct {
	Store  *store.Store
	Logger *slog.Logger
	Auth   Authenticator
}

// Register mounts the StateHandler routes on mux. Routes use Go 1.22's
// method+path patterns. They are mounted only when Store is non-nil — a
// daemon running without --data-dir naturally has nothing to expose.
func (h *StateHandler) Register(mux *http.ServeMux) {
	if h == nil || h.Store == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/scans", h.authed(h.listScans))
	mux.HandleFunc("GET /api/v1/scans/{id}", h.authed(h.getScan))
	mux.HandleFunc("GET /api/v1/queue", h.authed(h.listQueue))
	mux.HandleFunc("POST /api/v1/queue", h.authed(h.postDecision))
	mux.HandleFunc("DELETE /api/v1/queue/{container}", h.authed(h.forgetDecision))
	mux.HandleFunc("GET /api/v1/notifications", h.authed(h.listNotifications))
	mux.HandleFunc("DELETE /api/v1/notifications", h.authed(h.clearNotifications))
}

// authed wraps a HandlerFunc with the configured Authenticator. Nil Auth
// is treated as AnonymousAuth so unconfigured deployments behave the same
// as they did before this refactor.
func (h *StateHandler) authed(next http.HandlerFunc) http.HandlerFunc {
	auth := h.Auth
	if auth == nil {
		auth = AnonymousAuth{}
	}
	return authMiddleware(auth, next)
}

// --- /api/v1/scans -----------------------------------------------------------

func (h *StateHandler) listScans(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	scans, err := h.Store.ListScans(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (h *StateHandler) getScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "latest" {
		scans, err := h.Store.ListScans(1)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
			return
		}
		if len(scans) == 0 {
			writeJSON(w, http.StatusNotFound, errEnvelope(errors.New("no scans recorded")))
			return
		}
		id = scans[0].ID
	}
	rec, err := h.Store.GetScan(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errEnvelope(err))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// --- /api/v1/queue -----------------------------------------------------------

// queueRow combines latest-scan pending updates with recorded decisions.
type queueRow struct {
	Container      string `json:"container"`
	Image          string `json:"image,omitempty"`
	Level          string `json:"level,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	RegistryDigest string `json:"registry_digest,omitempty"`
	Decision       string `json:"decision"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	Note           string `json:"note,omitempty"`
}

func (h *StateHandler) listQueue(w http.ResponseWriter, r *http.Request) {
	rows, err := buildAPIQueueRows(h.Store)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// decisionRequest is the body of POST /api/v1/queue.
type decisionRequest struct {
	Container string `json:"container"`
	Decision  string `json:"decision"` // "approved" | "rejected"
	Note      string `json:"note"`
	DecidedBy string `json:"decided_by"`
}

func (h *StateHandler) postDecision(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 8*1024)
	defer body.Close()
	var req decisionRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errEnvelope(err))
		return
	}
	if req.Container == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("container is required")))
		return
	}
	var dec store.ApprovalDecision
	switch strings.ToLower(req.Decision) {
	case "approved", "approve":
		dec = store.DecisionApproved
	case "rejected", "reject":
		dec = store.DecisionRejected
	default:
		writeJSON(w, http.StatusBadRequest, errEnvelope(fmt.Errorf("decision must be 'approved' or 'rejected', got %q", req.Decision)))
		return
	}

	scans, err := h.Store.ListScans(1)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	if len(scans) == 0 {
		writeJSON(w, http.StatusConflict, errEnvelope(errors.New("no scan history yet")))
		return
	}
	full, err := h.Store.GetScan(scans[0].ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	var match *store.ScanResultRecord
	for i := range full.Results {
		rr := full.Results[i]
		if rr.ContainerName == req.Container && rr.UpdateAvailable {
			match = &full.Results[i]
			break
		}
	}
	if match == nil {
		writeJSON(w, http.StatusNotFound, errEnvelope(fmt.Errorf("no pending update for container %q", req.Container)))
		return
	}

	rec := store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{
			ContainerID:    match.ContainerName,
			RegistryDigest: match.RegistryDigest,
		},
		ContainerName: match.ContainerName,
		Image:         match.Image,
		Decision:      dec,
		Note:          req.Note,
		DecidedBy:     req.DecidedBy,
		DecidedAt:     time.Now().UTC(),
		Level:         match.Level,
		From:          match.From,
		To:            match.To,
	}
	if rec.DecidedBy == "" {
		// Prefer the identity surfaced by the auth middleware over the
		// body's decided_by — when forward-proxy auth is configured, this
		// gives us a real per-user audit trail. Falls back to "api" only
		// for AnonymousAuth deployments.
		if id := IdentityFromContext(r.Context()); !id.IsAnonymous() {
			rec.DecidedBy = id.User
		} else {
			rec.DecidedBy = "api"
		}
	}
	if err := h.Store.RecordDecision(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (h *StateHandler) forgetDecision(w http.ResponseWriter, r *http.Request) {
	container := r.PathValue("container")
	if container == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("container is required")))
		return
	}
	all, err := h.Store.ListApprovals()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	removed := 0
	for _, a := range all {
		if a.ContainerName != container {
			continue
		}
		if err := h.Store.ForgetDecision(a.ApprovalKey); err != nil {
			writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
			return
		}
		removed++
	}
	if removed == 0 {
		writeJSON(w, http.StatusNotFound, errEnvelope(fmt.Errorf("no decisions for container %q", container)))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed})
}

// --- /api/v1/notifications --------------------------------------------------

func (h *StateHandler) listNotifications(w http.ResponseWriter, _ *http.Request) {
	entries, err := h.Store.ListNotifications()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *StateHandler) clearNotifications(w http.ResponseWriter, _ *http.Request) {
	before, err := h.Store.ListNotifications()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	if err := h.Store.ClearNotifications(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": len(before)})
}

// --- helpers ----------------------------------------------------------------

// buildAPIQueueRows mirrors the CLI's `bulwark queue list` logic so HTTP
// callers see the same view. Kept here (not in cmd/bulwark) so the API
// package doesn't import CLI packages.
func buildAPIQueueRows(st *store.Store) ([]queueRow, error) {
	scans, err := st.ListScans(1)
	if err != nil {
		return nil, err
	}
	approvals, err := st.ListApprovals()
	if err != nil {
		return nil, err
	}
	byKey := make(map[store.ApprovalKey]store.ApprovalRecord, len(approvals))
	for _, a := range approvals {
		byKey[a.ApprovalKey] = a
	}

	var rows []queueRow
	if len(scans) == 1 {
		full, err := st.GetScan(scans[0].ID)
		if err != nil {
			return nil, err
		}
		for _, rr := range full.Results {
			if !rr.UpdateAvailable {
				continue
			}
			row := queueRow{
				Container:      rr.ContainerName,
				Image:          rr.Image,
				Level:          rr.Level.String(),
				From:           rr.From,
				To:             rr.To,
				RegistryDigest: rr.RegistryDigest,
				Decision:       "pending",
			}
			key := store.ApprovalKey{ContainerID: rr.ContainerName, RegistryDigest: rr.RegistryDigest}
			if dec, ok := byKey[key]; ok {
				row.Decision = dec.Decision.String()
				row.DecidedBy = dec.DecidedBy
				row.Note = dec.Note
				if !dec.DecidedAt.IsZero() {
					row.DecidedAt = dec.DecidedAt.UTC().Format(time.RFC3339)
				}
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func errEnvelope(err error) map[string]any {
	return map[string]any{"error": err.Error()}
}
