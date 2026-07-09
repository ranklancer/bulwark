package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/configstore"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/snapshot"
	"github.com/bulwark-docker/bulwark/internal/snapshot/detect"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
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
//
// CSRF is enforced on POST/DELETE/PUT/PATCH endpoints — the stance is
// "Sec-Fetch-Site=same-origin or recognized Origin", with Origin-less
// requests passing through (so curl + scripts continue to work). Browser
// cross-origin posts are rejected before they reach the handler.
type StateHandler struct {
	Store  *store.Store
	Logger *slog.Logger
	Auth   Authenticator

	// CSRF configures the cross-site-request-forgery defense applied to
	// mutating endpoints. Nil uses DefaultCSRFConfig.
	CSRF *CSRFConfig

	// TriggerScan, when set, runs one scan cycle on demand. The daemon's
	// `bulwark run` wires this to the same scan-job closure the scheduler
	// invokes, so a POST /api/v1/scans queue-jumps the next periodic
	// firing. nil omits the route.
	TriggerScan func(ctx context.Context) error

	// Sessions, when non-nil, enables HTTP-only session cookie auth so
	// the dashboard can authenticate without a token-in-localStorage
	// XSS vector. Auth is expected to be wrapped in CookieOrInnerAuth
	// pointing at the same SessionScheme so cookies actually satisfy
	// the wider middleware. The SessionInnerAuth field is the bare
	// inner Authenticator used by POST /api/v1/sessions to validate
	// the bootstrap credential before issuing a cookie.
	Sessions         *SessionScheme
	SessionInnerAuth Authenticator

	// Dispatcher, when set, exposes the configured notification
	// channels via GET /api/v1/notifiers and the synthetic-event
	// "send a test" endpoint at POST /api/v1/notifiers/{name}/test.
	// nil omits both routes.
	//
	// When Registry is also set, the daemon uses Registry as the
	// source of truth (it carries source-of-config metadata + a
	// SIGHUP-driven reload loop). Dispatcher is then derived from
	// the Registry's current snapshot and kept in sync automatically.
	Dispatcher *notifier.Dispatcher

	// Registry, when set, replaces Dispatcher as the source of truth
	// for the notifier set. The dashboard's POST/DELETE
	// /api/v1/notifiers endpoints mutate the underlying configstore
	// and trigger a registry reload. nil leaves notifier config
	// strictly yaml-driven (legacy / GitOps deployments).
	Registry *notifier.Registry

	// ConfigStore, when set, exposes UI-mutable subsets of the
	// configuration (settings overrides on top of the yaml-loaded
	// LoadedConfig). The dashboard's Settings page hits the
	// PATCH /api/v1/config/{section} endpoints; the daemon's hot
	// paths (scan, classify) read the merged config via
	// ConfigStore.Settings() at use time so changes take effect on
	// the next cycle without a restart.
	ConfigStore *configstore.Store

	// ReloadConfig is fired after a successful PATCH so daemon
	// subsystems can rebuild any state derived from the merged
	// config (rate limiter, scheduler cron, etc.). nil is fine;
	// most subsystems read configstore at use-time anyway.
	ReloadConfig func()

	// HostDetection, when set, overrides the live host probe with a
	// fixture. nil means GET /api/v1/host runs detect.Detect() against
	// the real filesystem at request time. Set in tests + when the
	// caller wants to cache one probe pass for the daemon's lifetime.
	HostDetection *detect.Result

	// LoadedConfig, when set, is exposed (with secrets redacted) via
	// GET /api/v1/config and feeds the GET /api/v1/policies effective-
	// classifier-config response. nil omits both routes — the
	// dashboard then renders "config not exposed" rather than failing.
	LoadedConfig *config.Config

	// SnapshotBackend, when set, exposes GET /api/v1/snapshots for the
	// dashboard's snapshot panel. Listing is read-only; restore + prune
	// stay CLI-only by design (destructive, want the operator to type
	// the explicit `bulwark snapshot restore --yes <id>` CLI form).
	SnapshotBackend snapshot.Backend

	// Events, when set, powers GET /api/v1/events (Server-Sent Events
	// stream) and the publish points the daemon's hot paths call. nil
	// omits the route — the dashboard falls back to the existing
	// "manual refresh" UX.
	Events *EventBus
}

// Register mounts the StateHandler routes on mux. Routes use Go 1.22's
// method+path patterns. They are mounted only when Store is non-nil — a
// daemon running without --data-dir naturally has nothing to expose.
//
// Mutating endpoints (POST/DELETE) are wrapped with the CSRF middleware;
// read endpoints are not.
func (h *StateHandler) Register(mux *http.ServeMux) {
	if h == nil || h.Store == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/scans", h.authed(h.listScans))
	mux.HandleFunc("GET /api/v1/scans/{id}", h.authed(h.getScan))
	if h.TriggerScan != nil {
		mux.HandleFunc("POST /api/v1/scans", h.authed(h.csrfProtect(h.postScan)))
	}
	mux.HandleFunc("GET /api/v1/queue", h.authed(h.listQueue))
	mux.HandleFunc("POST /api/v1/queue", h.authed(h.csrfProtect(h.postDecision)))
	mux.HandleFunc("DELETE /api/v1/queue/{container}", h.authed(h.csrfProtect(h.forgetDecision)))
	mux.HandleFunc("GET /api/v1/notifications", h.authed(h.listNotifications))
	mux.HandleFunc("DELETE /api/v1/notifications", h.authed(h.csrfProtect(h.clearNotifications)))
	// GET is always mounted so an anonymous-mode deployment can answer
	// the SPA's "am I logged in?" probe with the same shape as
	// session-enabled deployments. The response body's
	// session_endpoints_enabled flag tells the dashboard whether to
	// render the logout button + login page at all.
	mux.HandleFunc("GET /api/v1/sessions", h.authed(h.getSession))
	if h.Sessions != nil {
		// POST uses the *bare* inner Authenticator (typically Bearer)
		// so a cookie can't refresh itself indefinitely — only the
		// holder of the bootstrap credential gets a fresh session.
		// DELETE is open: even an expired cookie can request its own
		// deletion (logout button keeps working past TTL).
		mux.HandleFunc("POST /api/v1/sessions", h.csrfProtect(h.postSession))
		mux.HandleFunc("DELETE /api/v1/sessions", h.csrfProtect(h.deleteSession))
	}
	mux.HandleFunc("GET /api/v1/audit", h.authed(h.listAudit))
	mux.HandleFunc("GET /api/v1/containers", h.authed(h.listContainers))
	if h.ConfigStore != nil {
		// Per-container UI-driven overrides (snapshot_auto /
		// snapshot_dataset today). Persists to the encrypted store
		// and takes effect at the next apply cycle.
		mux.HandleFunc("GET /api/v1/containers/settings", h.authed(h.listContainerSettings))
		mux.HandleFunc("PUT /api/v1/containers/{name}/settings", h.authed(h.csrfProtect(h.putContainerSettings)))
		mux.HandleFunc("DELETE /api/v1/containers/{name}/settings", h.authed(h.csrfProtect(h.deleteContainerSettings)))
	}
	if h.Dispatcher != nil {
		mux.HandleFunc("GET /api/v1/notifiers", h.authed(h.listNotifiers))
		mux.HandleFunc("POST /api/v1/notifiers/{name}/test",
			h.authed(h.csrfProtect(h.testNotifier)))
	}
	if h.Registry != nil {
		// UI-managed notifier CRUD. Yaml-defined notifiers surface in
		// listNotifiers as read-only "managed by YAML" cards; these
		// routes write to the encrypted configstore + reload.
		mux.HandleFunc("POST /api/v1/notifiers", h.authed(h.csrfProtect(h.createNotifier)))
		mux.HandleFunc("GET /api/v1/notifiers/{id}", h.authed(h.getNotifier))
		mux.HandleFunc("PATCH /api/v1/notifiers/{id}", h.authed(h.csrfProtect(h.updateNotifier)))
		mux.HandleFunc("DELETE /api/v1/notifiers/{id}", h.authed(h.csrfProtect(h.deleteNotifier)))
		mux.HandleFunc("POST /api/v1/notifiers/test", h.authed(h.csrfProtect(h.testEphemeralNotifier)))
	}
	if h.LoadedConfig != nil {
		mux.HandleFunc("GET /api/v1/config", h.authed(h.getConfig))
		mux.HandleFunc("GET /api/v1/policies", h.authed(h.getPolicies))
	}
	if h.ConfigStore != nil {
		// /settings + PATCH only need the configstore; they return
		// the override payload directly. /effective also needs
		// LoadedConfig so it can compute the merged tree.
		mux.HandleFunc("GET /api/v1/config/settings", h.authed(h.getSettings))
		mux.HandleFunc("PATCH /api/v1/config/{section}", h.authed(h.csrfProtect(h.patchSettingsSection)))
		if h.LoadedConfig != nil {
			mux.HandleFunc("GET /api/v1/config/effective", h.authed(h.getEffectiveConfig))
		}
	}
	if h.SnapshotBackend != nil {
		mux.HandleFunc("GET /api/v1/snapshots", h.authed(h.listSnapshots))
	}
	// Host detection is always mounted — even when no SnapshotBackend
	// is configured, the dashboard wants to render a "platform =
	// truenas-scale" badge and suggest a backend. The endpoint is
	// read-only and reveals no secrets.
	mux.HandleFunc("GET /api/v1/host", h.authed(h.getHost))
	if h.Events != nil {
		mux.HandleFunc("GET /api/v1/events", h.authed(streamHandler(h.Events)))
	}
}

// currentDispatcher returns the live notifier Dispatcher. When a
// Registry is wired the Dispatcher is read fresh on each call so a
// SIGHUP-triggered reload propagates to callers immediately; otherwise
// the legacy h.Dispatcher field is used (yaml-only deployments).
func (h *StateHandler) currentDispatcher() *notifier.Dispatcher {
	if h.Registry != nil {
		return h.Registry.Dispatcher()
	}
	return h.Dispatcher
}

// csrfProtect wraps a handler with CSRF defense, using the configured
// CSRFConfig (or the default when nil).
func (h *StateHandler) csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	cfg := DefaultCSRFConfig()
	if h.CSRF != nil {
		cfg = *h.CSRF
	}
	return csrfMiddlewareFunc(cfg, nil, next)
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
		if errors.Is(err, store.ErrInvalidScanID) {
			writeJSON(w, http.StatusBadRequest, errEnvelope(err))
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errEnvelope(err))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// postScan triggers an immediate scan cycle. Returns 202 Accepted so
// long-running scans don't tie up the request: the cycle's outcome is
// observable via the next `GET /api/v1/scans` listing.
func (h *StateHandler) postScan(w http.ResponseWriter, r *http.Request) {
	if h.TriggerScan == nil {
		writeJSON(w, http.StatusNotImplemented, errEnvelope(errors.New("scan trigger not configured")))
		return
	}
	// Fire and forget. The cycle records its own history; the response
	// just acknowledges receipt. We could block here and return a record
	// summary, but a slow scan would tie up the request and the dashboard
	// already polls `/api/v1/scans` regularly.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := h.TriggerScan(ctx); err != nil && h.Logger != nil {
			h.Logger.Warn("api: triggered scan failed", "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"scheduled": true})
}

// --- /api/v1/queue -----------------------------------------------------------

// queueRow combines latest-scan pending updates with recorded decisions.
type queueRow struct {
	Container      string                    `json:"container"`
	Image          string                    `json:"image,omitempty"`
	Level          string                    `json:"level,omitempty"`
	From           string                    `json:"from,omitempty"`
	To             string                    `json:"to,omitempty"`
	RegistryDigest string                    `json:"registry_digest,omitempty"`
	Decision       string                    `json:"decision"`
	DecidedBy      string                    `json:"decided_by,omitempty"`
	DecidedAt      string                    `json:"decided_at,omitempty"`
	Note           string                    `json:"note,omitempty"`
	Security       *types.SecurityAssessment `json:"security,omitempty"`
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
	h.Events.Publish(Event{
		Type:      EventDecisionRecorded,
		Container: rec.ContainerID,
		Detail:    rec.Decision.String(),
	})
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
	if removed > 0 {
		h.Events.Publish(Event{Type: EventDecisionForgot, Container: container})
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
	h.Events.Publish(Event{
		Type:   EventNotificationsCleared,
		Detail: fmt.Sprintf("%d cleared", len(before)),
	})
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
				Security:       rr.Security,
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

// --- /api/v1/audit -----------------------------------------------------------

// listAudit returns the most-recent audit-log entries, newest first.
// Tail-of-log semantics matches the `bulwark audit` CLI.
func (h *StateHandler) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := h.Store.ReadAudit(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	if events == nil {
		// nil → empty slice so the dashboard's "no events yet"
		// rendering doesn't have to special-case JSON null.
		events = []store.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// --- /api/v1/containers ------------------------------------------------------

// containerView is the dashboard-facing summary of one monitored
// container, derived from the most-recent scan record. We deliberately
// don't go to the Docker socket here — the latest scan already contains
// the data + we want the dashboard to be view-only/cheap.
type containerView struct {
	ContainerID     string `json:"container_id,omitempty"`
	ContainerName   string `json:"container_name"`
	Image           string `json:"image,omitempty"`
	ComposeProject  string `json:"compose_project,omitempty"`
	Skipped         bool   `json:"skipped,omitempty"`
	SkipReason      string `json:"skip_reason,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	Level           string `json:"level,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	LastScanID      string `json:"last_scan_id,omitempty"`
	LastScanAt      string `json:"last_scan_at,omitempty"`
}

func (h *StateHandler) listContainers(w http.ResponseWriter, _ *http.Request) {
	scans, err := h.Store.ListScans(1)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	if len(scans) == 0 {
		writeJSON(w, http.StatusOK, []containerView{})
		return
	}
	full, err := h.Store.GetScan(scans[0].ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errEnvelope(err))
		return
	}
	views := make([]containerView, 0, len(full.Results))
	scanAt := full.FinishedAt.UTC().Format(time.RFC3339)
	for _, r := range full.Results {
		views = append(views, containerView{
			ContainerID:     r.ContainerID,
			ContainerName:   r.ContainerName,
			Image:           r.Image,
			ComposeProject:  r.ComposeProject,
			Skipped:         r.Skipped,
			SkipReason:      r.SkipReason,
			UpdateAvailable: r.UpdateAvailable,
			Level:           r.Level.String(),
			From:            r.From,
			To:              r.To,
			LastScanID:      full.ID,
			LastScanAt:      scanAt,
		})
	}
	writeJSON(w, http.StatusOK, views)
}

// --- /api/v1/notifiers -------------------------------------------------------

type notifierView struct {
	ID       string `json:"id,omitempty"`
	Source   string `json:"source"`
	Name     string `json:"name"`
	MinLevel string `json:"min_level"`
}

func (h *StateHandler) listNotifiers(w http.ResponseWriter, _ *http.Request) {
	// Prefer the Registry when wired (it carries source-of-config
	// metadata so the dashboard can render UI-managed entries with
	// edit/delete buttons and yaml ones as read-only cards).
	if h.Registry != nil {
		entries := h.Registry.Entries()
		out := make([]notifierView, 0, len(entries))
		for _, e := range entries {
			out = append(out, notifierView{
				ID:       e.ID,
				Source:   string(e.Source),
				Name:     e.Notifier.Name(),
				MinLevel: e.Notifier.MinLevel().String(),
			})
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	notifs := h.Dispatcher.Notifiers()
	out := make([]notifierView, 0, len(notifs))
	for _, n := range notifs {
		out = append(out, notifierView{
			Source:   string(notifier.SourceYAML),
			Name:     n.Name(),
			MinLevel: n.MinLevel().String(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- /api/v1/config ----------------------------------------------------------

// getConfig returns the loaded YAML config rendered as JSON with every
// well-known credential field replaced by "***". The dashboard's
// Settings page renders this verbatim so operators can verify what
// the daemon actually sees without having to shell into the host to
// `cat bulwark.yaml`.
//
// Round-trip via yaml so the keys the dashboard sees match the
// snake_case the operator typed in the YAML, not Go's CamelCase
// field names. (The Config struct carries `yaml:` tags but no
// `json:` tags.)
func (h *StateHandler) getConfig(w http.ResponseWriter, _ *http.Request) {
	raw, err := yaml.Marshal(h.LoadedConfig)
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
	writeJSON(w, http.StatusOK, tree)
}

// --- /api/v1/policies --------------------------------------------------------

// getPolicies returns the effective classifier policy after merging
// defaults with config + overrides. The dashboard renders this so
// operators can see exactly what each tier maps to and which stacks /
// containers carry overrides without having to mentally merge YAML.
type policiesView struct {
	Classifier any `json:"classifier"`
	Overrides  any `json:"overrides"`
}

func (h *StateHandler) getPolicies(w http.ResponseWriter, _ *http.Request) {
	cfg := h.LoadedConfig
	if cfg == nil {
		writeJSON(w, http.StatusNotFound, errEnvelope(errors.New("config not loaded")))
		return
	}
	out := policiesView{
		Classifier: cfg.ClassifierConfig(),
		Overrides:  cfg.Overrides,
	}
	writeJSON(w, http.StatusOK, out)
}

// --- /api/v1/snapshots -------------------------------------------------------

type snapshotView struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (h *StateHandler) listSnapshots(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("target query parameter is required")))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	snaps, err := h.SnapshotBackend.List(ctx, target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errEnvelope(err))
		return
	}
	out := make([]snapshotView, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, snapshotView{
			ID:        s.ID,
			Target:    s.Target,
			Label:     s.Label,
			CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// testNotifier dispatches a synthetic event to one named channel. The
// Synthetic flag on the event bypasses MinLevel filtering so the test
// always reaches the channel regardless of its threshold.
func (h *StateHandler) testNotifier(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errEnvelope(errors.New("notifier name is required")))
		return
	}
	var target notifier.Notifier
	for _, n := range h.currentDispatcher().Notifiers() {
		if n.Name() == name {
			target = n
			break
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, errEnvelope(fmt.Errorf("no notifier named %q", name)))
		return
	}
	now := time.Now().UTC()
	event := notifier.Event{
		Container: "bulwark-notify-test",
		Image:     "example.com/test:notify",
		Risk:      types.RiskReview,
		Action:    types.ActionNeedsReview,
		Synthetic: true,
		Timestamp: now,
		Rationale: "Synthetic test event sent from the dashboard.",
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := target.Notify(ctx, []notifier.Event{event}); err != nil {
		writeJSON(w, http.StatusBadGateway, errEnvelope(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sent":      true,
		"notifier":  name,
		"timestamp": now.Format(time.RFC3339),
	})
}

// --- /api/v1/sessions --------------------------------------------------------

// getSession is the dashboard's "am I logged in?" probe. The handler
// only fires when h.authed() let the request through, so reaching here
// already means authenticated — the body just answers the secondary
// question of whether session-cookie endpoints (POST/DELETE) are
// usable. The SPA hides login/logout UX when they're not.
func (h *StateHandler) getSession(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":             true,
		"session_endpoints_enabled": h.Sessions != nil,
	})
}

// postSession validates the bootstrap credential (typically Bearer)
// and issues a fresh session cookie. Bearer tokens still work as
// always — issuing a cookie is purely additive and exists so the
// dashboard can authenticate without putting the token in localStorage
// (an XSS would otherwise leak it).
func (h *StateHandler) postSession(w http.ResponseWriter, r *http.Request) {
	if h.Sessions == nil {
		writeJSON(w, http.StatusNotFound, errEnvelope(ErrSessionsDisabled))
		return
	}
	inner := h.SessionInnerAuth
	if inner == nil {
		// Defensive: without an inner authenticator anyone can mint a
		// cookie. Refuse rather than degrade.
		writeJSON(w, http.StatusInternalServerError, errEnvelope(errors.New("api: session login has no inner authenticator")))
		return
	}
	if _, err := inner.Authenticate(r); err != nil {
		var ae *AuthError
		if errors.As(err, &ae) {
			writeJSON(w, ae.Status, errEnvelope(err))
			return
		}
		writeJSON(w, http.StatusUnauthorized, errEnvelope(err))
		return
	}
	value, exp := h.Sessions.Issue()
	http.SetCookie(w, h.Sessions.BuildCookie(value, exp, isSecureRequest(r)))
	writeJSON(w, http.StatusOK, map[string]any{
		"expires_at":  exp.UTC().Format(time.RFC3339),
		"ttl_seconds": int(time.Until(exp).Seconds()),
	})
}

// deleteSession clears the session cookie. Authenticated callers and
// callers presenting an expired cookie alike succeed — logout buttons
// must keep working when the session has timed out so the user can
// re-authenticate cleanly.
func (h *StateHandler) deleteSession(w http.ResponseWriter, _ *http.Request) {
	if h.Sessions == nil {
		writeJSON(w, http.StatusNotFound, errEnvelope(ErrSessionsDisabled))
		return
	}
	http.SetCookie(w, ClearCookie())
	w.WriteHeader(http.StatusNoContent)
}
