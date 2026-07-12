package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/reconcile"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// DigestResolver mirrors registry.Client minus everything we don't need —
// kept local to the api package so tests can inject stubs without dragging
// in the registry HTTP client's transport configuration.
type DigestResolver interface {
	Resolve(ctx context.Context, ref registry.Reference) (string, error)
}

// DockerInspector lets the handler look up the locally-running container
// matching the webhook's image reference. Optional — when absent we still
// honour the webhook but can't compare against a "current" digest.
type DockerInspector interface {
	ListContainers(ctx context.Context, all bool) ([]docker.Container, error)
	InspectImage(ctx context.Context, idOrRef string) (*docker.ImageInspect, error)
}

// DIUNHandler implements the http.Handler at POST /api/v1/webhooks/diun.
//
// All dependencies are exported so callers can wire production or test
// implementations transparently. Classifier is required; Registry and
// Docker are optional but strongly recommended (without Registry the
// classifier sees only the DIUN-supplied digest; without Docker we can't
// resolve the locally-running version to compare against).
type DIUNHandler struct {
	Classifier *classifier.Classifier
	Registry   DigestResolver
	Docker     DockerInspector
	Notifier   *notifier.Dispatcher
	Store      *store.Store
	Logger     *slog.Logger

	// Reconciler, when set, runs the trust engine reconcile (capture -> gate -> queue a
	// candidate for manual promotion) for a detected update whose local
	// container was matched. nil disables it (no behaviour change).
	Reconciler ReconcileTrigger

	// Token is an optional shared secret. When non-empty, requests must
	// supply it via either an `Authorization: Bearer <token>` header or a
	// custom `X-Bulwark-Token` header. Empty means anonymous access.
	Token string

	// HMAC, when configured with a non-empty secret, additionally requires
	// every request to carry an X-Bulwark-Timestamp + X-Bulwark-Signature
	// pair that authenticates the request body and a freshness window.
	// DIUN can't natively sign, but the bulwark-diun-relay sidecar
	// (cmd/bulwark-diun-relay) does — point DIUN at the relay and the
	// relay at this endpoint.
	HMAC *HMACScheme

	// DedupTTL is the silencing window applied when Store is populated.
	// Zero disables dedup; negative is treated as zero.
	DedupTTL time.Duration

	// Now is overrideable for deterministic tests; falls back to time.Now.
	Now func() time.Time
}

// ReconcileTrigger runs the trust engine reconcile for a detected update. *reconcile.Reconciler satisfies it.
type ReconcileTrigger interface {
	Reconcile(ctx context.Context, u reconcile.Update) (reconcile.Outcome, error)
}

// diunPayload is the subset of DIUN's webhook body Bulwark consumes. We
// ignore unknown fields by default (json.Decoder is permissive), so DIUN
// version drift doesn't break us.
type diunPayload struct {
	Status   string `json:"status"`
	Image    string `json:"image"`
	Digest   string `json:"digest"`
	Provider string `json:"provider"`
	HubLink  string `json:"hub_link"`
}

// diunResponse is the JSON envelope we return so DIUN logs and Bulwark
// debugging show useful context. We never echo the request's auth token
// or the configured shared secret.
type diunResponse struct {
	Received                bool   `json:"received"`
	Image                   string `json:"image,omitempty"`
	ContainerMatched        bool   `json:"container_matched"`
	ContainerName           string `json:"container_name,omitempty"`
	ClassificationPerformed bool   `json:"classification_performed"`
	Level                   string `json:"level,omitempty"`
	Kind                    string `json:"kind,omitempty"`
	Confidence              string `json:"confidence,omitempty"`
	Rationale               string `json:"rationale,omitempty"`
	Notifications           int    `json:"notifications_dispatched,omitempty"`
	Silenced                int    `json:"notifications_silenced,omitempty"`
	Note                    string `json:"note,omitempty"`
}

const maxDIUNBodyBytes = 1 << 16 // 64 KiB — webhooks should be well under this

// ServeHTTP implements http.Handler.
//
// Response codes:
//   - 200 OK on successful receipt (whether or not a notification was sent).
//   - 400 on malformed JSON or unparseable image reference.
//   - 401 when the shared secret is required but missing / wrong.
//   - 405 on non-POST methods (the ServeMux pattern guarantees POST in
//     production, but defending against direct dispatch keeps the contract
//     explicit).
//
// We deliberately return 200 even when the downstream notifier dispatch
// fails: DIUN retries on non-2xx, and one failing webhook shouldn't trigger
// a retry storm. The failure is recorded in the response body and stderr log.
func (h *DIUNHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := h.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Token != "" && !h.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Read the body in full BEFORE JSON-decode so HMAC verification (which
	// signs the raw bytes) can run on the same buffer the decoder will see.
	limited := http.MaxBytesReader(w, r.Body, maxDIUNBodyBytes)
	defer limited.Close()
	rawBody, err := io.ReadAll(limited)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, diunResponse{
			Received: false,
			Note:     "could not read request body: " + err.Error(),
		})
		return
	}

	if h.HMAC.Enabled() {
		ts := r.Header.Get("X-Bulwark-Timestamp")
		sig := r.Header.Get("X-Bulwark-Signature")
		if err := h.HMAC.Verify(ts, sig, rawBody); err != nil {
			// Don't echo the parse-error detail in the response — that
			// just helps an attacker probe which check failed. The
			// daemon log gets the full reason via the middleware.
			logger.Warn("diun: hmac verification failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var payload diunPayload
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, diunResponse{
			Received: false,
			Note:     "could not decode JSON body: " + err.Error(),
		})
		return
	}
	if payload.Image == "" {
		writeJSON(w, http.StatusBadRequest, diunResponse{
			Received: false,
			Note:     "image field is required",
		})
		return
	}

	ref, err := registry.Parse(payload.Image)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, diunResponse{
			Received: false,
			Image:    payload.Image,
			Note:     "could not parse image reference: " + err.Error(),
		})
		return
	}
	if payload.Digest != "" {
		ref.Digest = payload.Digest
	}

	resp := diunResponse{Received: true, Image: ref.String()}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}

	// --- Resolve the locally-running container's digest, if we can. -----
	current := types.ImageInfo{Repository: ref.FullName(), Tag: ref.Tag}
	available := types.ImageInfo{Repository: ref.FullName(), Tag: ref.Tag, Digest: payload.Digest}

	matched := h.findLocalContainer(r.Context(), ref)
	if matched != nil {
		resp.ContainerMatched = true
		resp.ContainerName = matched.Name
		if h.Docker != nil && matched.ImageID != "" {
			if insp, err := h.Docker.InspectImage(r.Context(), matched.ImageID); err == nil && insp != nil {
				current.Digest = insp.DigestFor(ref.FullName())
			}
		}
	}

	// If we couldn't determine the local digest (no Docker access, or the
	// image reference doesn't appear among local containers), classification
	// will still run but with low confidence. The classifier's existing
	// digest-only path handles this gracefully.
	if available.Digest == "" {
		// Fall back to the registry's current view so we have at least one
		// concrete digest to feed the classifier.
		if h.Registry != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			if d, err := h.Registry.Resolve(ctx, ref); err == nil {
				available.Digest = d
			}
			cancel()
		}
	}

	if h.Classifier == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	assessment, err := h.Classifier.Classify(r.Context(), current, available, nil)
	if err != nil {
		resp.Note = "classification error: " + err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.ClassificationPerformed = true
	resp.Level = assessment.Level.String()
	resp.Kind = assessment.Delta.Kind.String()
	resp.Confidence = assessment.Confidence.String()
	resp.Rationale = assessment.Rationale

	// --- Build a notifier event, dedup-filter, dispatch, mark sent. ------
	if h.Notifier != nil && len(h.Notifier.Notifiers()) > 0 {
		evt := notifier.Event{
			Container:      resp.ContainerName,
			Image:          payload.Image,
			Risk:           assessment.Level,
			From:           assessment.Delta.From,
			To:             assessment.Delta.To,
			Kind:           assessment.Delta.Kind,
			Confidence:     assessment.Confidence,
			Rationale:      assessment.Rationale,
			ReleaseURL:     assessment.ReleaseURL,
			LocalDigest:    current.Digest,
			RegistryDigest: available.Digest,
			Timestamp:      now().UTC(),
		}
		if matched != nil {
			evt.ComposeProject = matched.ComposeProject()
		}
		dedupKey := store.NotificationKey{
			ContainerID:    evt.Container,
			RegistryDigest: evt.RegistryDigest,
		}
		if h.Store != nil && h.DedupTTL > 0 {
			ok, err := h.Store.ShouldNotify(dedupKey, evt.Risk, now(), h.DedupTTL)
			if err != nil {
				logger.Warn("api: dedup check failed", "err", err)
			}
			if !ok {
				resp.Silenced = 1
				writeJSON(w, http.StatusOK, resp)
				return
			}
		}
		results := h.Notifier.Dispatch(r.Context(), []notifier.Event{evt})
		anyOK := false
		for _, r := range results {
			if r.Ok() && r.Sent > 0 {
				anyOK = true
				resp.Notifications += r.Sent
			}
		}
		if anyOK && h.Store != nil {
			meta := store.NotificationRecord{
				ContainerName: evt.Container,
				Image:         evt.Image,
				Level:         evt.Risk,
			}
			if err := h.Store.MarkNotified(dedupKey, meta, now()); err != nil {
				logger.Warn("api: could not mark notification as sent", "err", err)
			}
		}
		if !anyOK && len(results) > 0 {
			resp.Note = "all notification channels failed; not marking as delivered"
		}
	}

	// --- the trust engine reconcile hook (optional). When a Reconciler is wired and a local
	// container was matched (so stack + service are known), resolve the pinned
	// index digest for the detected update, run the trust gate, and queue a
	// verified update as a canary candidate for MANUAL promotion (an internal note).
	// Best-effort: a reconcile error is logged but never fails the webhook.
	if h.Reconciler != nil && matched != nil {
		out, rerr := h.Reconciler.Reconcile(r.Context(), reconcile.Update{
			Ref:     payload.Image,
			Stack:   matched.ComposeProject(),
			Service: resp.ContainerName,
			Source:  "diun",
		})
		if rerr != nil {
			logger.Warn("api: reconcile failed", "err", rerr)
		} else {
			logger.Info("api: reconcile", "key", out.Key, "decision", string(out.Decision), "queued", out.Queued, "held", out.Held)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// findLocalContainer looks for a running container whose image reference
// matches the webhook's. Returns nil if Docker is unavailable or no match
// is found.
func (h *DIUNHandler) findLocalContainer(ctx context.Context, want registry.Reference) *docker.Container {
	if h.Docker == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	containers, err := h.Docker.ListContainers(ctx, false)
	if err != nil {
		return nil
	}
	wantFull := want.FullName()
	wantTag := want.Tag
	for _, c := range containers {
		if c.Image == "" {
			continue
		}
		got, err := registry.Parse(c.Image)
		if err != nil {
			continue
		}
		if got.FullName() == wantFull && got.Tag == wantTag {
			c := c
			return &c
		}
	}
	return nil
}

// authOK validates the shared-secret header(s) using a constant-time compare
// so authorized vs. unauthorized requests can't be distinguished by timing.
func (h *DIUNHandler) authOK(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.Header.Get("X-Bulwark-Token")
	}
	if tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(h.Token)) == 1
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		// We've already written the status; the best we can do is silently
		// truncate. The middleware logs the duration, so a partial write
		// is still observable.
		_ = err
	}
}
