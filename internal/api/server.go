// Package api hosts the long-running HTTP surface of Bulwark. The first
// endpoint exposed is the DIUN webhook receiver: existing DIUN deployments
// can post update notifications here and Bulwark becomes the "brain" that
// classifies, dispatches notifications, and (in a later phase) orchestrates
// the update pipeline. The Server type is also the foundation for the
// eventual web UI's API.
//
// The package is built with Go 1.22's enhanced http.ServeMux pattern syntax
// (method + path) so we don't need a third-party router for the small set
// of routes Bulwark serves.
package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/api/ui"
	uireact "github.com/bulwark-docker/bulwark/internal/api/ui-react"
)

// Server wraps an http.Server with Bulwark-specific lifecycle helpers.
type Server struct {
	HTTPServer *http.Server
	Logger     *slog.Logger
}

// NewServer wires the routes onto a fresh ServeMux and returns a Server
// listening on addr. Routes registered:
//
//	POST /api/v1/webhooks/diun     DIUN webhook receiver (when DIUNHandler is non-nil)
//	GET  /healthz                  liveness probe
//	GET  /readyz                   readiness probe
//	{state endpoints}              when StateHandler is non-nil — see StateHandler.Register
//
// limiter, when non-nil, wraps every request — including the dashboard,
// the API, and the DIUN webhook. nil disables rate limiting. The /healthz
// and /readyz probes are NOT exempt by design — a flooding load balancer
// is exactly the kind of thing the limiter exists to bound.
//
// metrics, when non-nil, exposes Prometheus-format counters at /metrics
// AND records request counts via the same handler chain. nil omits the
// route entirely.
func NewServer(addr string, diun *DIUNHandler, state *StateHandler, limiter *RateLimiter, metrics *Metrics, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleHealth)
	if metrics != nil {
		mux.Handle("GET /metrics", metrics)
	}
	if diun != nil {
		mux.Handle("POST /api/v1/webhooks/diun", diun)
	}
	if state != nil {
		state.Register(mux)
	}

	// Embedded dashboard. Mount at "/" so users hitting the daemon's
	// listener with a browser get something useful by default. The UI is
	// purely a client-side renderer over /api/v1/* — no extra surface.
	mountUI(mux, logger)

	var rootHandler http.Handler = mux
	if limiter != nil {
		rootHandler = limiter.Middleware(rootHandler)
	}

	return &Server{
		HTTPServer: &http.Server{
			Addr:              addr,
			Handler:           withLogging(rootHandler, logger),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       90 * time.Second,
		},
		Logger: logger,
	}
}

// Run starts the server and blocks until ctx is cancelled or the server
// errors. On context cancellation, in-flight requests are given up to
// shutdownTimeout to drain before the listener is closed forcibly.
func (s *Server) Run(ctx context.Context, shutdownTimeout time.Duration) error {
	listener, err := net.Listen("tcp", s.HTTPServer.Addr)
	if err != nil {
		return fmt.Errorf("api: listen %s: %w", s.HTTPServer.Addr, err)
	}
	s.Logger.Info("api: listening", "addr", listener.Addr().String())

	errCh := make(chan error, 1)
	go func() {
		err := s.HTTPServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.Logger.Info("api: shutdown requested, draining in-flight requests")
		if shutdownTimeout <= 0 {
			shutdownTimeout = 30 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.HTTPServer.Shutdown(shutdownCtx); err != nil {
			s.Logger.Warn("api: shutdown error", "err", err)
			return err
		}
		// Wait for Serve to return so we know shutdown completed cleanly.
		return <-errCh
	}
}

// withLogging is a middleware that emits one structured log line per request.
// It deliberately does NOT log full URLs or headers — webhook URLs and auth
// tokens often appear there, and logs end up grep-able and shippable.
//
// /healthz and /readyz are skipped: they fire every 5–30 s in production
// and dominate the access log without carrying any operator-relevant
// signal. Real probe failures still surface via the response status that
// the calling load balancer sees.
func withLogging(h http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		logger.Info("api: handled",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// uiCSP is the Content-Security-Policy header used by all UI routes.
// 'unsafe-inline' for script/style accommodates both the legacy
// dashboard's inlined JS/CSS and shadcn's CSS-vars-on-<style>-tags
// pattern. connect-src 'self' restricts the dashboard's fetches to
// the same origin (the /api/v1/* surface).
var uiCSP = strings.Join([]string{
	"default-src 'none'",
	"script-src 'self' 'unsafe-inline'",
	"style-src 'self' 'unsafe-inline'",
	"connect-src 'self'",
	"img-src 'self' data:",
	"font-src 'self' data:",
	"frame-ancestors 'none'",
}, "; ")

// mountUI wires the embedded dashboard onto mux. Two modes:
//
//   - When the React SPA has been built (`cd web && npm run build`
//     replaces internal/api/ui-react/dist/index.html with a real
//     Vite artifact), the SPA is served at GET /, its bundled assets
//     under GET /assets/, and the legacy vanilla dashboard moves to
//     GET /legacy/{$} for one release as a safety net.
//   - When the React dist is just the placeholder (operators running
//     a from-source build without npm), the legacy vanilla dashboard
//     keeps serving GET / unchanged. No new mount points appear.
//
// Detection is via uireact.IsBuilt() which checks for the placeholder
// marker in the embedded index.html.
func mountUI(mux *http.ServeMux, logger *slog.Logger) {
	uiSub, err := fs.Sub(ui.FS(), ".")
	if err != nil {
		logger.Warn("api: could not initialise embedded UI", "err", err)
		return
	}
	legacyIndex, err := fs.ReadFile(uiSub, "index.html")
	if err != nil {
		logger.Warn("api: embedded index.html missing", "err", err)
		return
	}

	var (
		reactSub   fs.FS
		reactIndex []byte
	)
	if uireact.IsBuilt() {
		sub, err := uireact.Sub()
		if err != nil {
			logger.Warn("api: react ui sub-fs failed; falling back to legacy", "err", err)
		} else if idx, err := fs.ReadFile(sub, "index.html"); err != nil {
			logger.Warn("api: react index.html unreadable; falling back to legacy", "err", err)
		} else {
			reactSub = sub
			reactIndex = idx
		}
	}
	mountUIRoutes(mux, legacyIndex, reactSub, reactIndex)
}

// mountUIRoutes is the testable inner helper. When reactSub + reactIndex
// are both non-nil, the React SPA mounts at "/", its hashed assets at
// "/assets/", and the legacy dashboard moves to "/legacy/{$}". Otherwise
// the legacy dashboard stays at "/" with no other mount points.
//
// Every UI route is wrapped in compressMiddleware so the SPA bundle goes
// out as brotli or gzip on the wire. API routes are deliberately NOT
// compressed in this phase because the SSE stream at /api/v1/events
// would buffer badly under encoding.
func mountUIRoutes(mux *http.ServeMux, legacyIndex []byte, reactSub fs.FS, reactIndex []byte) {
	legacyHandler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", uiCSP)
		_, _ = w.Write(legacyIndex)
	}))

	if reactSub == nil || reactIndex == nil {
		mux.Handle("GET /{$}", legacyHandler)
		return
	}

	preloadHeader := preloadLinkHeader(reactIndex)
	indexHandler := compressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// modulepreload tells the browser to start fetching the entry
		// chunk in parallel with HTML parse, saving an RTT on cold
		// loads. Empty when the placeholder index is in play.
		if preloadHeader != "" {
			w.Header().Set("Link", preloadHeader)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", uiCSP)
		_, _ = w.Write(reactIndex)
	}))
	mux.Handle("GET /{$}", indexHandler)
	// Hashed-asset file server. Vite-emitted filenames carry a content
	// hash, so a year of immutable Cache-Control is correct + safe.
	mux.Handle("GET /assets/", compressMiddleware(cacheImmutable(http.FileServer(http.FS(reactSub)))))
	mux.Handle("GET /legacy/{$}", legacyHandler)
}

// preloadScriptRE captures the src of the entry-point script tag Vite
// emits into index.html. The shape is stable across Vite versions:
//
//	<script type="module" crossorigin src="/assets/index-XXXXXXXX.js"></script>
//
// A regex is enough — there's exactly one such tag per build, and
// pulling in an HTML parser for this would be wasteful.
var preloadScriptRE = regexp.MustCompile(`<script[^>]*\bsrc="(/assets/[^"]+\.js)"`)

// preloadLinkHeader returns the value to set in the response Link
// header so the browser begins fetching the SPA's entry chunk in
// parallel with HTML parse. Returns "" when no entry script is found
// (e.g. the placeholder index ships nothing to preload).
func preloadLinkHeader(indexHTML []byte) string {
	m := preloadScriptRE.FindSubmatch(indexHTML)
	if len(m) < 2 {
		return ""
	}
	return "<" + string(m[1]) + ">; rel=modulepreload"
}

// cacheImmutable wraps a file-server handler with a long-lived
// Cache-Control header suitable for content-addressed asset filenames.
// Browsers treat "immutable" as "never revalidate within max-age".
func cacheImmutable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		next.ServeHTTP(w, r)
	})
}
