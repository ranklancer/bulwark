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
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/api/ui"
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
func NewServer(addr string, diun *DIUNHandler, state *StateHandler, limiter *RateLimiter, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleHealth)
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
func withLogging(h http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
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

// mountUI wires the embedded dashboard onto mux. We serve only "/" (so the
// route doesn't shadow the API namespace) and rely on the dashboard's JS
// to fetch /api/v1/*. A future build that ships static assets (CSS, JS,
// fonts) under a /ui/ prefix will mount those there separately.
func mountUI(mux *http.ServeMux, logger *slog.Logger) {
	uiSub, err := fs.Sub(ui.FS(), ".")
	if err != nil {
		logger.Warn("api: could not initialise embedded UI", "err", err)
		return
	}
	indexBytes, err := fs.ReadFile(uiSub, "index.html")
	if err != nil {
		logger.Warn("api: embedded index.html missing", "err", err)
		return
	}
	// "GET /{$}" matches only the literal root path; without {$} the pattern
	// would be a subtree wildcard and shadow every unmounted GET path,
	// turning genuine 404s into 200s and confusing 405 responses on other
	// methods.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// Strict-ish CSP: scripts and styles inline (we ship them inline
		// in index.html), connect-src self for the /api/v1/* fetches.
		w.Header().Set("Content-Security-Policy",
			strings.Join([]string{
				"default-src 'none'",
				"script-src 'self' 'unsafe-inline'",
				"style-src 'self' 'unsafe-inline'",
				"connect-src 'self'",
				"img-src 'self' data:",
				"frame-ancestors 'none'",
			}, "; "))
		_, _ = w.Write(indexBytes)
	})
}
