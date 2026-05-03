// bulwark-diun-relay is a tiny sidecar that bridges DIUN's plain webhook
// emitter to Bulwark's HMAC-protected /api/v1/webhooks/diun endpoint.
//
// DIUN's notification config supports custom HTTP headers but cannot
// compute an HMAC over the body. The relay sits between them: it accepts
// DIUN's vanilla POST, signs the body with the shared secret, and
// forwards to Bulwark with the X-Bulwark-Timestamp + X-Bulwark-Signature
// headers Bulwark expects.
//
// The relay is single-binary, stdlib-only, and idempotent. It does NOT
// retry on Bulwark's behalf; DIUN already retries on non-2xx, and so
// will the relay's own caller. Failed forwards return the upstream
// status verbatim.
//
// Usage:
//
//	bulwark-diun-relay \
//	  --listen :8090 \
//	  --upstream https://bulwark.example.com/api/v1/webhooks/diun \
//	  --secret-file /run/secrets/diun_hmac_secret
//
// Or via env vars: BULWARK_RELAY_LISTEN, BULWARK_RELAY_UPSTREAM,
// BULWARK_RELAY_SECRET_FILE, BULWARK_RELAY_BEARER (forwarded as
// Authorization: Bearer when set).
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxBodyBytes = 1 << 16 // 64 KiB; matches Bulwark's MaxDIUNBody

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("bulwark-diun-relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", envOr("BULWARK_RELAY_LISTEN", ":8090"), "address to listen on")
	upstream := fs.String("upstream", envOr("BULWARK_RELAY_UPSTREAM", ""), "Bulwark webhook URL (e.g. https://bulwark.example.com/api/v1/webhooks/diun)")
	secretFile := fs.String("secret-file", envOr("BULWARK_RELAY_SECRET_FILE", ""), "path to a file containing the HMAC shared secret")
	bearer := fs.String("bearer", os.Getenv("BULWARK_RELAY_BEARER"), "optional Authorization: Bearer token forwarded to Bulwark")
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage")
	}
	if *upstream == "" {
		return errors.New("--upstream is required")
	}
	if *secretFile == "" {
		return errors.New("--secret-file is required")
	}
	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		return fmt.Errorf("read secret file: %w", err)
	}
	secret = bytes.TrimSpace(secret)
	if len(secret) == 0 {
		return errors.New("secret file is empty")
	}

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: logLevel}))

	h := &relayHandler{
		Upstream: *upstream,
		Secret:   secret,
		Bearer:   *bearer,
		Logger:   logger,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("POST /", h)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	logger.Info("relay: listening", "addr", *listen, "upstream", redactURL(*upstream))
	_ = stdout

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return <-errCh
	}
}

type relayHandler struct {
	Upstream string
	Secret   []byte
	Bearer   string
	Logger   *slog.Logger
	Client   *http.Client
}

func (h *relayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "could not read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Sign body with the canonical "<timestamp>.<body>" envelope.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, h.Secret)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.Upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build upstream request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Forward DIUN's content type unchanged (defaults to JSON).
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Bulwark-Timestamp", ts)
	req.Header.Set("X-Bulwark-Signature", sig)
	if h.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+h.Bearer)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		// Strip the upstream URL from the error so secrets/auth-bearing
		// hosts don't end up in DIUN's retry logs.
		msg := strings.ReplaceAll(err.Error(), h.Upstream, "<upstream>")
		http.Error(w, "forward to bulwark failed: "+msg, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Mirror status + small body so DIUN's logs show what happened.
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4*1024))
	if h.Logger != nil {
		h.Logger.Info("relay: forwarded", "upstream_status", resp.StatusCode, "body_bytes", len(body))
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// redactURL keeps the host visible (useful for log triage) but strips any
// userinfo a misconfigured operator might have embedded in the URL.
func redactURL(u string) string {
	if i := strings.Index(u, "@"); i > 0 && strings.HasPrefix(u, "http") {
		// "https://user:pass@host/path" → "https://<redacted>@host/path"
		schemeEnd := strings.Index(u, "://")
		if schemeEnd >= 0 && schemeEnd < i {
			return u[:schemeEnd+3] + "<redacted>" + u[i:]
		}
	}
	return u
}
