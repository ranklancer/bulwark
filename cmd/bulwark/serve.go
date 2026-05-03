package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bulwark-docker/bulwark/internal/api"
	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// serveDeps lets tests substitute every networked component. The non-nil
// fields override what the CLI would otherwise construct from flags/env.
type serveDeps struct {
	Docker    api.DockerInspector
	Registry  api.DigestResolver
	Notifiers []notifier.Notifier
	Store     *store.Store

	// Ctx, when non-nil, replaces the production signal.NotifyContext as
	// the parent context driving server shutdown. Tests cancel this to
	// drive a clean shutdown without sending real OS signals; production
	// leaves it nil so SIGINT/SIGTERM are honoured.
	Ctx context.Context
}

func cmdServe(args []string, stdout, stderr io.Writer) error {
	return cmdServeWith(args, stdout, stderr, serveDeps{})
}

// cmdServeWith runs the long-running HTTP server. SIGINT and SIGTERM trigger
// a graceful shutdown that drains in-flight requests up to a 30-second budget.
func cmdServeWith(args []string, stdout, stderr io.Writer, deps serveDeps) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark serve [flags]

Run Bulwark as a long-running HTTP server. Currently exposes:

  POST /api/v1/webhooks/diun     DIUN webhook receiver
  GET  /healthz, /readyz         liveness / readiness probes

SIGINT or SIGTERM trigger a graceful shutdown.

Flags:`)
		fs.PrintDefaults()
	}

	listen := fs.String("listen", ":8080", "HTTP listen address (host:port)")
	configPath := fs.String("config", "", "path to bulwark.yaml (optional)")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory for persistent state")
	dockerHost := fs.String("docker-host", "", "Docker socket path (default /var/run/docker.sock); empty disables Docker integration")
	noDocker := fs.Bool("no-docker", false, "do not connect to Docker (cross-host DIUN deployments)")
	diunToken := fs.String("diun-token", os.Getenv("BULWARK_DIUN_TOKEN"), "shared secret required on DIUN webhook requests")
	dedupTTL := fs.Duration("dedup-ttl", 24*time.Hour, "minimum interval between repeat notifications for the same (container, digest)")
	githubToken := fs.String("github-token", os.Getenv("BULWARK_GITHUB_TOKEN"), "GitHub PAT for higher rate limits when fetching release notes")
	verbose := fs.Bool("v", false, "verbose progress logging on stderr")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("serve: unexpected positional arguments")
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: levelFor(*verbose)}))

	// --- Config + classifier --------------------------------------------
	var loaded *config.Config
	cfg := classifier.DefaultConfig()
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		loaded = c
		cfg = loaded.ClassifierConfig()
		// YAML can override the listen address and DIUN token when the
		// flag wasn't explicitly set.
		if !flagPassed(fs, "listen") && loaded.API.Listen != "" {
			*listen = loaded.API.Listen
		}
		if !flagPassed(fs, "diun-token") && loaded.API.DIUN.Token != "" {
			*diunToken = loaded.API.DIUN.Token
		}
		if !flagPassed(fs, "dedup-ttl") && loaded.API.DIUN.DedupTTL != "" {
			if d, err := time.ParseDuration(loaded.API.DIUN.DedupTTL); err == nil {
				*dedupTTL = d
			} else {
				logger.Warn("serve: ignoring invalid api.diun.dedup_ttl", "value", loaded.API.DIUN.DedupTTL, "err", err)
			}
		}
	}

	// --- Persistent store (optional) ------------------------------------
	st := deps.Store
	if st == nil && *dataDir != "" {
		opened, err := store.Open(*dataDir)
		if err != nil {
			return fmt.Errorf("serve: open store: %w", err)
		}
		st = opened
		defer func() { _ = st.Close() }()
	}

	// --- Docker (optional) ----------------------------------------------
	var dockerClient api.DockerInspector
	switch {
	case deps.Docker != nil:
		dockerClient = deps.Docker
	case *noDocker:
		logger.Info("serve: --no-docker set, container matching disabled")
	default:
		dc := docker.New(*dockerHost)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := dc.Ping(ctx)
		cancel()
		if err != nil {
			logger.Warn("serve: Docker socket unreachable; running without container matching", "err", err)
		} else {
			dockerClient = dc
		}
	}

	// --- Registry -------------------------------------------------------
	regClient := deps.Registry
	if regClient == nil {
		c := registry.New()
		c.Auth = buildRegistryAuth(loaded, logger)
		regClient = c
	}
	_ = githubToken // wired in a future revision once release-notes lookup is added to the receiver

	// --- Notifier dispatcher --------------------------------------------
	notifiers := deps.Notifiers
	if notifiers == nil {
		built, err := notifier.FromConfig(loaded)
		if err != nil {
			logger.Warn("serve: some notification channels failed to construct", "err", err)
		}
		notifiers = built
	}
	dispatcher := notifier.NewDispatcher(notifiers, logger, 30*time.Second)

	// --- Wire DIUN handler ----------------------------------------------
	diun := &api.DIUNHandler{
		Classifier: classifier.New(cfg),
		Registry:   regClient,
		Docker:     dockerClient,
		Notifier:   dispatcher,
		Store:      st,
		Logger:     logger,
		Token:      *diunToken,
		HMAC:       buildDIUNHMAC(loaded),
		DedupTTL:   *dedupTTL,
	}

	auth, err := buildAuthenticator(loaded, *diunToken, logger)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	var sessions *api.SessionScheme
	wrappedAuth := auth
	if _, anon := auth.(api.AnonymousAuth); !anon {
		sessions, err = api.NewSessionScheme(0)
		if err != nil {
			return fmt.Errorf("serve: sessions: %w", err)
		}
		wrappedAuth = api.CookieOrInnerAuth{Inner: auth, Sessions: sessions}
	}
	state := &api.StateHandler{
		Store:            st,
		Logger:           logger,
		Auth:             wrappedAuth,
		Sessions:         sessions,
		SessionInnerAuth: auth,
		Dispatcher:       dispatcher,
		LoadedConfig:     loaded,
		SnapshotBackend:  buildSnapshotBackend(loaded, logger),
		Events:           api.NewEventBus(),
	}
	srv := api.NewServer(*listen, diun, state, api.DefaultRateLimiter(), api.NewMetrics(), logger)

	// Production: translate SIGINT/SIGTERM into context cancellation.
	// Tests: a parent context provided through deps.Ctx is used directly so
	// shutdown can be driven without sending real signals to the test process.
	var ctx context.Context
	var stop context.CancelFunc
	if deps.Ctx != nil {
		ctx, stop = context.WithCancel(deps.Ctx)
	} else {
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
	defer stop()

	logger.Info("serve: ready", "addr", *listen, "docker", dockerClient != nil, "notifiers", len(notifiers), "store", st != nil)
	if err := srv.Run(ctx, 30*time.Second); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	logger.Info("serve: shutdown complete")
	_ = stdout
	return nil
}

// flagPassed reports whether a flag was set on the command line. The stdlib
// flag package doesn't expose this directly; iterating Visit() is the
// canonical workaround.
func flagPassed(fs *flag.FlagSet, name string) bool {
	passed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			passed = true
		}
	})
	return passed
}
