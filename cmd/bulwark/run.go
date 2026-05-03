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
	"sync"
	"syscall"
	"time"

	"github.com/bulwark-docker/bulwark/internal/api"
	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/hooks"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/releasenotes"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/internal/scheduler"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/updater"
)

// runDeps lets tests substitute every networked component for `bulwark run`.
// Mirrors serveDeps with one extension: the Notes fetcher (used by the scan
// loop, never by the HTTP server).
type runDeps struct {
	Docker    api.DockerInspector
	Registry  api.DigestResolver
	Notes     scanner.NotesFetcher
	Notifiers []notifier.Notifier
	Store     *store.Store
	Updater   *updater.Updater

	// Ctx, when non-nil, replaces signal.NotifyContext as the parent context
	// driving daemon shutdown. Tests cancel this to drive clean shutdown
	// without sending real OS signals.
	Ctx context.Context

	// Now is overrideable for deterministic dedup tests. Defaults to time.Now.
	Now func() time.Time
}

func cmdRun(args []string, stdout, stderr io.Writer) error {
	return cmdRunWith(args, stdout, stderr, runDeps{})
}

// cmdRunWith is the production daemon. It runs two long-lived workers in
// parallel — a periodic scan scheduler and the HTTP server — and waits for
// either to exit (or the parent context to be cancelled), then drains both
// cleanly within a 30-second shutdown budget.
//
// SIGINT and SIGTERM trigger a graceful shutdown.
func cmdRunWith(args []string, stdout, stderr io.Writer, deps runDeps) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark run [flags]

Run Bulwark as a continuously-running daemon. Combines:

  - A periodic scan loop that enumerates local containers, checks the
    registry, classifies, dispatches notifications, and records history.
  - An HTTP server hosting the DIUN-compatible webhook receiver and
    health probes (same surface as `+"`bulwark serve`"+`).

SIGINT or SIGTERM trigger a graceful shutdown.

Flags:`)
		fs.PrintDefaults()
	}

	listen := fs.String("listen", ":8080", "HTTP listen address (host:port)")
	configPath := fs.String("config", "", "path to bulwark.yaml (optional)")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory for persistent state")
	dockerHost := fs.String("docker-host", "", "Docker socket path (default /var/run/docker.sock)")
	noDocker := fs.Bool("no-docker", false, "do not connect to Docker (cross-host DIUN deployments)")
	scanInterval := fs.Duration("scan-interval", 6*time.Hour, "interval between scheduled scans (0 disables periodic scanning); ignored when --cron is set")
	scanCron := fs.String("cron", "", `cron expression for the scan schedule (5 fields, e.g. "0 3 * * *"); takes precedence over --scan-interval`)
	noInitialScan := fs.Bool("no-initial-scan", false, "skip the immediate scan at startup")
	apply := fs.Bool("apply", false, "auto-apply qualifying updates (SAFE always, plus REVIEW updates approved via `bulwark queue approve`); BREAKING never auto-applies")
	dryRun := fs.Bool("dry-run", false, "with --apply, log what would be applied without actually pulling/recreating containers")
	healthTimeout := fs.Duration("health-timeout", 60*time.Second, "how long to wait for the recreated container to become healthy before rolling back")
	all := fs.Bool("all", false, "include stopped containers in scans")
	skipNotes := fs.Bool("no-fetch-notes", false, "skip GitHub release-notes fetch during scans")
	githubToken := fs.String("github-token", os.Getenv("BULWARK_GITHUB_TOKEN"), "GitHub PAT for higher rate limits")
	concurrency := fs.Int("concurrency", 4, "number of containers to inspect in parallel")
	diunToken := fs.String("diun-token", os.Getenv("BULWARK_DIUN_TOKEN"), "shared secret required on DIUN webhook requests")
	dedupTTL := fs.Duration("dedup-ttl", 24*time.Hour, "minimum interval between repeat notifications for the same (container, digest)")
	verbose := fs.Bool("v", false, "verbose progress logging on stderr")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("run: unexpected positional arguments")
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
		if !flagPassed(fs, "listen") && loaded.API.Listen != "" {
			*listen = loaded.API.Listen
		}
		if !flagPassed(fs, "diun-token") && loaded.API.DIUN.Token != "" {
			*diunToken = loaded.API.DIUN.Token
		}
		if !flagPassed(fs, "scan-interval") && loaded.Schedule.ScanInterval != "" {
			if d, err := time.ParseDuration(loaded.Schedule.ScanInterval); err == nil {
				*scanInterval = d
			} else {
				logger.Warn("run: ignoring invalid schedule.scan_interval", "value", loaded.Schedule.ScanInterval, "err", err)
			}
		}
		if !flagPassed(fs, "cron") && loaded.Schedule.Check != "" {
			*scanCron = loaded.Schedule.Check
		}
	}

	// --- Persistent store (optional) ------------------------------------
	st := deps.Store
	if st == nil && *dataDir != "" {
		opened, err := store.Open(*dataDir)
		if err != nil {
			return fmt.Errorf("run: open store: %w", err)
		}
		st = opened
		defer func() { _ = st.Close() }()
	}

	// --- Docker (optional but normally required for the scan loop) ------
	var dockerClient api.DockerInspector
	switch {
	case deps.Docker != nil:
		dockerClient = deps.Docker
	case *noDocker:
		logger.Warn("run: --no-docker set; periodic scan loop will be disabled")
	default:
		dc := docker.New(*dockerHost)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := dc.Ping(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("run: %w", err)
		}
		dockerClient = dc
	}

	// --- Registry + release-notes fetcher -------------------------------
	regClient := deps.Registry
	if regClient == nil {
		c := registry.New()
		c.Auth = buildRegistryAuth(loaded, logger)
		regClient = c
	}
	var notesFetcher scanner.NotesFetcher
	switch {
	case deps.Notes != nil:
		notesFetcher = deps.Notes
	case !*skipNotes:
		f := releasenotes.NewFetcher()
		f.GitHub.Token = *githubToken
		notesFetcher = f
	}

	// --- Notifier dispatcher --------------------------------------------
	notifiers := deps.Notifiers
	if notifiers == nil {
		built, err := notifier.FromConfig(loaded)
		if err != nil {
			logger.Warn("run: some notification channels failed to construct", "err", err)
		}
		notifiers = built
	}
	dispatcher := notifier.NewDispatcher(notifiers, logger, 30*time.Second)

	// Live-events bus for the dashboard's SSE stream.
	eventBus := api.NewEventBus()

	// --- Digest mode (optional) ----------------------------------------
	// When notifications.digest.enabled is true in the YAML, non-urgent
	// events (everything except BREAKING / rolled-back / stack-skipped /
	// synthetic) are queued into a buffer and flushed on a separate
	// cron schedule. Default schedule is "0 8 * * *" — one digest at
	// 08:00 local time. Operators who don't configure digest get the
	// classic immediate-dispatch behaviour.
	var (
		digestBuf      *notifier.DigestBuffer
		digestSchedule *scheduler.CronSchedule
	)
	if loaded != nil && loaded.Notifications.Digest.Enabled {
		expr := loaded.Notifications.Digest.Schedule
		if expr == "" {
			expr = "0 8 * * *"
		}
		parsed, err := scheduler.ParseCron(expr)
		if err != nil {
			logger.Warn("run: digest disabled — invalid cron expression",
				"expr", expr, "err", err)
		} else {
			digestSchedule = parsed
			digestBuf = notifier.NewDigestBuffer()
		}
	}

	// --- Build the scan job that the scheduler will invoke periodically.
	// Important: each invocation gets a fresh scanner.Scanner so the Docker
	// listing is re-fetched every cycle (containers come and go).
	//
	// The api.DockerInspector and scanner.DockerLister interfaces have the
	// same shape; Go's structural typing lets us pass dockerClient directly
	// to the scanner without an adapter — but only if it's non-nil. With
	// --no-docker, dockerClient is nil and we skip scheduling.
	// If --apply is set we need a concrete *docker.Client (write methods).
	// Tests inject deps.Updater; production constructs one when dockerClient
	// is the real *docker.Client we built earlier.
	var upd *updater.Updater
	if *apply {
		if dc, ok := dockerClient.(*docker.Client); ok {
			snapBackend := buildSnapshotBackend(loaded, logger)
			upd = &updater.Updater{
				Docker:        dc,
				Snapshots:     snapBackend,
				Hooks:         hooks.ExecRunner{HooksRoot: hooksRoot(loaded)},
				Logger:        logger,
				HealthTimeout: *healthTimeout,
			}
		} else if deps.Updater != nil {
			upd = deps.Updater
		} else {
			return errors.New("run: --apply requires a real Docker client (or an injected updater for tests)")
		}
	}

	scanJob := func(ctx context.Context) error {
		if dockerClient == nil {
			return nil
		}
		scn := &scanner.Scanner{
			Docker:      dockerClient,
			Registry:    regClient,
			Notes:       notesFetcher,
			Classifier:  classifier.New(cfg),
			Config:      loaded,
			Concurrency: *concurrency,
		}
		cycle, err := runScanCycle(ctx, scanCycleConfig{
			Scanner:            scn,
			Dispatcher:         dispatcher,
			Store:              st,
			DedupTTL:           *dedupTTL,
			Updater:            upd,
			Apply:              *apply,
			DryRun:             *dryRun,
			MaintenanceWindows: parseMaintenanceWindows(loaded, logger),
			DigestBuffer:       digestBuf,
			Events:             eventBus,
			Now:                deps.Now,
			Logger:             logger,
			All:                *all,
		})
		if err != nil {
			return err
		}
		// Compact summary line — useful in journalctl, painful in
		// stdout-as-prometheus-source-of-truth setups, so it's just one
		// line per cycle.
		pending, breaking, review, safe := summarize(cycle.Results)
		logger.Info("run: scan cycle complete",
			"results", len(cycle.Results),
			"pending", pending,
			"breaking", breaking,
			"review", review,
			"safe", safe,
			"silenced", cycle.DedupSilenced,
			"digest_queued", cycle.DigestQueued,
		)
		return nil
	}

	// digestJob is the cron-driven flush that runs in its own scheduler
	// goroutine when digest mode is configured.
	digestJob := func(ctx context.Context) error {
		when := time.Now().UTC()
		if deps.Now != nil {
			when = deps.Now().UTC()
		}
		flushDigest(ctx, digestBuf, dispatcher, st, when, logger)
		return nil
	}

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
		Now:        deps.Now,
	}
	auth, err := buildAuthenticator(loaded, *diunToken, logger)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	// Sessions are enabled whenever the inner authenticator is anything
	// stronger than AnonymousAuth — there's nothing to protect on a
	// fully-anonymous deployment, and minting cookies in that case would
	// only confuse operators.
	var sessions *api.SessionScheme
	wrappedAuth := auth
	if _, anon := auth.(api.AnonymousAuth); !anon {
		sessions, err = api.NewSessionScheme(0)
		if err != nil {
			return fmt.Errorf("run: sessions: %w", err)
		}
		wrappedAuth = api.CookieOrInnerAuth{Inner: auth, Sessions: sessions}
	}
	state := &api.StateHandler{
		Store:            st,
		Logger:           logger,
		Auth:             wrappedAuth,
		Sessions:         sessions,
		SessionInnerAuth: auth, // bare; cookie can't renew itself
		TriggerScan:      scanJob, // POST /api/v1/scans queue-jumps the next periodic firing
		Dispatcher:       dispatcher,
		LoadedConfig:     loaded,
		SnapshotBackend:  buildSnapshotBackend(loaded, logger),
		Events:           eventBus,
	}
	srv := api.NewServer(*listen, diun, state, api.DefaultRateLimiter(), api.NewMetrics(), logger)

	// --- Set up parent context (signals or injected) --------------------
	var ctx context.Context
	var stop context.CancelFunc
	if deps.Ctx != nil {
		ctx, stop = context.WithCancel(deps.Ctx)
	} else {
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
	defer stop()

	var cronSchedule *scheduler.CronSchedule
	if *scanCron != "" {
		parsed, err := scheduler.ParseCron(*scanCron)
		if err != nil {
			return fmt.Errorf("run: invalid cron expression %q: %w", *scanCron, err)
		}
		cronSchedule = parsed
	}

	scheduleDescr := scanInterval.String()
	if cronSchedule != nil {
		scheduleDescr = "cron " + cronSchedule.String()
	}
	logger.Info("run: ready",
		"listen", *listen,
		"docker", dockerClient != nil,
		"notifiers", len(notifiers),
		"store", st != nil,
		"schedule", scheduleDescr,
	)

	// --- Run scheduler + HTTP server in parallel ------------------------
	var (
		wg           sync.WaitGroup
		serverErrCh  = make(chan error, 1)
		schedulerErr error
	)

	if dockerClient != nil && (cronSchedule != nil || *scanInterval > 0) {
		sch := &scheduler.Scheduler{
			Interval:       *scanInterval,
			Cron:           cronSchedule,
			RunImmediately: !*noInitialScan,
			Job:            scanJob,
			Logger:         logger,
			Name:           "run/scheduler",
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sch.Run(ctx)
			// context.Canceled on shutdown isn't a real error — surface only
			// genuine failures.
			if err != nil && !errors.Is(err, context.Canceled) {
				schedulerErr = err
				stop() // bring down the server too
			}
		}()
	}

	// Digest scheduler runs only when digest mode was successfully
	// configured. Failures here downgrade to "no digest" rather than
	// taking the whole daemon down — the buffer simply accumulates
	// until restart, at which point the next config load gets another
	// shot at parsing the cron expression.
	if digestSchedule != nil && digestBuf != nil {
		dsch := &scheduler.Scheduler{
			Cron:   digestSchedule,
			Job:    digestJob,
			Logger: logger,
			Name:   "run/digest",
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dsch.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("run: digest scheduler stopped", "err", err)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErrCh <- srv.Run(ctx, 30*time.Second)
	}()

	wg.Wait()
	srvErr := <-serverErrCh

	switch {
	case srvErr != nil:
		return fmt.Errorf("run: server: %w", srvErr)
	case schedulerErr != nil:
		return fmt.Errorf("run: scheduler: %w", schedulerErr)
	}
	logger.Info("run: shutdown complete")
	_ = stdout
	return nil
}

// summarize collapses scan results into the four counters the daemon log line
// surfaces. It mirrors writeScanText's bookkeeping but without the rendering.
func summarize(results []scanner.Result) (pending, breaking, review, safe int) {
	for _, r := range results {
		if r.Skipped || r.Err != nil || !r.HasUpdate() || r.Assessment == nil {
			continue
		}
		pending++
		switch r.Assessment.Level.String() {
		case "breaking":
			breaking++
		case "review":
			review++
		case "safe":
			safe++
		}
	}
	return
}
