package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/configstore"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/hooks"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/releasenotes"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/internal/snapshot"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/updater"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// scanDeps lets tests substitute the network-touching components. Production
// leaves all fields nil and cmdScan constructs real clients.
type scanDeps struct {
	Docker       scanner.DockerLister
	Registry     scanner.DigestResolver
	Notes        scanner.NotesFetcher
	Notifiers    []notifier.Notifier    // overrides FromConfig when non-nil
	Store        *store.Store           // overrides --data-dir when non-nil
	Updater      *updater.Updater       // overrides Updater construction when --apply is set
	DigestBuffer *notifier.DigestBuffer // optional digest buffer for tests; production wiring happens in `bulwark run`
	Now          func() time.Time       // for deterministic dedup tests; defaults to time.Now
}

// cmdScan implements `bulwark scan`. It enumerates the containers on the
// local Docker daemon, asks the registry whether the pinned tag's digest has
// moved, fetches release notes when a change is detected, and prints the
// classifier's verdict per container.
func cmdScan(args []string, stdout, stderr io.Writer) error {
	return cmdScanWith(args, stdout, stderr, scanDeps{})
}

func cmdScanWith(args []string, stdout, stderr io.Writer, deps scanDeps) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark scan [flags]

Enumerates the local Docker daemon's containers, resolves each pinned tag's
current digest in the registry, and classifies the resulting update (if any).

Flags:`)
		fs.PrintDefaults()
	}

	dockerHost := fs.String("docker-host", "", "Docker socket path (default /var/run/docker.sock)")
	configPath := fs.String("config", "", "path to bulwark.yaml (optional)")
	all := fs.Bool("all", false, "include stopped containers")
	jsonOut := fs.Bool("json", false, "emit JSON instead of human-readable text")
	skipNotes := fs.Bool("no-fetch-notes", false, "skip GitHub release-notes fetch")
	githubTokenDefault, err := config.SecretEnv("BULWARK_GITHUB_TOKEN")
	if err != nil {
		return err
	}
	githubToken := fs.String("github-token", githubTokenDefault, "GitHub PAT for higher rate limits")
	concurrency := fs.Int("concurrency", 4, "number of containers to inspect in parallel")
	noColor := fs.Bool("no-color", false, "disable ANSI colour codes in text output")
	notify := fs.Bool("notify", false, "after scanning, dispatch notifications to channels enabled in config")
	apply := fs.Bool("apply", false, "auto-apply qualifying updates: SAFE always, plus REVIEW updates that have been approved via `bulwark queue approve`. BREAKING never auto-applies.")
	dryRun := fs.Bool("dry-run", false, "with --apply, log what would be applied without actually pulling/recreating containers")
	healthTimeout := fs.Duration("health-timeout", 60*time.Second, "how long to wait for the recreated container to become healthy before rolling back")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory for persistent state (notification dedup, scan history)")
	dedupTTL := fs.Duration("dedup-ttl", 24*time.Hour, "minimum interval between repeat notifications for the same (container, digest) pair")
	verbose := fs.Bool("v", false, "verbose progress logging on stderr")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("scan: unexpected positional arguments")
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: levelFor(*verbose)}))

	// --- Wire up the classifier from config ----------------------------------
	var loaded *config.Config
	cfg := classifier.DefaultConfig()
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		loaded = c
		cfg = loaded.ClassifierConfig()
		if !flagPassed(fs, "docker-host") && loaded.Docker.Host != "" {
			*dockerHost = loaded.Docker.Host
		}
	}

	// --- Wire up dependencies ------------------------------------------------
	dockerClient := deps.Docker
	if dockerClient == nil {
		dc := docker.New(*dockerHost)
		// Fail fast with a clean error message if the socket is unreachable.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := dc.Ping(ctx)
		cancel()
		if err != nil {
			return err
		}
		dockerClient = dc
	}

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

	// --- Wire up the persistent store (optional) ----------------------------
	now := time.Now
	if deps.Now != nil {
		now = deps.Now
	}
	st := deps.Store
	if st == nil && *dataDir != "" {
		opened, err := store.Open(*dataDir)
		if err != nil {
			return fmt.Errorf("scan: open store: %w", err)
		}
		st = opened
		defer func() { _ = st.Close() }()
	}

	cveSource, cveThreshold, cveErr := buildCVESource(loaded)
	if cveErr != nil {
		return fmt.Errorf("scan: %w", cveErr)
	}
	scn := &scanner.Scanner{
		Docker:       dockerClient,
		Registry:     regClient,
		Notes:        notesFetcher,
		Classifier:   classifier.New(cfg),
		Config:       loaded,
		Concurrency:  *concurrency,
		CVE:          cveSource,
		CVEThreshold: cveThreshold,
	}

	var dispatcher *notifier.Dispatcher
	if *notify {
		notifiers := deps.Notifiers
		if notifiers == nil {
			built, err := notifier.FromConfig(loaded)
			if err != nil {
				// Per FromConfig's contract, partial successes are returned
				// alongside the error — log and proceed with what we got.
				logger.Warn("some notification channels failed to construct", "err", err)
			}
			notifiers = built
		}
		if len(notifiers) == 0 {
			logger.Warn("--notify requested but no notification channels are configured")
		} else {
			dispatcher = notifier.NewDispatcher(notifiers, logger, 30*time.Second)
		}
	}

	var upd *updater.Updater
	if *apply {
		// dockerClient is api.DockerInspector / scanner.DockerLister — for
		// apply we also need the write methods, which only the concrete
		// *docker.Client provides. Production paths construct a real client
		// when --apply is set; tests inject one via deps.
		if dc, ok := dockerClient.(*docker.Client); ok {
			// scan.go's one-shot CLI doesn't have a daemon-owned
			// configstore; pass nil so only yaml is consulted.
			snapBackend := buildSnapshotBackend(loaded, nil, logger)
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
			return errors.New("scan: --apply requires a real Docker client; pass --docker-host or run inside a container with the socket mounted")
		}
	}

	logger.Info("starting scan", "all", *all, "concurrency", *concurrency, "store", st != nil, "apply", *apply, "dry_run", *dryRun)
	cycle, err := runScanCycle(context.Background(), scanCycleConfig{
		Scanner:            scn,
		Dispatcher:         dispatcher,
		Store:              st,
		DedupTTL:           *dedupTTL,
		Updater:            upd,
		Apply:              *apply,
		DryRun:             *dryRun,
		MaintenanceWindows: parseMaintenanceWindows(loaded, logger),
		DigestBuffer:       deps.DigestBuffer,
		Now:                now,
		Logger:             logger,
		All:                *all,
	})
	if err != nil {
		return err
	}
	results := cycle.Results
	dispatchResults := cycle.Dispatch
	dedupSilenced := cycle.DedupSilenced
	approvalSilenced := cycle.ApprovalSilenced

	if *jsonOut {
		return writeScanJSON(stdout, results, dispatchResults)
	}
	if err := writeScanText(stdout, results, !*noColor && isLikelyTTY(stdout)); err != nil {
		return err
	}
	if len(dispatchResults) > 0 || dedupSilenced > 0 || approvalSilenced > 0 {
		writeDispatchSummary(stdout, dispatchResults, dedupSilenced, approvalSilenced)
	}
	return nil
}

// filterByDedup removes events the store says we've already notified about
// (within the TTL). It returns the kept events and the count of silenced ones.
// A nil store is the no-op (dedup disabled).
func filterByDedup(st *store.Store, events []notifier.Event, now time.Time, ttl time.Duration, logger *slog.Logger) ([]notifier.Event, int) {
	if st == nil || ttl <= 0 {
		return events, 0
	}
	kept := make([]notifier.Event, 0, len(events))
	silenced := 0
	for _, e := range events {
		key, legacy := dedupKeyWithLegacy(e)
		ok, err := st.ShouldNotifyOrLegacy(key, legacy, e.Risk, now, ttl)
		if err != nil {
			// Fail open — better to over-notify than to suppress on a store
			// failure. Log and proceed.
			logger.Warn("dedup lookup failed; sending event anyway", "container", e.Container, "err", err)
			kept = append(kept, e)
			continue
		}
		if !ok {
			silenced++
			continue
		}
		kept = append(kept, e)
	}
	return kept, silenced
}

// buildSnapshotBackend reads the snapshots.backend YAML field and returns
// the matching backend, or nil if disabled / unsupported on this host.
// Failures are warnings — the daemon falls back to "no snapshots" rather
// than aborting startup.
//
// When cs is non-nil, snapshot fields from the encrypted configstore
// (the dashboard's Snapshots editor) merge on top of the yaml-loaded
// base. This is how the UI-editable Proxmox token reaches the
// backend without ever appearing in bulwark.yaml.
func buildSnapshotBackend(loaded *config.Config, cs *configstore.Store, logger *slog.Logger) snapshot.Backend {
	if loaded == nil {
		return nil
	}
	if cs != nil {
		loaded = loaded.WithUISettings(cs.Settings().ToUISettings())
	}
	name := strings.ToLower(strings.TrimSpace(loaded.Snapshots.Backend))
	var b snapshot.Backend
	switch name {
	case "restic":
		// Restic needs repo + password-file from YAML; the generic
		// snapshot.New factory only takes a name. Construct directly so
		// the misconfiguration ("restic chosen but no repo configured")
		// produces a clear log line rather than a runtime backup failure.
		repo := loaded.Snapshots.Restic.Repository
		pw := loaded.Snapshots.Restic.PasswordFile
		if repo == "" || pw == "" {
			logger.Warn("snapshots: restic backend chosen but repository or password_file missing; running without snapshots")
			return nil
		}
		b = snapshot.NewRestic(repo, pw, nil)
	case "proxmox":
		// Proxmox VE API backend. Validates url/token/node/vmid up
		// front so a misconfig produces a clear startup warning, not
		// a runtime failure mid-apply.
		pxCfg := loaded.Snapshots.Proxmox
		insecureSkip := pxCfg.TLS.InsecureSkipVerify
		if pxCfg.InsecureTLS {
			logger.Warn("snapshots: proxmox.insecure_tls is deprecated; use proxmox.tls.insecure_skip_verify")
			insecureSkip = true
		}
		px, err := snapshot.NewProxmox(snapshot.ProxmoxConfig{
			URL:                pxCfg.URL,
			Token:              pxCfg.Token,
			Node:               pxCfg.Node,
			VMID:               pxCfg.VMID,
			Kind:               snapshot.ProxmoxKind(pxCfg.Kind),
			CAFile:             pxCfg.TLS.CAFile,
			InsecureSkipVerify: insecureSkip,
			Logger:             logger,
		})
		if err != nil {
			logger.Warn("snapshots: proxmox misconfigured; running without snapshots", "err", err)
			return nil
		}
		b = px
	default:
		built, err := snapshot.New(name)
		if err != nil {
			logger.Warn("snapshots: invalid backend; running without snapshots", "name", name, "err", err)
			return nil
		}
		b = built
	}
	if b == nil {
		return nil
	}
	if !b.Available(context.Background()) {
		logger.Warn("snapshots: backend unavailable on this host; running without snapshots", "backend", b.Name())
		return nil
	}
	logger.Info("snapshots: backend ready", "backend", b.Name())
	return b
}

// filterByApproval drops events for which the user has already recorded
// a decision (approved or rejected). Returns the kept events and a count
// of decided-and-silenced ones for output rendering. A nil store is the
// no-op.
//
// Decisions take priority over TTL dedup: an approved or rejected
// (container, digest) is silenced forever, not just within a window.
func filterByApproval(st *store.Store, events []notifier.Event, logger *slog.Logger) ([]notifier.Event, int) {
	if st == nil {
		return events, 0
	}
	kept := make([]notifier.Event, 0, len(events))
	decided := 0
	for _, e := range events {
		key := store.ApprovalKey{ContainerID: e.Container, RegistryDigest: e.RegistryDigest}
		rec, err := st.LookupDecision(key)
		if err != nil {
			// Fail open — better to over-notify than to suppress on a store
			// failure.
			logger.Warn("approval lookup failed; sending event anyway", "container", e.Container, "err", err)
			kept = append(kept, e)
			continue
		}
		if rec == nil {
			kept = append(kept, e)
			continue
		}
		// User has already decided about this exact (container, digest).
		// No notification needed regardless of TTL.
		decided++
	}
	return kept, decided
}

// We deliberately treat "all channels failed" as "not delivered" — better to
// re-notify next scan than to silently swallow a failed alert.
func markSentEvents(st *store.Store, events []notifier.Event, results []notifier.DispatchResult, when time.Time, logger *slog.Logger) {
	if st == nil || len(events) == 0 {
		return
	}
	anyOK := false
	for _, r := range results {
		if r.Ok() && r.Sent > 0 {
			anyOK = true
			break
		}
	}
	if !anyOK {
		return
	}
	for _, e := range events {
		key, _ := dedupKeyWithLegacy(e) // always write under the new ID-keyed form
		meta := store.NotificationRecord{
			ContainerName: e.Container,
			Image:         e.Image,
			Level:         e.Risk,
		}
		if err := st.MarkNotified(key, meta, when); err != nil {
			logger.Warn("could not mark notification as sent", "container", e.Container, "err", err)
		}
	}
}

// dedupKeyWithLegacy returns the new (Container.ID-keyed) primary key plus
// the legacy (Container.Name-keyed) fallback. Pre-Phase-10 Bulwark keyed
// dedup state on the container name; existing on-disk records still resolve
// via the legacy key until they age out.
//
// When ContainerID is empty (synthetic events / older event sources), the
// primary key falls back to Name and legacy is set to the same key — no
// behavioural change vs. the legacy code path.
func dedupKeyWithLegacy(e notifier.Event) (primary, legacy store.NotificationKey) {
	id := e.ContainerID
	if id == "" {
		id = e.Container
	}
	primary = store.NotificationKey{ContainerID: id, RegistryDigest: e.RegistryDigest}
	legacy = store.NotificationKey{ContainerID: e.Container, RegistryDigest: e.RegistryDigest}
	return primary, legacy
}

// buildScanRecord materializes a store.ScanRecord from the in-memory results
// and dispatch outcomes. Stays in sync with writeScanJSON's per-result fields.
func buildScanRecord(results []scanner.Result, dispatch []notifier.DispatchResult, started, finished time.Time) store.ScanRecord {
	rec := store.ScanRecord{StartedAt: started, FinishedAt: finished}
	host, _ := os.Hostname()
	rec.Host = host
	rec.Summary.Total = len(results)
	rec.Results = make([]store.ScanResultRecord, 0, len(results))
	for _, r := range results {
		rr := store.ScanResultRecord{
			ContainerID:     r.Container.ID,
			ContainerName:   r.Container.Name,
			Image:           r.Container.Image,
			ComposeProject:  r.Container.ComposeProject(),
			Skipped:         r.Skipped,
			SkipReason:      r.SkipReason,
			UpdateAvailable: r.HasUpdate(),
			LocalDigest:     r.LocalDigest,
			RegistryDigest:  r.RegistryDigest,
			NotesSource:     r.NotesSource,
		}
		if r.Err != nil {
			rr.Error = r.Err.Error()
			rec.Summary.Errored++
		} else if r.Skipped {
			rec.Summary.Skipped++
		} else if r.Assessment != nil {
			rr.Level = r.Assessment.Level
			rr.Kind = r.Assessment.Delta.Kind
			rr.Confidence = r.Assessment.Confidence
			rr.From = r.Assessment.Delta.From
			rr.To = r.Assessment.Delta.To
			rr.Rationale = r.Assessment.Rationale
			rr.ReleaseURL = r.Assessment.ReleaseURL
			rr.Security = r.Assessment.Security
			if rr.UpdateAvailable {
				rec.Summary.Pending++
				switch r.Assessment.Level {
				case types.RiskBreaking:
					rec.Summary.Breaking++
				case types.RiskReview:
					rec.Summary.Review++
				case types.RiskSafe:
					rec.Summary.Safe++
				}
			}
		}
		rec.Results = append(rec.Results, rr)
	}
	return rec
}

// jsonResult is the wire shape of a scan result; mirrors scanner.Result but
// uses string-typed fields for type-safe JSON consumers.
type jsonResult struct {
	Container       string   `json:"container"`
	Image           string   `json:"image"`
	ComposeProject  string   `json:"compose_project,omitempty"`
	Skipped         bool     `json:"skipped"`
	SkipReason      string   `json:"skip_reason,omitempty"`
	UpdateAvailable bool     `json:"update_available"`
	LocalDigest     string   `json:"local_digest,omitempty"`
	RegistryDigest  string   `json:"registry_digest,omitempty"`
	Level           string   `json:"level,omitempty"`
	Confidence      string   `json:"confidence,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	Rationale       string   `json:"rationale,omitempty"`
	From            string   `json:"from,omitempty"`
	To              string   `json:"to,omitempty"`
	NotesSource     string   `json:"notes_source,omitempty"`
	ReleaseURL      string   `json:"release_url,omitempty"`
	MatchedTokens   []string `json:"matched_tokens,omitempty"`
	Error           string   `json:"error,omitempty"`
}

func writeScanJSON(w io.Writer, results []scanner.Result, dispatch []notifier.DispatchResult) error {
	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		jr := jsonResult{
			Container:       r.Container.Name,
			Image:           r.Container.Image,
			ComposeProject:  r.Container.ComposeProject(),
			Skipped:         r.Skipped,
			SkipReason:      r.SkipReason,
			UpdateAvailable: r.HasUpdate(),
			LocalDigest:     r.LocalDigest,
			RegistryDigest:  r.RegistryDigest,
			NotesSource:     r.NotesSource,
		}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		if r.Assessment != nil {
			jr.Level = r.Assessment.Level.String()
			jr.Confidence = r.Assessment.Confidence.String()
			jr.Kind = r.Assessment.Delta.Kind.String()
			jr.Rationale = r.Assessment.Rationale
			jr.From = r.Assessment.Delta.From
			jr.To = r.Assessment.Delta.To
			jr.ReleaseURL = r.Assessment.ReleaseURL
			jr.MatchedTokens = r.Assessment.MatchedTokens
		}
		out = append(out, jr)
	}

	if len(dispatch) == 0 {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	// When notifications were dispatched, wrap results + per-channel outcomes
	// so machine consumers can act on both.
	type dispatchJSON struct {
		Notifier string `json:"notifier"`
		Sent     int    `json:"sent"`
		Skipped  int    `json:"skipped"`
		Error    string `json:"error,omitempty"`
	}
	envelope := struct {
		Results  []jsonResult   `json:"results"`
		Notifies []dispatchJSON `json:"notifications"`
	}{Results: out}
	for _, d := range dispatch {
		row := dispatchJSON{Notifier: d.Notifier, Sent: d.Sent, Skipped: d.Skipped}
		if d.Err != nil {
			row.Error = d.Err.Error()
		}
		envelope.Notifies = append(envelope.Notifies, row)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func writeDispatchSummary(w io.Writer, results []notifier.DispatchResult, dedupSilenced, approvalSilenced int) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notifications:")
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(w, "  %s: ERROR — %s\n", r.Notifier, r.Err.Error())
		case r.Sent == 0:
			fmt.Fprintf(w, "  %s: no events met threshold (%d filtered)\n", r.Notifier, r.Skipped)
		default:
			fmt.Fprintf(w, "  %s: sent %d (%d filtered)\n", r.Notifier, r.Sent, r.Skipped)
		}
	}
	if approvalSilenced > 0 {
		fmt.Fprintf(w, "  (%d event(s) silenced by recorded decision; clear with `bulwark queue clear`)\n", approvalSilenced)
	}
	if dedupSilenced > 0 {
		fmt.Fprintf(w, "  (%d event(s) silenced by dedup; use --dedup-ttl=0 to disable)\n", dedupSilenced)
	}
}

// writeScanText prints a human-friendly scan report. Each container occupies
// one line for the header and an indented detail block when a verdict exists.
func writeScanText(w io.Writer, results []scanner.Result, color bool) error {
	c := palette(color)

	// Compute the column width for container names so the output stays aligned.
	maxName := len("CONTAINER")
	for _, r := range results {
		if n := len(r.Container.Name); n > maxName {
			maxName = n
		}
	}

	// Sort: errors first, then breaking, review, safe, no-update, skipped — so
	// the most actionable items are at the top of the list.
	sorted := append([]scanner.Result(nil), results...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return scanRank(sorted[i]) < scanRank(sorted[j])
	})

	header := fmt.Sprintf("%-*s  %s", maxName, "CONTAINER", "IMAGE")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("─", len(header)))

	for _, r := range sorted {
		fmt.Fprintf(w, "%-*s  %s\n", maxName, r.Container.Name, r.Container.Image)

		switch {
		case r.Err != nil:
			fmt.Fprintf(w, "    %sERROR%s  %s\n", c.red, c.reset, r.Err.Error())
		case r.Skipped:
			fmt.Fprintf(w, "    %sSKIPPED%s  %s\n", c.dim, c.reset, r.SkipReason)
		case !r.HasUpdate():
			fmt.Fprintf(w, "    %sno update%s  digest %s\n", c.dim, c.reset, shortDigest(r.RegistryDigest))
		default:
			a := r.Assessment
			label, levelColor := levelLabel(a.Level, c)
			fmt.Fprintf(w, "    %s%s%s  %s  %s → %s  (%s)\n",
				levelColor, label, c.reset,
				a.Delta.Kind,
				a.Delta.From, a.Delta.To,
				a.Confidence,
			)
			if a.Rationale != "" {
				fmt.Fprintf(w, "    %s\n", a.Rationale)
			}
			if r.NotesSource != "" {
				fmt.Fprintf(w, "    notes: %s\n", r.NotesSource)
			}
			if a.ReleaseURL != "" {
				fmt.Fprintf(w, "    %s\n", a.ReleaseURL)
			}
		}
		fmt.Fprintln(w)
	}

	// Summary line.
	pending, breaking, review, safe, skipped, errored := 0, 0, 0, 0, 0, 0
	for _, r := range results {
		switch {
		case r.Err != nil:
			errored++
		case r.Skipped:
			skipped++
		case !r.HasUpdate():
			// nothing
		default:
			pending++
			switch r.Assessment.Level {
			case types.RiskBreaking:
				breaking++
			case types.RiskReview:
				review++
			case types.RiskSafe:
				safe++
			}
		}
	}
	fmt.Fprintf(w, "%d update(s) pending: %d breaking, %d review, %d safe.  %d skipped, %d error.\n",
		pending, breaking, review, safe, skipped, errored)
	return nil
}

func scanRank(r scanner.Result) int {
	switch {
	case r.Err != nil:
		return 0
	case r.Skipped:
		return 6
	case !r.HasUpdate():
		return 5
	}
	switch r.Assessment.Level {
	case types.RiskBreaking:
		return 1
	case types.RiskReview:
		return 2
	case types.RiskSafe:
		return 3
	}
	return 4
}

func levelLabel(l types.RiskLevel, c colors) (string, string) {
	switch l {
	case types.RiskBreaking:
		return "BREAKING", c.red
	case types.RiskReview:
		return "REVIEW", c.yellow
	case types.RiskSafe:
		return "SAFE", c.green
	default:
		return strings.ToUpper(l.String()), c.dim
	}
}

func shortDigest(d string) string {
	if d == "" {
		return "(unknown)"
	}
	if i := strings.Index(d, ":"); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}

type colors struct {
	red, green, yellow, dim, reset string
}

func palette(enabled bool) colors {
	if !enabled {
		return colors{}
	}
	return colors{
		red:    "\x1b[31m",
		green:  "\x1b[32m",
		yellow: "\x1b[33m",
		dim:    "\x1b[2m",
		reset:  "\x1b[0m",
	}
}

// isLikelyTTY uses the file-mode device flag to decide whether to emit ANSI
// colour. It's a best-effort heuristic and treats anything we can't introspect
// (bytes.Buffer in tests, pipes, etc.) as non-TTY so output stays clean.
func isLikelyTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
