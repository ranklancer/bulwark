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
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/releasenotes"
	"github.com/bulwark-docker/bulwark/internal/scanner"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// scanDeps lets tests substitute the network-touching components. Production
// leaves all fields nil and cmdScan constructs real clients.
type scanDeps struct {
	Docker     scanner.DockerLister
	Registry   scanner.DigestResolver
	Notes      scanner.NotesFetcher
	Notifiers  []notifier.Notifier // overrides FromConfig when non-nil
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
	githubToken := fs.String("github-token", os.Getenv("BULWARK_GITHUB_TOKEN"), "GitHub PAT for higher rate limits")
	concurrency := fs.Int("concurrency", 4, "number of containers to inspect in parallel")
	noColor := fs.Bool("no-color", false, "disable ANSI colour codes in text output")
	notify := fs.Bool("notify", false, "after scanning, dispatch notifications to channels enabled in config")
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
		regClient = registry.New()
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

	s := &scanner.Scanner{
		Docker:      dockerClient,
		Registry:    regClient,
		Notes:       notesFetcher,
		Classifier:  classifier.New(cfg),
		Config:      loaded,
		Concurrency: *concurrency,
	}

	logger.Info("starting scan", "all", *all, "concurrency", *concurrency)
	results, err := s.Scan(context.Background(), *all)
	if err != nil {
		return err
	}

	var dispatchResults []notifier.DispatchResult
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
			events := notifier.EventsFromScan(results, time.Now().UTC())
			d := notifier.NewDispatcher(notifiers, logger, 30*time.Second)
			dispatchResults = d.Dispatch(context.Background(), events)
		}
	}

	if *jsonOut {
		return writeScanJSON(stdout, results, dispatchResults)
	}
	if err := writeScanText(stdout, results, !*noColor && isLikelyTTY(stdout)); err != nil {
		return err
	}
	if len(dispatchResults) > 0 {
		writeDispatchSummary(stdout, dispatchResults)
	}
	return nil
}

// jsonResult is the wire shape of a scan result; mirrors scanner.Result but
// uses string-typed fields for type-safe JSON consumers.
type jsonResult struct {
	Container       string `json:"container"`
	Image           string `json:"image"`
	ComposeProject  string `json:"compose_project,omitempty"`
	Skipped         bool   `json:"skipped"`
	SkipReason      string `json:"skip_reason,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	LocalDigest     string `json:"local_digest,omitempty"`
	RegistryDigest  string `json:"registry_digest,omitempty"`
	Level           string `json:"level,omitempty"`
	Confidence      string `json:"confidence,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Rationale       string `json:"rationale,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	NotesSource     string `json:"notes_source,omitempty"`
	ReleaseURL      string `json:"release_url,omitempty"`
	MatchedTokens   []string `json:"matched_tokens,omitempty"`
	Error           string `json:"error,omitempty"`
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

func writeDispatchSummary(w io.Writer, results []notifier.DispatchResult) {
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
