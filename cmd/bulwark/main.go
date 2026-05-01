// Bulwark — intelligent Docker container update guardian.
//
// This is the entrypoint binary. The current subcommands are:
//
//	bulwark version              print version metadata
//	bulwark validate-config      parse a config file and report validation result
//	bulwark classify             run the classifier offline against two image references
//	bulwark check                resolve digests via the registry, fetch release notes,
//	                             and classify the resulting update
//
// The "run" daemon depends on Docker socket integration and is wired in a
// subsequent phase.
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
	"runtime"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/releasenotes"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// Build metadata. Set via -ldflags "-X main.version=..." at release time.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printRootUsage(stderr)
		return errUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		printRootUsage(stdout)
		return nil
	case "version":
		return cmdVersion(stdout)
	case "validate-config":
		return cmdValidateConfig(args[1:], stdout, stderr)
	case "classify":
		return cmdClassify(args[1:], stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printRootUsage(stderr)
		return errUsage
	}
}

func printRootUsage(w io.Writer) {
	fmt.Fprintln(w, `bulwark — intelligent Docker container update guardian

Usage:
  bulwark <command> [flags]

Commands:
  version             Print version metadata
  validate-config     Parse a config file and report validation result
  classify            Classify a hypothetical image update (offline, no network)
  check               Resolve registry digests, fetch release notes, and classify

Run "bulwark <command> --help" for command-specific options.`)
}

func cmdVersion(out io.Writer) error {
	fmt.Fprintf(out, "bulwark %s (commit %s, built %s, %s/%s)\n",
		version, commit, date, runtime.GOOS, runtime.GOARCH)
	return nil
}

func cmdValidateConfig(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to bulwark.yaml")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *path == "" {
		return errors.New("validate-config: --config is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config %s: ok\n", *path)
	fmt.Fprintf(stdout, "  default_risk:    %s\n", cfg.Classification.DefaultRisk)
	fmt.Fprintf(stdout, "  snapshot_backend: %s\n", nonEmpty(cfg.Snapshots.Backend, "none"))
	fmt.Fprintf(stdout, "  api_listen:      %s\n", cfg.API.Listen)
	return nil
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func cmdClassify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("classify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "current image reference (e.g., lscr.io/linuxserver/sonarr:4.0.9-ls45)")
	to := fs.String("to", "", "available image reference (e.g., lscr.io/linuxserver/sonarr:4.0.10-ls46)")
	notesPath := fs.String("notes", "", "path to a release-notes file (optional)")
	notesURL := fs.String("notes-url", "", "URL to attach to the assessment (optional)")
	configPath := fs.String("config", "", "path to bulwark.yaml (optional; uses defaults when absent)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *from == "" || *to == "" {
		return errors.New("classify: --from and --to are required")
	}

	current, err := parseRef(*from)
	if err != nil {
		return fmt.Errorf("classify: --from: %w", err)
	}
	available, err := parseRef(*to)
	if err != nil {
		return fmt.Errorf("classify: --to: %w", err)
	}
	if current.Repository == "" {
		current.Repository = available.Repository
	}
	if available.Repository == "" {
		available.Repository = current.Repository
	}
	if current.Repository != available.Repository {
		return fmt.Errorf("classify: --from and --to must reference the same repository (got %q and %q)",
			current.Repository, available.Repository)
	}

	cfg := classifier.DefaultConfig()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = loaded.ClassifierConfig()
	}

	var notes *classifier.ReleaseNotes
	if *notesPath != "" {
		body, err := os.ReadFile(*notesPath)
		if err != nil {
			return fmt.Errorf("classify: read notes: %w", err)
		}
		notes = &classifier.ReleaseNotes{Body: string(body), URL: *notesURL, Resolved: true}
	} else if *notesURL != "" {
		notes = &classifier.ReleaseNotes{URL: *notesURL}
	}

	c := classifier.New(cfg)
	assessment, err := c.Classify(context.Background(), current, available, notes)
	if err != nil {
		return err
	}

	out := struct {
		Level         string             `json:"level"`
		Confidence    string             `json:"confidence"`
		Kind          string             `json:"kind"`
		Rationale     string             `json:"rationale"`
		Delta         types.VersionDelta `json:"delta"`
		MatchedTokens []string           `json:"matched_tokens,omitempty"`
		ReleaseURL    string             `json:"release_url,omitempty"`
	}{
		Level:         assessment.Level.String(),
		Confidence:    assessment.Confidence.String(),
		Kind:          assessment.Delta.Kind.String(),
		Rationale:     assessment.Rationale,
		Delta:         assessment.Delta,
		MatchedTokens: assessment.MatchedTokens,
		ReleaseURL:    assessment.ReleaseURL,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// parseRef parses an image reference of the form
//
//	[registry/]repository[:tag][@digest]
//
// for the offline classify command. It preserves the user's input verbatim
// (no library/ namespace prepending) so the rationale string in the output
// matches what they typed. cmdCheck uses registry.Parse instead, which
// performs the Docker Hub default-namespace expansion needed for HTTP calls.
func parseRef(ref string) (types.ImageInfo, error) {
	if ref == "" {
		return types.ImageInfo{}, errors.New("empty reference")
	}
	var info types.ImageInfo
	rest := ref
	if i := strings.Index(rest, "@"); i >= 0 {
		info.Digest = rest[i+1:]
		rest = rest[:i]
	}
	// The colon separating tag from repo must be the last colon AFTER the last
	// slash, so we don't confuse port numbers in registry hosts (e.g.
	// "registry.example.com:5000/app:1.2.3").
	slash := strings.LastIndex(rest, "/")
	colon := strings.LastIndex(rest, ":")
	if colon > slash {
		info.Tag = rest[colon+1:]
		rest = rest[:colon]
	}
	info.Repository = rest
	return info, nil
}

// checkDeps bundles the network dependencies cmdCheck uses. Tests inject stubs
// pointing at httptest servers; main() leaves them nil so production clients
// are constructed.
type checkDeps struct {
	Registry *registry.Client
	GitHub   *releasenotes.GitHubClient
}

// cmdCheck implements `bulwark check`. Unlike classify, it goes to the network:
// it resolves both the current and target image digests via the registry and
// (when possible) fetches release notes from GitHub before running the
// classifier. Diagnostic output goes to stderr via slog; the final
// assessment is emitted on stdout as JSON.
func cmdCheck(args []string, stdout, stderr io.Writer) error {
	return cmdCheckWith(args, stdout, stderr, checkDeps{})
}

func cmdCheckWith(args []string, stdout, stderr io.Writer, deps checkDeps) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark check <current-image-ref> <new-tag> [flags]

Resolves digests via the registry, fetches release notes from GitHub when
the image maps to a known source repository, and prints a JSON assessment.

Examples:
  bulwark check lscr.io/linuxserver/sonarr:4.0.9-ls45 4.0.10-ls46
  bulwark check ghcr.io/owner/app:1.2.3 1.3.0

Flags:`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to bulwark.yaml (optional)")
	skipNotes := fs.Bool("no-fetch-notes", false, "skip GitHub release-notes fetch")
	githubToken := fs.String("github-token", os.Getenv("BULWARK_GITHUB_TOKEN"), "GitHub PAT for higher rate limits")
	verbose := fs.Bool("v", false, "verbose progress logging on stderr")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return errors.New("check: expected exactly two positional arguments")
	}
	currentArg := fs.Arg(0)
	newTag := fs.Arg(1)

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{
		Level: levelFor(*verbose),
	}))

	currentRef, err := registry.Parse(currentArg)
	if err != nil {
		return fmt.Errorf("check: parse current ref: %w", err)
	}
	if currentRef.Tag == "" && currentRef.Digest == "" {
		return errors.New("check: current reference must include a tag")
	}
	targetRef := currentRef
	targetRef.Tag = newTag
	targetRef.Digest = ""

	cfg := classifier.DefaultConfig()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = loaded.ClassifierConfig()
	}

	ctx := context.Background()

	regClient := deps.Registry
	if regClient == nil {
		regClient = registry.New()
	}
	logger.Info("resolving current digest", "ref", currentRef.String())
	currentDigest, err := regClient.Resolve(ctx, currentRef)
	if err != nil {
		return fmt.Errorf("check: resolve current digest: %w", err)
	}
	currentRef.Digest = currentDigest

	logger.Info("resolving target digest", "ref", targetRef.String())
	targetDigest, err := regClient.Resolve(ctx, targetRef)
	if err != nil {
		return fmt.Errorf("check: resolve target digest: %w", err)
	}
	targetRef.Digest = targetDigest

	var notes *classifier.ReleaseNotes
	var fetchedFrom string
	if !*skipNotes {
		fetcher := releasenotes.NewFetcher()
		if deps.GitHub != nil {
			fetcher.GitHub = deps.GitHub
		}
		fetcher.GitHub.Token = *githubToken
		res, err := fetcher.Fetch(ctx, targetRef)
		if err != nil {
			logger.Warn("release-notes fetch failed; classifying without notes", "err", err)
		} else if res.Found() {
			notes = &classifier.ReleaseNotes{
				URL:      res.Notes.URL,
				Body:     res.Notes.Body,
				Resolved: true,
			}
			fetchedFrom = res.Source.String()
			logger.Info("fetched release notes", "source", fetchedFrom, "tag", res.Notes.Tag)
		} else if res.Source != (releasenotes.Source{}) {
			fetchedFrom = res.Source.String() + " (no release found)"
			logger.Info("no release notes published", "source", res.Source.String())
		} else {
			logger.Info("no source repo could be inferred for image; skipping notes")
		}
	}

	c := classifier.New(cfg)
	assessment, err := c.Classify(ctx, currentRef.ToImageInfo(), targetRef.ToImageInfo(), notes)
	if err != nil {
		return err
	}

	out := struct {
		Level         types.RiskLevel    `json:"level"`
		Confidence    types.Confidence   `json:"confidence"`
		Kind          types.ChangeKind   `json:"kind"`
		Rationale     string             `json:"rationale"`
		Delta         types.VersionDelta `json:"delta"`
		MatchedTokens []string           `json:"matched_tokens,omitempty"`
		ReleaseURL    string             `json:"release_url,omitempty"`
		CurrentDigest string             `json:"current_digest"`
		TargetDigest  string             `json:"target_digest"`
		NotesSource   string             `json:"notes_source,omitempty"`
	}{
		Level:         assessment.Level,
		Confidence:    assessment.Confidence,
		Kind:          assessment.Delta.Kind,
		Rationale:     assessment.Rationale,
		Delta:         assessment.Delta,
		MatchedTokens: assessment.MatchedTokens,
		ReleaseURL:    assessment.ReleaseURL,
		CurrentDigest: currentDigest,
		TargetDigest:  targetDigest,
		NotesSource:   fetchedFrom,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func levelFor(verbose bool) slog.Level {
	if verbose {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
