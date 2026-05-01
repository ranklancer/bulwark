// Bulwark — intelligent Docker container update guardian.
//
// This is the entrypoint binary. The MVP exposes three subcommands:
//
//	bulwark version              print version metadata
//	bulwark validate-config      parse a config file and report validation result
//	bulwark classify             run the classifier against two image references and
//	                             print the assessment as JSON
//
// The "run" daemon and "check" oneshot scanner depend on Docker integration
// and are wired in subsequent phases.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/config"
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
  classify            Classify a hypothetical image update and print assessment

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
// We do not pull in the docker reference parser (heavyweight) — this is a
// best-effort split adequate for CLI input.
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
