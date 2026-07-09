package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/capture"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// pinResolver resolves an image reference to a digest pin. Injected so the
// command is testable without network access.
type pinResolver func(ctx context.Context, ref registry.Reference) (capture.Pin, error)

func registryResolver(c *registry.Client) pinResolver {
	return func(ctx context.Context, ref registry.Reference) (capture.Pin, error) {
		info, err := c.ResolveManifest(ctx, ref)
		if err != nil {
			return capture.Pin{}, err
		}
		return capture.Pin{IndexDigest: info.Digest, IsIndex: info.IsIndex, Arches: info.Arches, MediaType: info.MediaType}, nil
	}
}

// cmdCapture discovers compose stacks, resolves each pinnable image to its
// multi-arch INDEX digest, and (dry-run) prints the pin it would apply or
// (--apply) writes it in place with backup/atomic/rollback safety, recording
// each pin in pins.json.
func cmdCapture(args []string, stdout, stderr io.Writer) error {
	return cmdCaptureWith(args, stdout, stderr, registryResolver(registry.New()))
}

func cmdCaptureWith(args []string, stdout, stderr io.Writer, resolve pinResolver) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stacks := fs.String("stacks-path", "", "comma-separated stack dirs / globs / compose files (overrides config sources)")
	configPath := fs.String("config", "", "config file whose sources: declare the backends to capture")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir for pins.json (needed to record pins on --apply)")
	backupDir := fs.String("backup-dir", "", "where to back up originals before an in-place edit (default <data-dir>/pin-backups)")
	autodiscover := fs.Bool("autodiscover", true, "scan <root>/<stack>/ subdirs (flat Dockge layout)")
	requireIndex := fs.Bool("require-index", true, "skip a ref that resolves to a single-arch (non-index) manifest")
	apply := fs.Bool("apply", false, "apply pins in place (backup + atomic + rollback). Default: dry-run")
	if err := fs.Parse(args); err != nil {
		return err
	}

	backup := *backupDir
	if backup == "" && *dataDir != "" {
		backup = filepath.Join(*dataDir, "pin-backups")
	}

	var sources []*capture.ComposeSource
	switch {
	case strings.TrimSpace(*stacks) != "":
		var paths []string
		for _, p := range strings.Split(*stacks, ",") {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		sources = append(sources, &capture.ComposeSource{Paths: paths, Autodiscover: *autodiscover, BackupDir: backup})
	case *configPath != "":
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		bd := backup
		if bd == "" && cfg.Capture.BackupDir != "" {
			bd = cfg.Capture.BackupDir
		}
		for _, sc := range cfg.Sources {
			switch strings.ToLower(strings.TrimSpace(sc.Type)) {
			case "", "compose":
				sources = append(sources, &capture.ComposeSource{Paths: sc.Paths, Autodiscover: sc.Autodiscover, BackupDir: bd})
			default:
				fmt.Fprintf(stdout, "source %q: type %q not implemented (file-based compose only) — skipping\n", sc.Name, sc.Type)
			}
		}
	default:
		return errors.New("capture: provide --stacks-path or --config (with a sources: block)")
	}

	var pins *store.PinStore
	if *apply && *dataDir != "" {
		pins = store.OpenPinStore(*dataDir)
	}

	ctx := context.Background()
	mode := "dry-run"
	if *apply {
		mode = "apply"
	}
	for _, src := range sources {
		targets, err := src.Discover(ctx)
		if err != nil {
			return err
		}
		for _, tgt := range targets {
			fmt.Fprintf(stdout, "%s: %s (%s)\n", mode, tgt.Name, tgt.Path)
			refs, err := src.LocateImageRefs(ctx, tgt)
			if err != nil {
				fmt.Fprintf(stdout, "  ! error: %v\n", err)
				continue
			}
			for _, r := range refs {
				if !r.Pinnable {
					fmt.Fprintf(stdout, "  - %s: skip (%s)\n", r.Service, r.Reason)
					continue
				}
				ref, err := registry.Parse(r.Ref)
				if err != nil {
					fmt.Fprintf(stdout, "  - %s: skip (unparseable %q)\n", r.Service, r.Ref)
					continue
				}
				pin, err := resolve(ctx, ref)
				if err != nil {
					fmt.Fprintf(stdout, "  - %s: resolve error: %v\n", r.Service, err)
					continue
				}
				if *requireIndex && !pin.IsIndex {
					fmt.Fprintf(stdout, "  - %s: skip (%s is single-arch; --require-index)\n", r.Service, r.Ref)
					continue
				}
				prop, err := src.ProposePin(ctx, tgt, r, pin)
				if err != nil {
					fmt.Fprintf(stdout, "  - %s: %v\n", r.Service, err)
					continue
				}
				if prop.NoOp {
					fmt.Fprintf(stdout, "  - %s: already pinned (no-op)\n", r.Service)
					continue
				}
				if !*apply {
					fmt.Fprintf(stdout, "  - %s (line %d):\n      %s\n", r.Service, prop.Line, strings.ReplaceAll(prop.Diff, "\n", "\n      "))
					continue
				}
				applied, err := src.WritePin(ctx, prop)
				if err != nil {
					fmt.Fprintf(stdout, "  - %s: WRITE FAILED: %v\n", r.Service, err)
					continue
				}
				fmt.Fprintf(stdout, "  - %s: pinned %s@%s (backup %s)\n", r.Service, r.Ref, pin.IndexDigest, applied.BackupPath)
				if pins != nil {
					_ = pins.Set(tgt.Name+"/"+r.Service, store.PinRecord{
						Ref: r.Ref, IndexDigest: pin.IndexDigest, MediaType: pin.MediaType,
						Arches: pin.Arches, Source: "file:" + tgt.Name, ComposePath: tgt.Path,
						BackupPath: applied.BackupPath, Service: r.Service, CanaryState: "candidate",
					})
				}
			}
		}
	}
	if *apply && *dataDir == "" {
		fmt.Fprintln(stdout, "note: --data-dir not set; pins were applied but not recorded in pins.json")
	}
	return nil
}
