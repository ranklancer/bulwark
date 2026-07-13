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
	"github.com/bulwark-docker/bulwark/internal/verify"
)

// pinResolver resolves an image reference to a digest pin. Injected so the
// command is testable without network access.
type pinResolver func(ctx context.Context, ref registry.Reference) (capture.Pin, error)

// gateEvaluator is the slice of verify.Gate the capture command uses (digest pinning
// Phase 3). *verify.Gate satisfies it; tests inject a fake.
type gateEvaluator interface {
	Evaluate(ctx context.Context, in verify.Input) verify.Verdict
}

func registryResolver(c *registry.Client) pinResolver {
	return func(ctx context.Context, ref registry.Reference) (capture.Pin, error) {
		info, err := c.ResolveManifest(ctx, ref)
		if err != nil {
			return capture.Pin{}, err
		}
		return capture.Pin{IndexDigest: info.Digest, IsIndex: info.IsIndex, Arches: info.Arches, MediaType: info.MediaType}, nil
	}
}

// buildVerifyGate constructs the trust gate from config, reusing the exact
// wiring the daemon uses (no new verification logic — the digest-pin capture design Phase 3).
func buildVerifyGate(cfg *config.Config) (*verify.Gate, error) {
	sig, err := cfg.SignatureVerifier()
	if err != nil {
		return nil, err
	}
	src, _, cveErr := buildCVESource(cfg)
	if cveErr != nil {
		return nil, cveErr
	}
	prov, err := cfg.ProvenanceVerifier()
	if err != nil {
		return nil, err
	}
	return &verify.Gate{Policy: cfg.VerifyPolicy(), Signature: sig, Provenance: prov, Vulns: src}, nil
}

func cmdCapture(args []string, stdout, stderr io.Writer) error {
	return cmdCaptureWith(args, stdout, stderr, registryResolver(registry.New()), nil)
}

func cmdCaptureWith(args []string, stdout, stderr io.Writer, resolve pinResolver, gate gateEvaluator) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stacks := fs.String("stacks-path", "", "comma-separated stack dirs / globs / compose files (overrides config sources)")
	configPath := fs.String("config", "", "config file whose sources: declare the backends to capture")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir for pins.json (needed to record pins on --apply)")
	backupDir := fs.String("backup-dir", "", "where to back up originals before an in-place edit (default <data-dir>/pin-backups)")
	autodiscover := fs.Bool("autodiscover", true, "scan <root>/<stack>/ subdirs (flat Dockge layout)")
	requireIndex := fs.Bool("require-index", true, "skip a ref that resolves to a single-arch (non-index) manifest")
	apply := fs.Bool("apply", false, "apply pins in place (backup + atomic + rollback). Default: dry-run")
	digestFlag := fs.String("digest", "", "pin to this exact sha256 digest, skipping registry resolution (single target / air-gapped)")
	doVerify := fs.Bool("verify", false, "evaluate each captured pin through the trust gate and report the verdict (requires --config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var cfg *config.Config
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = c
	}

	backup := *backupDir
	if backup == "" && *dataDir != "" {
		backup = filepath.Join(*dataDir, "pin-backups")
	}

	var sources []capture.Source
	switch {
	case strings.TrimSpace(*stacks) != "":
		var paths []string
		for _, p := range strings.Split(*stacks, ",") {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		sources = append(sources, &capture.ComposeSource{Paths: paths, Autodiscover: *autodiscover, BackupDir: backup})
	case cfg != nil:
		bd := backup
		if bd == "" && cfg.Capture.BackupDir != "" {
			bd = cfg.Capture.BackupDir
		}
		for _, sc := range cfg.Sources {
			switch strings.ToLower(strings.TrimSpace(sc.Type)) {
			case "", "compose":
				sources = append(sources, &capture.ComposeSource{Paths: sc.Paths, Autodiscover: sc.Autodiscover, BackupDir: bd})
			case "dockge":
				sources = append(sources, &capture.DockgeSource{StacksDirs: sc.Paths, Autodetect: sc.Autodiscover, ExtraRoots: sc.ExtraRoots, DockgeCompose: sc.DockgeCompose, BackupDir: bd})
			default:
				fmt.Fprintf(stdout, "source %q: type %q not implemented (file-based compose only) — skipping\n", sc.Name, sc.Type)
			}
		}
	default:
		return errors.New("capture: provide --stacks-path or --config (with a sources: block)")
	}

	if *doVerify && gate == nil {
		if cfg == nil {
			return errors.New("capture: --verify requires --config (to build the trust gate)")
		}
		g, err := buildVerifyGate(cfg)
		if err != nil {
			return err
		}
		gate = g
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
				var pin capture.Pin
				if *digestFlag != "" {
					pin = capture.Pin{IndexDigest: *digestFlag, IsIndex: true}
				} else {
					p, rerr := resolve(ctx, ref)
					if rerr != nil {
						fmt.Fprintf(stdout, "  - %s: resolve error: %v\n", r.Service, rerr)
						continue
					}
					pin = p
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
				pinnedRef := r.Ref
				if !strings.Contains(pinnedRef, "@") {
					pinnedRef = r.Ref + "@" + pin.IndexDigest
				}
				if *apply {
					applied, err := src.WritePin(ctx, prop)
					if err != nil {
						fmt.Fprintf(stdout, "  - %s: WRITE FAILED: %v\n", r.Service, err)
						continue
					}
					fmt.Fprintf(stdout, "  - %s: pinned %s (backup %s)\n", r.Service, pinnedRef, applied.BackupPath)
					if pins != nil {
						_ = pins.Set(tgt.Name+"/"+r.Service, store.PinRecord{
							Ref: r.Ref, IndexDigest: pin.IndexDigest, MediaType: pin.MediaType,
							Arches: pin.Arches, Source: "file:" + tgt.Name, ComposePath: tgt.Path,
							BackupPath: applied.BackupPath, Service: r.Service, CanaryState: "candidate",
						})
					}
				} else {
					fmt.Fprintf(stdout, "  - %s (line %d):\n      %s\n", r.Service, prop.Line, strings.ReplaceAll(prop.Diff, "\n", "\n      "))
				}
				if *doVerify && gate != nil {
					v := gate.Evaluate(ctx, verify.Input{PinnedRef: pinnedRef})
					fmt.Fprintf(stdout, "      verify: %s — %s\n", v.Decision, v.Summary())
				}
			}
		}
	}
	if *apply && *dataDir == "" {
		fmt.Fprintln(stdout, "note: --data-dir not set; pins were applied but not recorded in pins.json")
	}
	return nil
}
