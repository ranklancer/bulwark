package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/capture"
	"github.com/bulwark-docker/bulwark/internal/registry"
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
		return capture.Pin{IndexDigest: info.Digest, IsIndex: info.IsIndex, Arches: info.Arches}, nil
	}
}

// cmdCapture is the digest pinning Phase-1 dry-run capture command: it discovers compose
// stacks, resolves each pinnable image to its multi-arch INDEX digest, and
// prints the inline pin it WOULD apply. It never writes (in-place edits land in
// Phase 2 behind --apply).
func cmdCapture(args []string, stdout, stderr io.Writer) error {
	return cmdCaptureWith(args, stdout, stderr, registryResolver(registry.New()))
}

func cmdCaptureWith(args []string, stdout, stderr io.Writer, resolve pinResolver) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stacks := fs.String("stacks-path", "", "comma-separated stack dirs / globs / compose files to scan")
	autodiscover := fs.Bool("autodiscover", true, "scan <root>/<stack>/ subdirs (flat Dockge layout)")
	requireIndex := fs.Bool("require-index", true, "skip a ref that resolves to a single-arch (non-index) manifest")
	apply := fs.Bool("apply", false, "apply pins in place (digest pinning Phase 2; currently refused)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apply {
		return errors.New("capture: --apply (in-place edit with backup/atomic/rollback) lands in digest pinning Phase 2; this build is dry-run only")
	}
	var paths []string
	for _, p := range strings.Split(*stacks, ",") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return errors.New("capture: --stacks-path is required (config-driven sources: arrive in Phase 2)")
	}
	src := &capture.ComposeSource{Paths: paths, Autodiscover: *autodiscover}
	ctx := context.Background()
	targets, err := src.Discover(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintln(stdout, "capture: no compose stacks found under the given path(s)")
		return nil
	}
	fmt.Fprintf(stdout, "capture (dry-run): %d stack(s)\n", len(targets))
	for _, tgt := range targets {
		fmt.Fprintf(stdout, "  %s (%s)\n", tgt.Name, tgt.Path)
		refs, err := src.LocateImageRefs(ctx, tgt)
		if err != nil {
			fmt.Fprintf(stdout, "    ! error: %v\n", err)
			continue
		}
		for _, r := range refs {
			if !r.Pinnable {
				fmt.Fprintf(stdout, "    - %s: skip (%s)\n", r.Service, r.Reason)
				continue
			}
			ref, err := registry.Parse(r.Ref)
			if err != nil {
				fmt.Fprintf(stdout, "    - %s: skip (unparseable %q)\n", r.Service, r.Ref)
				continue
			}
			pin, err := resolve(ctx, ref)
			if err != nil {
				fmt.Fprintf(stdout, "    - %s: resolve error: %v\n", r.Service, err)
				continue
			}
			if *requireIndex && !pin.IsIndex {
				fmt.Fprintf(stdout, "    - %s: skip (%s is single-arch; --require-index)\n", r.Service, r.Ref)
				continue
			}
			prop, err := src.ProposePin(ctx, tgt, r, pin)
			if err != nil {
				fmt.Fprintf(stdout, "    - %s: %v\n", r.Service, err)
				continue
			}
			if prop.NoOp {
				fmt.Fprintf(stdout, "    - %s: already pinned (no-op)\n", r.Service)
				continue
			}
			arches := ""
			if len(pin.Arches) > 0 {
				arches = " [" + strings.Join(pin.Arches, " ") + "]"
			}
			fmt.Fprintf(stdout, "    - %s (line %d)%s:\n        %s\n", r.Service, prop.Line, arches,
				strings.ReplaceAll(prop.Diff, "\n", "\n        "))
		}
	}
	return nil
}
