package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/reconcile"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// reconcileResolver adapts the registry client (or a fixed --digest) to
// reconcile.IndexResolver.
type reconcileResolver struct {
	client       *registry.Client
	digest       string // when set, skip registry resolution (air-gapped / single target)
	requireIndex bool
}

func (r reconcileResolver) ResolveIndex(ctx context.Context, ref string) (store.PinRecord, error) {
	if d := strings.TrimSpace(r.digest); d != "" {
		// Operator-supplied override (air-gapped / single target): validate it
		// is a canonical digest before trusting it as a pin — never splice raw input.
		d = strings.ToLower(d)
		if !registry.IsSHA256Digest(d) {
			return store.PinRecord{}, fmt.Errorf("reconcile: --digest %q is not a canonical sha256:<64-hex> digest", r.digest)
		}
		return store.PinRecord{IndexDigest: d}, nil
	}
	parsed, err := registry.Parse(ref)
	if err != nil {
		return store.PinRecord{}, err
	}
	info, err := r.client.ResolveManifest(ctx, parsed)
	if err != nil {
		return store.PinRecord{}, err
	}
	if r.requireIndex && !info.IsIndex {
		return store.PinRecord{}, fmt.Errorf("reconcile: %q resolved to a single-arch (non-index) manifest; require-index is set", ref)
	}
	return store.PinRecord{IndexDigest: info.Digest, MediaType: info.MediaType, Arches: info.Arches}, nil
}

func cmdReconcile(args []string, stdout, stderr io.Writer) error {
	return cmdReconcileWith(args, stdout, stderr, nil, nil)
}

// cmdReconcileWith runs the trust engine reconcile: resolve the pinned index digest for a
// detected update, evaluate the trust gate, and (per an internal note) queue a verified
// update as a canary candidate for MANUAL promotion, or hold a blocked one.
// resolve/gate may be injected for tests; nil builds them from config.
func cmdReconcileWith(args []string, stdout, stderr io.Writer, resolve reconcile.IndexResolver, gate reconcile.Verdicter) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("ref", "", "image reference of the detected update, e.g. \"nginx:1.27\" (required)")
	stack := fs.String("stack", "", "stack name (the pins key is <stack>/<service>) (required)")
	service := fs.String("service", "", "service name (required)")
	configPath := fs.String("config", "", "config file (to build the trust gate)")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir for pins.json + audit log")
	composePath := fs.String("compose-path", "", "host compose file for this service (recorded for later rollback)")
	source := fs.String("source", "reconcile", "source label recorded on the pin")
	digest := fs.String("digest", "", "pin to this exact sha256 digest, skipping registry resolution")
	requireIndex := fs.Bool("require-index", true, "reject a ref that resolves to a single-arch (non-index) manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*ref) == "" || strings.TrimSpace(*stack) == "" || strings.TrimSpace(*service) == "" {
		return errors.New("reconcile: --ref, --stack and --service are required")
	}

	var cfg *config.Config
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = c
	}

	if gate == nil {
		if cfg == nil {
			return errors.New("reconcile: --config is required to build the trust gate")
		}
		g, err := buildVerifyGate(cfg)
		if err != nil {
			return err
		}
		gate = g
	}
	if resolve == nil {
		resolve = reconcileResolver{client: registry.New(), digest: *digest, requireIndex: *requireIndex}
	}

	var pins reconcile.Recorder
	var audit reconcile.Auditor
	if strings.TrimSpace(*dataDir) != "" {
		pins = store.OpenPinStore(*dataDir)
		if st, err := store.Open(*dataDir); err == nil {
			audit = st
		}
	}

	r := &reconcile.Reconciler{Resolve: resolve, Gate: gate, Pins: pins, Audit: audit}
	out, err := r.Reconcile(context.Background(), reconcile.Update{
		Ref:         *ref,
		Stack:       *stack,
		Service:     *service,
		ComposePath: *composePath,
		Source:      *source,
	})
	if err != nil {
		return err
	}

	switch {
	case out.Held:
		fmt.Fprintf(stdout, "reconcile: %s HELD (gate: %s) %s\n", out.Key, out.Decision, out.PinnedRef)
	case out.Queued:
		fmt.Fprintf(stdout, "reconcile: %s QUEUED as candidate for manual promotion (gate: %s) %s\n", out.Key, out.Decision, out.PinnedRef)
	default:
		fmt.Fprintf(stdout, "reconcile: %s no action (gate: %s)\n", out.Key, out.Decision)
	}
	for _, reason := range out.Reasons {
		fmt.Fprintf(stdout, "  - %s\n", reason)
	}
	if out.Queued {
		fmt.Fprintf(stdout, "next: promote manually with `bulwark canary start --data-dir %s <stack>/<service>`\n", *dataDir)
	}
	return nil
}
