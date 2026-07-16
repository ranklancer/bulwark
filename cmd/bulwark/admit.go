package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ranklancer/bulwark/internal/admit"
	"github.com/ranklancer/bulwark/internal/capture"
	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/verify"
)

// cmdAdmit is the admission-gate design Phase 1 deploy-time admission gate. It resolves the
// images in one or more compose files, evaluates the pin-state axis plus the trust engine
// trust engine per image, prints a report, and returns a non-zero (error) exit
// when the aggregate verdict is BLOCK — so it composes as:
//
//	bulwark admit compose.yaml && docker compose up
func cmdAdmit(args []string, stdout, stderr io.Writer) error {
	return cmdAdmitWith(args, stdout, stderr, nil)
}

// cmdAdmitWith allows a test to inject the trust gate; nil => build it from
// config via the same wiring the daemon and capture use (buildVerifyGate).
func cmdAdmitWith(args []string, stdout, stderr io.Writer, gate admit.TrustGate) error {
	fs := flag.NewFlagSet("admit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "config file (verify policy + trust verifiers)")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir for pins.json (pin-state axis)")
	pinModeStr := fs.String("pin-mode", "warn", "pin-state axis enforcement: off|warn|block")
	format := fs.String("format", "text", "report format: text|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	if len(files) == 0 {
		return errors.New("admit: need at least one compose file (usage: bulwark admit [flags] <compose.yaml>...)")
	}
	pinMode, err := verify.ParseMode(*pinModeStr)
	if err != nil {
		return fmt.Errorf("admit: --pin-mode: %w", err)
	}

	if gate == nil {
		cfg := &config.Config{}
		if strings.TrimSpace(*configPath) != "" {
			c, err := config.Load(*configPath)
			if err != nil {
				return fmt.Errorf("admit: load config: %w", err)
			}
			cfg = c
		}
		g, err := buildVerifyGate(cfg)
		if err != nil {
			return fmt.Errorf("admit: build trust gate: %w", err)
		}
		gate = g
	}

	var pins *store.PinStore
	if strings.TrimSpace(*dataDir) != "" {
		pins = store.OpenPinStore(*dataDir)
	}

	ctx := context.Background()
	cs := &capture.ComposeSource{}
	var images []admit.Image
	for _, f := range files {
		name := capture.StackName(f)
		refs, err := cs.LocateImageRefs(ctx, capture.Target{Name: name, Path: f, Kind: capture.KindFile})
		if err != nil {
			return fmt.Errorf("admit: read %s: %w", f, err)
		}
		for _, r := range refs {
			img := admit.Image{Service: r.Service, Ref: r.Raw}
			img.Pinned, img.PinnedRef, img.PinSource = admitPinState(r, name, pins)
			images = append(images, img)
		}
	}
	if len(images) == 0 {
		fmt.Fprintln(stdout, "admit: no image references found in the given compose file(s)")
		return nil
	}

	v := admit.Engine{Policy: admit.Policy{Pin: pinMode}, Gate: gate}.Admit(ctx, images)
	if err := writeAdmitReport(stdout, v, *format); err != nil {
		return err
	}
	if v.Blocked() {
		return fmt.Errorf("admit: BLOCKED — %d image(s) failed a block-mode axis (deploy refused)", admitCountBlocked(v))
	}
	return nil
}

// admitPinState decides whether r is digest-pinned and the PROVENANCE of the pin.
// Precedence: (1) a canonical sha256 digest in the ref AS WRITTEN ("literal");
// (2) a digest that arrives via ${VAR}/.env expansion — the compose parser resolves
// it into r.Ref, which is the concrete reference compose would deploy ("var",
// the admission-gate design Phase 2); (3) a digest recorded by `bulwark capture` under the same
// stackName(path)/<service> key ("store"). r.Raw is the PRE-expansion literal, so
// the literal check never mistakes a var-sourced digest for a hard-coded one, and
// an unresolved ${VAR} (no .env value) yields no digest — read as unpinned.
func admitPinState(r capture.ImageRef, target string, pins *store.PinStore) (pinned bool, pinnedRef, source string) {
	if hasSHA256Digest(r.Raw) {
		return true, r.Raw, "literal"
	}
	if exp := strings.TrimSpace(r.Ref); exp != "" && exp != strings.TrimSpace(r.Raw) && hasSHA256Digest(exp) {
		return true, exp, "var"
	}
	if pins != nil {
		if rec, ok := pins.Get(target + "/" + r.Service); ok && strings.TrimSpace(rec.IndexDigest) != "" {
			base := r.Raw
			if strings.TrimSpace(rec.Ref) != "" {
				base = rec.Ref // the captured repo ref, never a raw ${VAR} literal
			}
			return true, base + "@" + rec.IndexDigest, "store"
		}
	}
	return false, r.Raw, ""
}

// hasSHA256Digest reports whether ref carries a canonical @sha256:<64hex> digest.
func hasSHA256Digest(ref string) bool {
	at := strings.LastIndex(ref, "@")
	return at >= 0 && registry.IsSHA256Digest(strings.ToLower(ref[at+1:]))
}

func admitCountBlocked(v admit.Verdict) int {
	n := 0
	for _, im := range v.Images {
		if im.Decision == admit.DecisionBlock {
			n++
		}
	}
	return n
}

func writeAdmitReport(w io.Writer, v admit.Verdict, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	fmt.Fprintf(w, "admission: %s\n", strings.ToUpper(string(v.Decision)))
	for _, im := range v.Images {
		pin := "pinned"
		if !im.Pinned {
			pin = "UNPINNED"
		} else if im.PinSource != "" && im.PinSource != "literal" {
			pin = "pinned(" + im.PinSource + ")"
		}
		fmt.Fprintf(w, "  [%s] %s (%s) %s\n", strings.ToUpper(string(im.Decision)), im.Service, pin, im.Ref)
		for _, reason := range im.Reasons {
			fmt.Fprintf(w, "      - %s\n", reason)
		}
	}
	return nil
}
