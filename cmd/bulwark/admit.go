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
			pinned, pinnedRef, source, perr := admitPinState(r, name, pins)
			img.Pinned, img.PinnedRef, img.PinSource = pinned, pinnedRef, source
			if perr != nil {
				// Case 3 (the admission-gate design fail-closed pin-state model): the pin store's
				// underlying file could not be read or parsed for this image, so
				// its pin state is UNKNOWN. admit.Image.PinStoreErr makes
				// Engine.Admit fail closed regardless of --pin-mode. The raw
				// filesystem error (which can embed local paths) goes to stderr
				// only, for operator diagnosis -- never into the admission
				// report on stdout/JSON.
				img.PinStoreErr = perr
				fmt.Fprintf(stderr, "admit: warning: pin-store read failed for %s/%s: %v\n", name, r.Service, perr)
			}
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
func admitPinState(r capture.ImageRef, target string, pins *store.PinStore) (pinned bool, pinnedRef, source string, storeErr error) {
	if hasSHA256Digest(r.Raw) {
		return true, r.Raw, "literal", nil
	}
	if exp := strings.TrimSpace(r.Ref); exp != "" && exp != strings.TrimSpace(r.Raw) && hasSHA256Digest(exp) {
		return true, exp, "var", nil
	}
	if pins != nil {
		rec, ok, err := pins.Get(target + "/" + r.Service)
		if err != nil {
			// Pin-store read/parse error (case 3): the pin state for this
			// image is UNKNOWN, distinct from "genuinely never pinned"
			// (ok=false, err=nil). The caller (cmdAdmitWith) fails closed on
			// this via admit.Image.PinStoreErr regardless of --pin-mode.
			return false, r.Raw, "", err
		}
		if ok && strings.TrimSpace(rec.IndexDigest) != "" {
			base := r.Raw
			if strings.TrimSpace(rec.Ref) != "" {
				base = rec.Ref // the captured repo ref, never a raw ${VAR} literal
			}
			// Hardening (#64/#67): report a store-sourced pin only when a
			// well-formed digest-pinned reference can be POSITIVELY composed.
			// composeStorePin fails closed on an unresolved variable of any
			// form (${VAR}, ${VAR:-x}, or bare $VAR), a base already carrying
			// an "@" (which would double the "@sha256:"), a non-canonical
			// stored digest, or an unparseable base. Anything it cannot attest
			// falls through to unpinned rather than emitting a malformed ref.
			if pinnedRef, ok := composeStorePin(base, rec.IndexDigest); ok {
				return true, pinnedRef, "store", nil
			}
		}
	}
	return false, r.Raw, "", nil
}

// hasSHA256Digest reports whether ref carries a canonical @sha256:<64hex> digest.
func hasSHA256Digest(ref string) bool {
	at := strings.LastIndex(ref, "@")
	return at >= 0 && registry.IsSHA256Digest(strings.ToLower(ref[at+1:]))
}

// composeStorePin composes a digest-pinned reference from a base image
// reference and a store-recorded digest, returning ok=true ONLY when the
// result is a well-formed, positively verifiable pinned reference. It fails
// closed (ok=false) on: an unresolved variable placeholder of any form
// (${VAR}, ${VAR:-def}, or a bare $VAR — a '$' is never valid in a Docker
// image reference, so its presence means an unexpanded variable that cannot
// be attested); a base already containing '@' (which would yield a doubled
// '@sha256:'); a stored digest that is not a canonical sha256:<64hex>; or a
// base that is not a parseable image reference.
func composeStorePin(base, digest string) (string, bool) {
	base = strings.TrimSpace(base)
	digest = strings.TrimSpace(digest)
	if strings.ContainsRune(base, '$') {
		return "", false
	}
	if strings.Contains(base, "@") {
		return "", false
	}
	// Reject any character outside the image-reference grammar
	// (registry[:port]/name[:tag]); registry.Parse is permissive, so this
	// catches junk like whitespace or shell metacharacters before we
	// splice a digest onto it.
	if strings.IndexFunc(base, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return false
		case r == '.' || r == '_' || r == '/' || r == ':' || r == '-':
			return false
		default:
			return true
		}
	}) >= 0 {
		return "", false
	}
	if !registry.IsSHA256Digest(strings.ToLower(digest)) {
		return "", false
	}
	if _, err := registry.Parse(base); err != nil {
		return "", false
	}
	return base + "@" + digest, true
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
