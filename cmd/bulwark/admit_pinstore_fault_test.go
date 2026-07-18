package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/capture"
	"github.com/ranklancer/bulwark/internal/store"
)

// a hardening tier pin-store fault injection -- now fail-closed (an internal audit fix).
//
// internal/admit.Engine never touches a pin store itself -- it only consumes
// an already-resolved admit.Image{Pinned bool, PinSource string,
// PinStoreErr error}. The actual pin-store read lives one layer up, in
// admitPinState() (cmd/bulwark/admit.go), backed by store.PinStore
// (internal/store/pins.go).
//
// BEFORE this fix, store.PinStore.Get swallowed any load() error and
// returned (PinRecord{}, false) -- a result indistinguishable from "no pin
// was ever recorded for this key". admitPinState then fell through to its
// unpinned case with no error and no distinguishing PinSource, and
// cmdAdmitWith's default --pin-mode=warn (and --pin-mode=off) would ADMIT
// the deploy with the entire the trust engine trust axis silently skipped -- a real
// fail-OPEN gap, distinct from the legitimate "image genuinely never
// pinned" case.
//
// AFTER this fix: store.PinStore.Get returns (PinRecord, bool, error), with
// err non-nil ONLY for a genuine read/parse failure of an EXISTING store
// (a file-absent / empty store is still legitimate not-found, err=nil).
// admitPinState propagates that error; cmdAdmitWith sets
// admit.Image.PinStoreErr; internal/admit.Engine.Admit forces a BLOCK
// decision for that image regardless of --pin-mode (warn/off/block all
// converge on block), with a generic "cannot determine pin state" reason
// that never leaks the underlying filesystem error into the admission
// report.
//
// TestAdmitPinState_StoreReadErrorReturnsError and
// TestCmdAdmit_PinStoreReadErrorFailsClosed assert the fixed behavior.
// TestCmdAdmit_PinStoreLoadsOkGenuinelyUnpinnedWarnAdmits is the case-2
// regression test proving the fix did not change ordinary unpinned-image
// policy semantics.

// dirAsPinsJSON forces a genuine pin-store READ error: pins.json is created
// as a directory instead of a file, so os.ReadFile in PinStore.load() fails
// with a non-NotExist error (EISDIR) regardless of process privilege (unlike
// a permission-bit fault, which root bypasses).
func dirAsPinsJSON(t *testing.T, dataDir string) {
	t.Helper()
	p := filepath.Join(dataDir, "pins.json")
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestAdmitPinState_StoreReadErrorReturnsError is the boundary-level fix
// assertion: a pin-store read error must surface as a non-nil error from
// admitPinState, distinct from the legitimate "never pinned" zero-value
// result (pinned=false, source="", err=nil).
func TestAdmitPinState_StoreReadErrorReturnsError(t *testing.T) {
	dataDir := t.TempDir()
	dirAsPinsJSON(t, dataDir)
	ps := store.OpenPinStore(dataDir)

	// Sanity: confirm the injected fault really does surface as a read
	// error at the store layer (List is the one PinStore method with an
	// error return, so it's the cleanest way to prove the fault landed).
	if _, err := ps.List(); err == nil {
		t.Fatal("fault injection did not reach the store: PinStore.List() returned no error for a directory-as-pins.json path")
	}

	pinned, ref, src, err := admitPinState(
		capture.ImageRef{Service: "app", Raw: "nginx:1.27", Ref: "nginx:1.27"}, "stack", ps)

	if err == nil {
		t.Fatal("expected admitPinState to surface the pin-store read error, got nil")
	}
	if pinned {
		t.Fatalf("a pin-store read error must not report pinned=true: ref=%q src=%q", ref, src)
	}
}

// TestCmdAdmit_PinStoreReadErrorFailsClosed proves the end-to-end fix: a
// service WAS legitimately pinned (a capture recorded a digest for it), but
// by the time `admit` runs, pins.json has become unreadable. This must now
// BLOCK the deploy regardless of --pin-mode -- warn, off, and the explicit
// block mode all converge on the same fail-closed outcome, because the
// pin-store fault means the pin state is UNKNOWN, not "unpinned".
func TestCmdAdmit_PinStoreReadErrorFailsClosed(t *testing.T) {
	for _, mode := range []string{"warn", "off", "block"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cpath := filepath.Join(dir, "compose.yaml")
			if err := os.WriteFile(cpath, []byte("services:\n  app:\n    image: nginx:1.27\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			// A pin WAS legitimately captured for this service...
			data := t.TempDir()
			ps := store.OpenPinStore(data)
			if err := ps.Set(capture.StackName(cpath)+"/app", store.PinRecord{Ref: "nginx:1.27", IndexDigest: "sha256:" + strings.Repeat("d", 64)}); err != nil {
				t.Fatal(err)
			}
			// ...but by the time admit runs, the pin store is unreadable
			// (disk corruption, bad permissions, a writer crashing
			// mid-rename -- any real-world "pin-store read error").
			// Simulate it.
			dirAsPinsJSON(t, data)

			var out, errb bytes.Buffer
			err := admitDo(t, []string{"--pin-mode", mode, "--data-dir", data, cpath}, &out, &errb)

			if err == nil {
				t.Fatalf("pin-mode=%s: a pin-store read error must fail closed (non-zero exit) regardless of pin-mode:\n%s", mode, out.String())
			}
			if !strings.Contains(out.String(), "BLOCK") {
				t.Fatalf("pin-mode=%s: report must show BLOCK:\n%s", mode, out.String())
			}
			if !strings.Contains(out.String(), "cannot determine pin state") {
				t.Fatalf("pin-mode=%s: report must carry the fail-closed reason:\n%s", mode, out.String())
			}
			// The trust axis must not have been consulted -- an unresolved
			// pin state means there's nothing safe to hand the gate.
			if strings.Contains(out.String(), "trust:") {
				t.Fatalf("pin-mode=%s: trust axis must be skipped on an unresolved pin state:\n%s", mode, out.String())
			}
			// The report must never leak the underlying filesystem detail
			// (e.g. the data-dir path) into the admission output.
			if strings.Contains(out.String(), data) {
				t.Fatalf("pin-mode=%s: admission report leaked the data-dir path:\n%s", mode, out.String())
			}
		})
	}
}

// TestCmdAdmit_PinStoreLoadsOkGenuinelyUnpinnedWarnAdmits is the case-2
// regression test: the pin store loads fine (no read/parse error) but
// genuinely has no pin recorded for this image. This is NOT a pin-store
// fault -- it is the ordinary "never captured" case -- and under warn-mode
// it must still ADMIT (exit 0, WARN decision), proving the case-3
// fail-closed fix above did not change case-2 policy semantics.
func TestCmdAdmit_PinStoreLoadsOkGenuinelyUnpinnedWarnAdmits(t *testing.T) {
	dir := t.TempDir()
	cpath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(cpath, []byte("services:\n  app:\n    image: nginx:1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A real, readable, empty pin store -- no pin was ever captured for
	// this image. This is legitimate not-found, not a read error.
	data := t.TempDir()
	ps := store.OpenPinStore(data)
	if _, err := ps.List(); err != nil {
		t.Fatalf("expected a healthy empty store to load without error: %v", err)
	}

	var out, errb bytes.Buffer
	err := admitDo(t, []string{"--pin-mode", "warn", "--data-dir", data, cpath}, &out, &errb)

	if err != nil {
		t.Fatalf("case 2 (genuinely unpinned, warn-mode) must still admit (exit 0): %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "admission: WARN") {
		t.Fatalf("expected a WARN aggregate for the genuinely-unpinned image:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "UNPINNED") {
		t.Fatalf("expected the image to report UNPINNED (not a store-error block):\n%s", out.String())
	}
	if strings.Contains(out.String(), "cannot determine pin state") {
		t.Fatalf("case 2 must not be confused with the case-3 pin-store-error path:\n%s", out.String())
	}
}

// admitDo runs cmdAdmitWith with a fixed allow-everything trust gate, so the
// fault-injection / regression tests above read as "run admit" instead of
// threading the fake gate literal through each one. In the pin-store-error
// cases the gate's exact verdict is irrelevant because it must not be
// consulted at all.
func admitDo(t *testing.T, args []string, stdout, stderr *bytes.Buffer) error {
	t.Helper()
	return cmdAdmitWith(args, stdout, stderr, admitFakeGate{})
}
