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

// a hardening tier fault injection: what happens to the admission decision when the
// pin-store READ fails (corrupted file, bad permissions, a crashed writer
// leaving a half-renamed path, etc.)?
//
// internal/admit.Engine never touches a pin store itself -- it only consumes
// an already-resolved admit.Image{Pinned bool, PinSource string}. The actual
// pin-store read lives one layer up, in admitPinState() (cmd/bulwark/admit.go),
// backed by store.PinStore (internal/store/pins.go). That is the real
// boundary where a "pin-store read error" can be injected, so the fault
// injection tests live here rather than in internal/admit.
//
// store.PinStore.Get (internal/store/pins.go:110-119) swallows any load()
// error and returns (PinRecord{}, false) -- a signature indistinguishable
// from "no pin was ever recorded for this key". admitPinState then falls
// through to its unpinned case with NO error and NO distinguishing
// PinSource. Whether the resulting admission decision fails closed depends
// entirely on the operator's configured --pin-mode:
//
//   - --pin-mode=block: unpinned still blocks, so the read error happens to
//     fail closed -- but only as a side effect of the pin-mode, not because
//     the read failure itself is handled.
//   - --pin-mode=warn (cmdAdmitWith's own default) or --pin-mode=off: a
//     genuinely pinned, previously-trust-verified image is silently
//     downgraded to "unpinned" and the entire the trust engine trust axis
//     (signature/provenance/vulnerability) is skipped, admitting the deploy
//     with only a WARN (exit 0) or no signal at all. This is a real fail-OPEN
//     gap: a storage fault ends up *more* permissive than a healthy read of
//     an untouched pin store would ever be for that image, because the
//     trust axis that WOULD have run on a successful pinned read never runs.
//
// These two tests are fault-injection evidence, not mutation kills: they
// pin the CURRENT (undesired) behavior so it is visible in CI and does not
// regress silently. See the PR description for the minimal fix.

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

// TestAdmitPinState_StoreReadErrorFallsSilentlyToUnpinned documents the
// swallow at the admitPinState boundary: a pin-store read error produces the
// exact same (pinned=false, source="") result as "never pinned", with no
// error returned or logged anywhere in this call.
func TestAdmitPinState_StoreReadErrorFallsSilentlyToUnpinned(t *testing.T) {
	dataDir := t.TempDir()
	dirAsPinsJSON(t, dataDir)
	ps := store.OpenPinStore(dataDir)

	// Sanity: confirm the injected fault really does surface as a read error
	// at the store layer (List is the one PinStore method with an error
	// return, so it's the cleanest way to prove the fault landed).
	if _, err := ps.List(); err == nil {
		t.Fatal("fault injection did not reach the store: PinStore.List() returned no error for a directory-as-pins.json path")
	}

	pinned, ref, src := admitPinState(
		capture.ImageRef{Service: "app", Raw: "nginx:1.27", Ref: "nginx:1.27"}, "stack", ps)

	if pinned {
		t.Fatalf("expected the read-error fallthrough to report unpinned, got pinned=true ref=%q src=%q", ref, src)
	}
	if src != "" {
		t.Fatalf("expected an empty PinSource on the read-error fallthrough (indistinguishable from never-pinned), got %q", src)
	}
}

// TestCmdAdmit_PinStoreReadErrorAdmitsUnderDefaultWarnMode is the
// end-to-end fault injection: a service WAS legitimately pinned (a capture
// recorded a digest for it), but by the time `admit` runs, pins.json has
// become unreadable. Under cmdAdmitWith's own default enforcement
// (--pin-mode=warn), the current behavior is to ADMIT the deploy (exit 0)
// with the trust axis silently skipped, rather than failing closed on the
// storage fault.
func TestCmdAdmit_PinStoreReadErrorAdmitsUnderDefaultWarnMode(t *testing.T) {
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
	// ...but by the time admit runs, the pin store is unreadable (disk
	// corruption, bad permissions, a writer crashing mid-rename -- any
	// real-world "pin-store read error"). Simulate it.
	dirAsPinsJSON(t, data)

	var out, errb bytes.Buffer
	// No --pin-mode flag: exercises cmdAdmitWith's own default (warn).
	err := admitDo(t, []string{"--data-dir", data, cpath}, &out, &errb)

	// CURRENT (undesired) behavior: admits despite the storage fault. If
	// this assertion starts failing, the gap described in the PR has been
	// fixed -- update this test (and remove the "known gap" framing) rather
	// than loosening the assertion.
	if err != nil {
		t.Fatalf("documenting CURRENT behavior: admit unexpectedly failed closed on a pin-store read error (%v) -- if intentional, this is a fix for the fail-open gap, update this test's framing:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "UNPINNED") {
		t.Fatalf("expected the read-error fallthrough to report UNPINNED:\n%s", out.String())
	}
	if strings.Contains(out.String(), "trust:") {
		t.Fatalf("expected the trust axis to have been skipped entirely (no gate consulted) for the read-error fallthrough:\n%s", out.String())
	}
}

// admitDo is a small wrapper so the fault-injection test above reads as
// "run admit" rather than threading a fake gate literal through it; the fake
// gate mirrors admitFakeGate (admit_test.go) but its exact verdict is
// irrelevant here since the point is that it must NOT be consulted at all.
func admitDo(t *testing.T, args []string, stdout, stderr *bytes.Buffer) error {
	t.Helper()
	return cmdAdmitWith(args, stdout, stderr, admitFakeGate{})
}
