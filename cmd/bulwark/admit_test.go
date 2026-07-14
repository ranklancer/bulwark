package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/capture"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

// admitFakeGate implements admit.TrustGate: allow everything (so the test isolates
// the pin-state axis + exit-code behavior without real verifiers).
type admitFakeGate struct{}

func (admitFakeGate) Evaluate(_ context.Context, _ verify.Input) verify.Verdict {
	return verify.Verdict{Decision: verify.DecisionAllow}
}

func writeComposeFile(t *testing.T, dir string) string {
	t.Helper()
	body := "services:\n" +
		"  web:\n" +
		"    image: nginx@sha256:" + strings.Repeat("a", 64) + "\n" +
		"  cache:\n" +
		"    image: redis:7\n"
	p := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCmdAdmit_PinBlockRefusesUnpinned(t *testing.T) {
	f := writeComposeFile(t, t.TempDir())
	var out, errb bytes.Buffer
	err := cmdAdmitWith([]string{"--pin-mode", "block", f}, &out, &errb, admitFakeGate{})
	if err == nil {
		t.Fatalf("unpinned image under --pin-mode block must return a (non-zero) error; out=%s", out.String())
	}
	if !strings.Contains(out.String(), "BLOCK") || !strings.Contains(out.String(), "UNPINNED") {
		t.Fatalf("report should flag the UNPINNED/BLOCK image:\n%s", out.String())
	}
}

func TestCmdAdmit_PinWarnProceeds(t *testing.T) {
	f := writeComposeFile(t, t.TempDir())
	var out, errb bytes.Buffer
	err := cmdAdmitWith([]string{"--pin-mode", "warn", f}, &out, &errb, admitFakeGate{})
	if err != nil {
		t.Fatalf("warn-mode must proceed (exit 0): %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "admission: WARN") {
		t.Fatalf("aggregate should be WARN (one unpinned image):\n%s", out.String())
	}
}

func TestCmdAdmit_JSONFormat(t *testing.T) {
	f := writeComposeFile(t, t.TempDir())
	var out, errb bytes.Buffer
	if err := cmdAdmitWith([]string{"--pin-mode", "off", "--format", "json", f}, &out, &errb, admitFakeGate{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\"decision\": \"allow\"") {
		t.Fatalf("json report missing allow decision:\n%s", out.String())
	}
}

func TestCmdAdmit_NoFile(t *testing.T) {
	var out, errb bytes.Buffer
	if err := cmdAdmitWith(nil, &out, &errb, admitFakeGate{}); err == nil {
		t.Fatal("missing compose file must be an error")
	}
}

func TestCmdAdmit_VarExpandedDigestUnpinned(t *testing.T) {
	dir := t.TempDir()
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  app:\n    image: nginx@${DIGEST}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DIGEST="+digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	// The digest arrives via ${VAR} expansion; Phase 1 treats that as UNPINNED
	// (r.Raw keeps ${DIGEST}). Under block mode that must refuse the deploy.
	err := cmdAdmitWith([]string{"--pin-mode", "block", filepath.Join(dir, "compose.yaml")}, &out, &errb, admitFakeGate{})
	if err == nil || !strings.Contains(out.String(), "UNPINNED") {
		t.Fatalf("var-expanded digest must read as UNPINNED in Phase 1:\nerr=%v\n%s", err, out.String())
	}
}

func TestCmdAdmit_PinStoreKeyMatchesCapture(t *testing.T) {
	dir := t.TempDir()
	cpath := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(cpath, []byte("services:\n  cache:\n    image: redis:7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Record a pin the way `bulwark capture` does: key = StackName(path)/service.
	data := t.TempDir()
	ps := store.OpenPinStore(data)
	if err := ps.Set(capture.StackName(cpath)+"/cache", store.PinRecord{Ref: "redis:7", IndexDigest: "sha256:" + strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	// With the correct (stackName) key derivation the tag-only image resolves as
	// PINNED from the store, so block mode does not refuse it.
	if err := cmdAdmitWith([]string{"--pin-mode", "block", "--data-dir", data, cpath}, &out, &errb, admitFakeGate{}); err != nil {
		t.Fatalf("pin-store hit should make the image pinned (no block): %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "UNPINNED") {
		t.Fatalf("pin-store keyed image must not read as UNPINNED:\n%s", out.String())
	}
}
