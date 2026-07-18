package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/store"
	"github.com/ranklancer/bulwark/internal/verify"
)

func TestCmdCanary_Lifecycle(t *testing.T) {
	dir := t.TempDir()
	dataDir := t.TempDir()
	stack := filepath.Join(dir, "web")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stack, "compose.yaml")
	orig := "services:\n  web:\n    image: nginx:1.27\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	var out, eb bytes.Buffer

	// capture --apply creates the pin (candidate) and edits the compose in place.
	if err := cmdCaptureWith([]string{"--stacks-path", dir, "--data-dir", dataDir, "--apply"}, &out, &eb, fakeResolve(digest, true), nil); err != nil {
		t.Fatalf("capture apply: %v (%s)", err, eb.String())
	}
	key := "web/web"

	// start: candidate -> canary
	out.Reset()
	if err := cmdCanary([]string{"start", "--data-dir", dataDir, key}, &out, &eb); err != nil {
		t.Fatalf("start: %v", err)
	}
	// a second start is an illegal transition.
	if err := cmdCanary([]string{"start", "--data-dir", dataDir, key}, &out, &eb); err == nil {
		t.Error("second start must be an illegal transition")
	}

	// status shows the canary state.
	out.Reset()
	if err := cmdCanary([]string{"status", "--data-dir", dataDir}, &out, &eb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "canary") {
		t.Errorf("status should show canary state:\n%s", out.String())
	}

	// promote is refused on a block verdict.
	blockGate := fakeGate{v: verify.Verdict{Decision: verify.DecisionBlock, Reasons: []string{"signature: untrusted"}}}
	if err := cmdCanaryWith([]string{"promote", "--data-dir", dataDir, key}, &out, &eb, blockGate); err == nil {
		t.Error("promote must be refused on a block verdict")
	}
	if rec, _, _ := store.OpenPinStore(dataDir).Get(key); rec.CanaryState != store.CanaryActive {
		t.Errorf("state after refused promote = %q, want canary", rec.CanaryState)
	}

	// promote succeeds on an allow verdict.
	allowGate := fakeGate{v: verify.Verdict{Decision: verify.DecisionAllow, Reasons: []string{"signature: trusted"}}}
	out.Reset()
	if err := cmdCanaryWith([]string{"promote", "--data-dir", dataDir, key}, &out, &eb, allowGate); err != nil {
		t.Fatalf("promote allow: %v", err)
	}
	if rec, _, _ := store.OpenPinStore(dataDir).Get(key); rec.CanaryState != store.CanaryPromoted {
		t.Errorf("state after promote = %q, want promoted", rec.CanaryState)
	}

	// rollback restores the compose file byte-identical and marks rolled-back.
	out.Reset()
	if err := cmdCanary([]string{"rollback", "--data-dir", dataDir, key}, &out, &eb); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != orig {
		t.Errorf("rollback did not restore original:\n got %q\nwant %q", got, orig)
	}
	if rec, _, _ := store.OpenPinStore(dataDir).Get(key); rec.CanaryState != store.CanaryRolledBack {
		t.Errorf("state after rollback = %q, want rolled-back", rec.CanaryState)
	}
}

// TestCmdCanary_RollbackRefusesManagedPin: an API/DB-managed pin (no file
// backup) must be refused with a LOUD "manual rollback required" and must NOT be
// marked rolled-back (no false success).
func TestCmdCanary_RollbackRefusesManagedPin(t *testing.T) {
	dataDir := t.TempDir()
	ps := store.OpenPinStore(dataDir)
	key := "portainer-web/web"
	if err := ps.Set(key, store.PinRecord{
		Ref: "nginx:1.27", IndexDigest: "sha256:" + strings.Repeat("a", 64),
		Source: "managed:portainer-web", ComposePath: "7", Service: "web",
		CanaryState: store.CanaryActive,
	}); err != nil {
		t.Fatal(err)
	}
	var out, eb bytes.Buffer
	err := cmdCanary([]string{"rollback", "--data-dir", dataDir, key}, &out, &eb)
	if err == nil {
		t.Fatal("rollback of a managed pin must be refused")
	}
	if !strings.Contains(err.Error(), "MANUAL ROLLBACK REQUIRED") {
		t.Errorf("error must loudly require manual rollback, got: %v", err)
	}
	if rec, _, _ := ps.Get(key); rec.CanaryState == store.CanaryRolledBack {
		t.Error("a managed pin must NOT be marked rolled-back (false success)")
	}
}
