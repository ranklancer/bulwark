package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/capture"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

func fakeResolve(digest string, isIndex bool) pinResolver {
	return func(_ context.Context, _ registry.Reference) (capture.Pin, error) {
		return capture.Pin{IndexDigest: digest, IsIndex: isIndex, MediaType: "application/vnd.oci.image.index.v1+json"}, nil
	}
}

func TestCmdCapture_DryRunProposesAndSkips(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "web")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  web:\n    image: nginx:1.27\n  cache:\n    image: redis:latest\n"
	if err := os.WriteFile(filepath.Join(stack, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	var out, errbuf bytes.Buffer
	if err := cmdCaptureWith([]string{"--stacks-path", dir}, &out, &errbuf, fakeResolve(digest, true), nil); err != nil {
		t.Fatalf("cmdCaptureWith: %v (stderr=%s)", err, errbuf.String())
	}
	got := out.String()
	if !strings.Contains(got, "nginx:1.27@"+digest) {
		t.Errorf("expected proposed pin for web; got:\n%s", got)
	}
	if !strings.Contains(got, "cache: skip") {
		t.Errorf("expected redis:latest to be skipped; got:\n%s", got)
	}
	// Dry-run must not modify the file.
	after, _ := os.ReadFile(filepath.Join(stack, "compose.yaml"))
	if string(after) != compose {
		t.Error("dry-run modified the compose file")
	}
}

func TestCmdCapture_ApplyWritesAndRecordsPins(t *testing.T) {
	dir := t.TempDir()
	dataDir := t.TempDir()
	stack := filepath.Join(dir, "web")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stack, "compose.yaml")
	if err := os.WriteFile(path, []byte("services:\n  web:\n    image: nginx:1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	var out, errbuf bytes.Buffer
	if err := cmdCaptureWith([]string{"--stacks-path", dir, "--data-dir", dataDir, "--apply"}, &out, &errbuf, fakeResolve(digest, true), nil); err != nil {
		t.Fatalf("apply: %v (%s)", err, errbuf.String())
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "nginx:1.27@"+digest) {
		t.Errorf("compose not pinned in place:\n%s", got)
	}
	pins, _ := store.OpenPinStore(dataDir).List()
	if rec, ok := pins["web/web"]; !ok || rec.IndexDigest != digest {
		t.Errorf("pin not recorded in pins.json: %+v", pins)
	}
}

func TestCmdPin_ListAndRollback(t *testing.T) {
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
	digest := "sha256:" + strings.Repeat("f", 64)
	var out, errbuf bytes.Buffer
	if err := cmdCaptureWith([]string{"--stacks-path", dir, "--data-dir", dataDir, "--apply"}, &out, &errbuf, fakeResolve(digest, true), nil); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdPinList([]string{"--data-dir", dataDir}, &out, &errbuf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "web/web") {
		t.Errorf("pin list missing key:\n%s", out.String())
	}
	out.Reset()
	if err := cmdPinRollback([]string{"--data-dir", dataDir, "web/web"}, &out, &errbuf); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != orig {
		t.Errorf("rollback did not restore original:\n got %q\nwant %q", got, orig)
	}
}

type fakeGate struct{ v verify.Verdict }

func (f fakeGate) Evaluate(_ context.Context, _ verify.Input) verify.Verdict { return f.v }

func TestCmdCapture_VerifyReportsVerdict(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "web")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stack, "compose.yaml"), []byte("services:\n  web:\n    image: nginx:1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	gate := fakeGate{v: verify.Verdict{Decision: verify.DecisionWarn, Reasons: []string{"signature: untrusted or unsigned"}}}
	var out, errbuf bytes.Buffer
	if err := cmdCaptureWith([]string{"--stacks-path", dir, "--verify"}, &out, &errbuf, fakeResolve(digest, true), gate); err != nil {
		t.Fatalf("capture --verify: %v (%s)", err, errbuf.String())
	}
	if !strings.Contains(out.String(), "verify: warn") {
		t.Errorf("expected a warn verdict reported; got:\n%s", out.String())
	}
}
