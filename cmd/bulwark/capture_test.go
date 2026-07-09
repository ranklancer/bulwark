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
)

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
	resolve := func(_ context.Context, _ registry.Reference) (capture.Pin, error) {
		return capture.Pin{IndexDigest: digest, IsIndex: true, Arches: []string{"linux/amd64", "linux/arm64"}}, nil
	}
	var out, errbuf bytes.Buffer
	if err := cmdCaptureWith([]string{"--stacks-path", dir}, &out, &errbuf, resolve); err != nil {
		t.Fatalf("cmdCaptureWith: %v (stderr=%s)", err, errbuf.String())
	}
	got := out.String()
	if !strings.Contains(got, "nginx:1.27@"+digest) {
		t.Errorf("expected proposed pin for web; got:\n%s", got)
	}
	if !strings.Contains(got, "cache: skip") {
		t.Errorf("expected redis:latest to be skipped; got:\n%s", got)
	}
}

func TestCmdCapture_ApplyRefusedInPhase1(t *testing.T) {
	var out, errbuf bytes.Buffer
	err := cmdCaptureWith([]string{"--stacks-path", "/tmp/x", "--apply"}, &out, &errbuf, nil)
	if err == nil || !strings.Contains(err.Error(), "Phase 2") {
		t.Fatalf("--apply must be refused in Phase 1, got %v", err)
	}
}
