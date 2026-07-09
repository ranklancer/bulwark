package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestComposeSource_DiscoverFlatDockge(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "sonarr", "compose.yaml"), "services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:4.0.10\n")
	writeFile(t, filepath.Join(root, "redis", "docker-compose.yml"), "services:\n  redis:\n    image: redis:7.2\n")
	writeFile(t, filepath.Join(root, "notes.txt"), "ignore me")

	src := &ComposeSource{Paths: []string{root}, Autodiscover: true}
	targets, err := src.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 targets, got %d: %+v", len(targets), targets)
	}
	names := map[string]bool{}
	for _, tg := range targets {
		names[tg.Name] = true
		if tg.Kind != KindFile {
			t.Errorf("target %s kind=%s, want file", tg.Name, tg.Kind)
		}
	}
	if !names["sonarr"] || !names["redis"] {
		t.Errorf("missing expected stacks: %+v", names)
	}
}

func TestComposeSource_LocateImageRefs_Classification(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "TAG=1.0\n")
	compose := `services:
  web:
    image: nginx:1.27
  cache:
    image: redis:latest
  builder:
    build: .
    image: myorg/app:2.1
  varimg:
    image: ghcr.io/acme/svc:${TAG}
  broken:
    image: ghcr.io/acme/other:${MISSING}
`
	writeFile(t, filepath.Join(dir, "compose.yaml"), compose)
	src := &ComposeSource{}
	target := Target{Name: "t", Path: filepath.Join(dir, "compose.yaml"), Kind: KindFile}
	refs, err := src.LocateImageRefs(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ImageRef{}
	for _, r := range refs {
		by[r.Service] = r
	}
	if r := by["web"]; !r.Pinnable || r.Ref != "nginx:1.27" || r.Line == 0 {
		t.Errorf("web: %+v — want pinnable nginx:1.27 with a line number", r)
	}
	if r := by["cache"]; r.Pinnable {
		t.Errorf("cache (redis:latest) must not be pinnable: %+v", r)
	}
	if r := by["builder"]; r.Pinnable {
		t.Errorf("builder (has build:) must not be pinnable: %+v", r)
	}
	if r := by["varimg"]; r.Ref != "ghcr.io/acme/svc:1.0" || r.Pinnable {
		t.Errorf("varimg: %+v — want expanded ref :1.0 but not pinnable (Phase 2)", r)
	}
	if r := by["broken"]; r.Pinnable || r.Reason == "" {
		t.Errorf("broken (unresolved ${MISSING}) must not be pinnable: %+v", r)
	}
}

func TestComposeSource_ProposePin_And_Idempotent(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	src := &ComposeSource{}
	tgt := Target{Name: "web", Path: "/x/compose.yaml", Kind: KindFile}
	ref := ImageRef{Service: "web", Raw: "nginx:1.27", Ref: "nginx:1.27", Line: 3, Pinnable: true}
	prop, err := src.ProposePin(context.Background(), tgt, ref, Pin{IndexDigest: digest, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if prop.NewValue != "nginx:1.27@"+digest || prop.NoOp {
		t.Fatalf("propose: %+v — want NewValue nginx:1.27@<digest>, not no-op", prop)
	}
	if prop.Line != 3 || !strings.Contains(prop.Diff, digest) {
		t.Errorf("propose diff/line wrong: %+v", prop)
	}
	ref2 := ImageRef{Service: "web", Raw: "nginx:1.27@" + digest, Ref: "nginx:1.27@" + digest, Line: 3, Pinnable: true}
	prop2, err := src.ProposePin(context.Background(), tgt, ref2, Pin{IndexDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if !prop2.NoOp {
		t.Errorf("re-pin to same digest must be a no-op: %+v", prop2)
	}
}
