package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStack(t *testing.T, root, name, image string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "compose.yaml")
	body := "services:\n  app:\n    image: " + image + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func names(ts []Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestDockgeSource_Kind(t *testing.T) {
	if (&DockgeSource{}).Kind() != KindFile {
		t.Fatal("Dockge must be a file-based source")
	}
}

func TestDockgeSource_DiscoverFlatStacks(t *testing.T) {
	root := t.TempDir()
	writeStack(t, root, "web", "nginx:1.27")
	writeStack(t, root, "db", "postgres:16")
	// noise that must be ignored:
	os.WriteFile(filepath.Join(root, "loose.txt"), []byte("x"), 0o644) // a file, not a stack dir
	os.MkdirAll(filepath.Join(root, "empty"), 0o750)                   // dir with no compose

	got, err := (&DockgeSource{StacksDirs: []string{root}}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gotNames := names(got)
	if len(gotNames) != 2 || !contains(gotNames, "web") || !contains(gotNames, "db") {
		t.Fatalf("Discover = %v, want [web db]", gotNames)
	}
}

func TestDockgeSource_MultipleRootsDedup(t *testing.T) {
	r1, r2 := t.TempDir(), t.TempDir()
	writeStack(t, r1, "a", "nginx:1.27")
	writeStack(t, r2, "b", "caddy:2")
	// same root listed twice must not double-count.
	got, _ := (&DockgeSource{StacksDirs: []string{r1, r2, r1}}).Discover(context.Background())
	if n := len(got); n != 2 {
		t.Fatalf("got %d targets, want 2 (%v)", n, names(got))
	}
}

func TestDockgeSource_SymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	// A legit in-root stack.
	writeStack(t, root, "legit", "nginx:1.27")
	// A stack dir whose compose.yaml is a symlink to a file OUTSIDE the root.
	evilDir := filepath.Join(root, "evil")
	os.MkdirAll(evilDir, 0o750)
	outFile := filepath.Join(outside, "compose.yaml")
	os.WriteFile(outFile, []byte("services:\n  x:\n    image: evil:1\n"), 0o644)
	if err := os.Symlink(outFile, filepath.Join(evilDir, "compose.yaml")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	got := names(mustDiscover(t, &DockgeSource{StacksDirs: []string{root}}))
	if contains(got, "evil") {
		t.Fatalf("symlink-escaping stack must be rejected; got %v", got)
	}
	if !contains(got, "legit") {
		t.Fatalf("legit stack must be discovered; got %v", got)
	}
}

func TestDockgeSource_DelegatesWriteAndIdempotent(t *testing.T) {
	root := t.TempDir()
	p := writeStack(t, root, "web", "nginx:1.27")
	src := &DockgeSource{StacksDirs: []string{root}}
	targets := mustDiscover(t, src)
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	refs, err := src.LocateImageRefs(context.Background(), targets[0])
	if err != nil || len(refs) != 1 {
		t.Fatalf("LocateImageRefs err=%v refs=%d", err, len(refs))
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	prop, err := src.ProposePin(context.Background(), targets[0], refs[0], Pin{IndexDigest: digest, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.WritePin(context.Background(), prop); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "nginx:1.27@"+digest) {
		t.Fatalf("pin not written in place: %q", data)
	}
	// Re-propose against the now-pinned file: must be a no-op (idempotent).
	refs2, _ := src.LocateImageRefs(context.Background(), targets[0])
	prop2, err := src.ProposePin(context.Background(), targets[0], refs2[0], Pin{IndexDigest: digest, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if !prop2.NoOp {
		t.Errorf("re-pin must be a no-op, got %+v", prop2)
	}
}

func TestStacksDirFromDockgeCompose(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
		ok   bool
	}{
		{
			name: "short volume + env list",
			yaml: "services:\n  dockge:\n    image: louislam/dockge:1\n    environment:\n      - DOCKGE_STACKS_DIR=/opt/stacks\n    volumes:\n      - /opt/stacks:/opt/stacks\n",
			want: "/opt/stacks", ok: true,
		},
		{
			name: "long volume + env map + default target",
			yaml: "services:\n  dockge:\n    image: louislam/dockge:1\n    volumes:\n      - type: bind\n        source: /srv/dockge\n        target: /app/stacks\n",
			want: "/srv/dockge", ok: true,
		},
		{
			name: "env map explicit target",
			yaml: "services:\n  dockge:\n    environment:\n      DOCKGE_STACKS_DIR: /data/stacks\n    volumes:\n      - /host/data:/data/stacks:rw\n",
			want: "/host/data", ok: true,
		},
		{
			name: "no matching mount",
			yaml: "services:\n  dockge:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
			want: "", ok: false,
		},
		{
			name: "no services",
			yaml: "version: '3'\n",
			want: "", ok: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := StacksDirFromDockgeCompose([]byte(c.yaml))
			if ok != c.ok || got != c.want {
				t.Fatalf("got (%q,%v) want (%q,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestWithinRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "a", "compose.yaml")
	os.MkdirAll(filepath.Dir(inside), 0o750)
	os.WriteFile(inside, []byte("x"), 0o644)
	if !withinRoot(root, inside) {
		t.Error("in-root path must be contained")
	}
	if withinRoot(root, t.TempDir()) {
		t.Error("a sibling temp dir must not be contained")
	}
}

func mustDiscover(t *testing.T, s *DockgeSource) []Target {
	t.Helper()
	ts, err := s.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func TestDockgeSource_AutodetectFromComposeMount(t *testing.T) {
	base := t.TempDir()
	// The host stacks root, referenced relatively from the Dockge compose.
	stacksRoot := filepath.Join(base, "stacks")
	writeStack(t, stacksRoot, "web", "nginx:1.27")
	// A Dockge compose whose bind-mount source is RELATIVE to its own dir.
	dockgeCompose := filepath.Join(base, "compose.yaml")
	body := "services:\n  dockge:\n    image: louislam/dockge:1\n" +
		"    environment:\n      - DOCKGE_STACKS_DIR=/app/stacks\n" +
		"    volumes:\n      - ./stacks:/app/stacks\n"
	if err := os.WriteFile(dockgeCompose, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	src := &DockgeSource{Autodetect: true, DockgeCompose: dockgeCompose}
	got := names(mustDiscover(t, src))
	if !contains(got, "web") {
		t.Fatalf("autodetect from a relative Dockge bind-mount must find stacks; got %v", got)
	}
}

// TestDockgeSource_WritePinRefusesSymlinkSwapAfterDiscover is the TOCTOU guard:
// the compose file is swapped to an out-of-root symlink AFTER Discover/Propose
// but BEFORE WritePin. The write must be refused and the out-of-root file left
// untouched.
func TestDockgeSource_WritePinRefusesSymlinkSwapAfterDiscover(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	p := writeStack(t, root, "web", "nginx:1.27")
	src := &DockgeSource{StacksDirs: []string{root}}
	targets := mustDiscover(t, src)
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	refs, err := src.LocateImageRefs(context.Background(), targets[0])
	if err != nil || len(refs) != 1 {
		t.Fatalf("locate: err=%v refs=%d", err, len(refs))
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	prop, err := src.ProposePin(context.Background(), targets[0], refs[0], Pin{IndexDigest: digest, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(outside, "compose.yaml")
	if err := os.WriteFile(outFile, []byte("services:\n  x:\n    image: nginx:1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outFile, p); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	before, _ := os.ReadFile(outFile)
	if _, err := src.WritePin(context.Background(), prop); err == nil {
		t.Fatal("WritePin must refuse a compose file swapped to an out-of-root symlink after Discover")
	}
	after, _ := os.ReadFile(outFile)
	if string(before) != string(after) {
		t.Fatal("the out-of-root target must not be modified")
	}
}

// TestDockgeSource_WritePinRefusesIntermediateSymlinkSwap swaps an INTERMEDIATE
// directory component (the stack dir) to an out-of-root symlink after Discover.
func TestDockgeSource_WritePinRefusesIntermediateSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeStack(t, root, "web", "nginx:1.27")
	src := &DockgeSource{StacksDirs: []string{root}}
	targets := mustDiscover(t, src)
	refs, _ := src.LocateImageRefs(context.Background(), targets[0])
	digest := "sha256:" + strings.Repeat("b", 64)
	prop, err := src.ProposePin(context.Background(), targets[0], refs[0], Pin{IndexDigest: digest, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(outside, "web")
	os.MkdirAll(outDir, 0o750)
	os.WriteFile(filepath.Join(outDir, "compose.yaml"), []byte("services:\n  x:\n    image: nginx:1.27\n"), 0o644)
	os.RemoveAll(filepath.Join(root, "web"))
	if err := os.Symlink(outDir, filepath.Join(root, "web")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := src.WritePin(context.Background(), prop); err == nil {
		t.Fatal("WritePin must refuse when an intermediate dir component is swapped to an out-of-root symlink")
	}
}

func TestStacksDirFromDockgeCompose_PrefersDockgeService(t *testing.T) {
	y := "services:\n" +
		"  app:\n    image: myapp:1\n    volumes:\n      - /wrong/path:/app/stacks\n" +
		"  dockge:\n    image: louislam/dockge:1\n    volumes:\n      - /opt/stacks:/app/stacks\n"
	got, ok := StacksDirFromDockgeCompose([]byte(y))
	if !ok || got != "/opt/stacks" {
		t.Fatalf("got (%q,%v), want (/opt/stacks,true) — the dockge service must win", got, ok)
	}
}

func TestStacksDirFromDockgeCompose_ExplicitEmptyEnvIsIntentional(t *testing.T) {
	y := "services:\n  dockge:\n    image: louislam/dockge:1\n" +
		"    environment:\n      - DOCKGE_STACKS_DIR=\n" +
		"    volumes:\n      - /opt/stacks:/app/stacks\n"
	if got, ok := StacksDirFromDockgeCompose([]byte(y)); ok {
		t.Fatalf("explicit-empty DOCKGE_STACKS_DIR must yield no match, got %q", got)
	}
}
