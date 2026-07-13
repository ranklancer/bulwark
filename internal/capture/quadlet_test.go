package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func qdigest64(c string) string { return "sha256:" + strings.Repeat(c, 64) }

const sampleContainerUnit = `[Unit]
Description=web

[Container]
Image=docker.io/library/nginx:1.27
PublishPort=8080:80
Environment=MODE=prod

[Install]
WantedBy=default.target
`

func writeUnit(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestQuadletSource_Kind(t *testing.T) {
	if (&QuadletSource{}).Kind() != KindFile {
		t.Fatal("Podman quadlets must be a file-based source")
	}
}

func TestQuadletSource_DiscoverAndLocate(t *testing.T) {
	dir := t.TempDir()
	writeUnit(t, dir, "web.container", sampleContainerUnit)
	writeUnit(t, dir, "db.pod", "[Pod]\nPodName=db\n")    // no image -> not a .container
	writeUnit(t, dir, "notes.txt", "Image=ignored:1.0\n") // wrong extension
	src := &QuadletSource{UnitDirs: []string{dir}}
	got, err := src.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "web" || got[0].Kind != KindFile {
		t.Fatalf("Discover = %+v, want only web.container", got)
	}
	refs, err := src.LocateImageRefs(context.Background(), got[0])
	if err != nil || len(refs) != 1 {
		t.Fatalf("locate: err=%v refs=%+v", err, refs)
	}
	if refs[0].Raw != "docker.io/library/nginx:1.27" || !refs[0].Pinnable || refs[0].Line != 5 {
		t.Fatalf("ref = %+v, want nginx:1.27 pinnable on line 5", refs[0])
	}
}

func TestQuadletSource_WritePinAppliesWithBackup(t *testing.T) {
	dir := t.TempDir()
	backup := t.TempDir()
	writeUnit(t, dir, "web.container", sampleContainerUnit)
	src := &QuadletSource{UnitDirs: []string{dir}, BackupDir: backup}
	tgt := src.mustDiscoverOne(t)
	refs, err := src.LocateImageRefs(context.Background(), tgt)
	if err != nil || len(refs) != 1 {
		t.Fatalf("locate: %v %+v", err, refs)
	}
	d := qdigest64("a")
	prop, err := src.ProposePin(context.Background(), tgt, refs[0], Pin{IndexDigest: d, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := src.WritePin(context.Background(), prop)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(tgt.Path)
	if !strings.Contains(string(out), "Image=docker.io/library/nginx:1.27@"+d) {
		t.Fatalf("unit not pinned:\n%s", out)
	}
	// Format preserved: other keys untouched.
	if !strings.Contains(string(out), "PublishPort=8080:80") || !strings.Contains(string(out), "Environment=MODE=prod") {
		t.Fatalf("format not preserved:\n%s", out)
	}
	if applied.BackupPath == "" {
		t.Fatal("expected a backup path")
	}
	if _, err := os.Stat(applied.BackupPath); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	// Idempotent re-pin is a no-op.
	refs2, _ := src.LocateImageRefs(context.Background(), tgt)
	prop2, _ := src.ProposePin(context.Background(), tgt, refs2[0], Pin{IndexDigest: d})
	if !prop2.NoOp {
		t.Fatal("expected NoOp on re-pin")
	}
}

func TestQuadletSource_WritePinRefusesNonDigest(t *testing.T) {
	dir := t.TempDir()
	p := writeUnit(t, dir, "web.container", sampleContainerUnit)
	src := &QuadletSource{UnitDirs: []string{dir}}
	prop := Proposal{Path: p, Line: 5, OldValue: "docker.io/library/nginx:1.27", NewValue: "docker.io/library/nginx:1.28"}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "not a sha256 digest") {
		t.Fatalf("want non-digest refusal, got %v", err)
	}
}

func TestQuadletSource_WritePinRefusesOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	p := writeUnit(t, other, "web.container", sampleContainerUnit) // outside the configured root
	src := &QuadletSource{UnitDirs: []string{dir}}
	prop := Proposal{Path: p, Line: 5, OldValue: "docker.io/library/nginx:1.27", NewValue: "docker.io/library/nginx:1.27@" + qdigest64("b")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "no longer resolves inside any configured") {
		t.Fatalf("want containment refusal, got %v", err)
	}
}

func TestQuadletSource_WritePinRefusesSymlinkFinal(t *testing.T) {
	dir := t.TempDir()
	real := writeUnit(t, dir, "real.container", sampleContainerUnit)
	link := filepath.Join(dir, "web.container")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	src := &QuadletSource{UnitDirs: []string{dir}}
	// Craft a proposal whose Path is the symlink itself (not the resolved target).
	prop := Proposal{Path: link, Line: 5, OldValue: "docker.io/library/nginx:1.27", NewValue: "docker.io/library/nginx:1.27@" + qdigest64("c")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "O_NOFOLLOW") {
		t.Fatalf("want O_NOFOLLOW refusal on symlinked target, got %v", err)
	}
}

func TestQuadletSource_WritePinRefusesOnDrift(t *testing.T) {
	dir := t.TempDir()
	p := writeUnit(t, dir, "web.container", strings.Replace(sampleContainerUnit, "nginx:1.27", "nginx:1.28", 1))
	src := &QuadletSource{UnitDirs: []string{dir}}
	prop := Proposal{Path: p, Line: 5, OldValue: "docker.io/library/nginx:1.27", NewValue: "docker.io/library/nginx:1.27@" + qdigest64("d")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "no longer contains") {
		t.Fatalf("want drift refusal, got %v", err)
	}
}

func TestImageRefsFromQuadletBytes(t *testing.T) {
	// Image outside [Container] is ignored; only the [Container] Image= is returned.
	body := "[Service]\nImage=ignored:1.0\n[Container]\n# Image=commented:1.0\nImage=nginx:1.27\n"
	refs, err := imageRefsFromQuadletBytes([]byte(body), "web")
	if err != nil || len(refs) != 1 || refs[0].Raw != "nginx:1.27" || refs[0].Line != 5 {
		t.Fatalf("refs = %+v (err %v)", refs, err)
	}
	// :latest is not pinnable.
	refs, _ = imageRefsFromQuadletBytes([]byte("[Container]\nImage=nginx:latest\n"), "web")
	if len(refs) != 1 || refs[0].Pinnable {
		t.Fatalf(":latest must be non-pinnable: %+v", refs)
	}
	// A unit with no Image= yields nil.
	refs, _ = imageRefsFromQuadletBytes([]byte("[Pod]\nPodName=db\n"), "db")
	if refs != nil {
		t.Fatalf("no-image unit should yield nil, got %+v", refs)
	}
}

// mustDiscoverOne is a test helper returning the single discovered target.
func (s *QuadletSource) mustDiscoverOne(t *testing.T) Target {
	t.Helper()
	got, err := s.Discover(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("discover: err=%v got=%+v", err, got)
	}
	return got[0]
}
