package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func udigest64(c string) string { return "sha256:" + strings.Repeat(c, 64) }

const sampleUnraidTemplate = `<?xml version="1.0"?>
<Container version="2">
  <Name>Nginx</Name>
  <Repository>linuxserver/nginx:1.27</Repository>
  <Registry>https://hub.docker.com/r/linuxserver/nginx/</Registry>
  <Network>bridge</Network>
</Container>
`

func writeTmpl(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnraidSource_Kind(t *testing.T) {
	if (&UnraidSource{}).Kind() != KindFile {
		t.Fatal("Unraid must be a file-based source")
	}
}

func TestUnraidSource_DiscoverAndLocate(t *testing.T) {
	dir := t.TempDir()
	writeTmpl(t, dir, "my-Nginx.xml", sampleUnraidTemplate)
	writeTmpl(t, dir, "notes.txt", "<Repository>ignored:1.0</Repository>\n") // wrong extension
	src := &UnraidSource{TemplateDirs: []string{dir}}
	got, err := src.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "Nginx" || got[0].Kind != KindFile {
		t.Fatalf("Discover = %+v, want only my-Nginx.xml (name Nginx)", got)
	}
	refs, err := src.LocateImageRefs(context.Background(), got[0])
	if err != nil || len(refs) != 1 {
		t.Fatalf("locate: err=%v refs=%+v", err, refs)
	}
	if refs[0].Raw != "linuxserver/nginx:1.27" || !refs[0].Pinnable || refs[0].Line != 4 {
		t.Fatalf("ref = %+v, want linuxserver/nginx:1.27 pinnable on line 4", refs[0])
	}
}

func TestUnraidSource_WritePinAppliesWithBackup(t *testing.T) {
	dir := t.TempDir()
	backup := t.TempDir()
	writeTmpl(t, dir, "my-Nginx.xml", sampleUnraidTemplate)
	src := &UnraidSource{TemplateDirs: []string{dir}, BackupDir: backup}
	tgt := src.mustDiscoverOne(t)
	refs, err := src.LocateImageRefs(context.Background(), tgt)
	if err != nil || len(refs) != 1 {
		t.Fatalf("locate: %v %+v", err, refs)
	}
	d := udigest64("a")
	prop, err := src.ProposePin(context.Background(), tgt, refs[0], Pin{IndexDigest: d, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := src.WritePin(context.Background(), prop)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(tgt.Path)
	if !strings.Contains(string(out), "<Repository>linuxserver/nginx:1.27@"+d+"</Repository>") {
		t.Fatalf("template not pinned:\n%s", out)
	}
	// Format preserved: other elements untouched.
	if !strings.Contains(string(out), "<Name>Nginx</Name>") || !strings.Contains(string(out), "<Network>bridge</Network>") {
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

func TestUnraidSource_WritePinRefusesNonDigest(t *testing.T) {
	dir := t.TempDir()
	p := writeTmpl(t, dir, "my-Nginx.xml", sampleUnraidTemplate)
	src := &UnraidSource{TemplateDirs: []string{dir}}
	prop := Proposal{Path: p, Line: 4, OldValue: "linuxserver/nginx:1.27", NewValue: "linuxserver/nginx:1.28"}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "not a sha256 digest") {
		t.Fatalf("want non-digest refusal, got %v", err)
	}
}

func TestUnraidSource_WritePinRejectsBadProposal(t *testing.T) {
	dir := t.TempDir()
	p := writeTmpl(t, dir, "my-Nginx.xml", sampleUnraidTemplate)
	src := &UnraidSource{TemplateDirs: []string{dir}}
	d := udigest64("a")
	if _, err := src.WritePin(context.Background(), Proposal{Path: p, Line: 0, OldValue: "x", NewValue: "x@" + d}); err == nil {
		t.Fatal("Line<=0 must be rejected")
	}
	if _, err := src.WritePin(context.Background(), Proposal{Path: p, Line: 4, OldValue: "", NewValue: "x@" + d}); err == nil {
		t.Fatal("empty OldValue must be rejected")
	}
	if _, err := src.WritePin(context.Background(), Proposal{Path: "", Line: 4, OldValue: "x", NewValue: "x@" + d}); err == nil {
		t.Fatal("empty Path must be rejected")
	}
}

func TestUnraidSource_WritePinRefusesOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	p := writeTmpl(t, other, "my-Nginx.xml", sampleUnraidTemplate) // outside the configured root
	src := &UnraidSource{TemplateDirs: []string{dir}}
	prop := Proposal{Path: p, Line: 4, OldValue: "linuxserver/nginx:1.27", NewValue: "linuxserver/nginx:1.27@" + udigest64("b")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "no longer resolves inside any configured") {
		t.Fatalf("want containment refusal, got %v", err)
	}
}

func TestUnraidSource_WritePinRefusesSymlinkFinal(t *testing.T) {
	dir := t.TempDir()
	real := writeTmpl(t, dir, "real.xml", sampleUnraidTemplate)
	link := filepath.Join(dir, "my-Nginx.xml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	src := &UnraidSource{TemplateDirs: []string{dir}}
	prop := Proposal{Path: link, Line: 4, OldValue: "linuxserver/nginx:1.27", NewValue: "linuxserver/nginx:1.27@" + udigest64("c")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "O_NOFOLLOW") {
		t.Fatalf("want O_NOFOLLOW refusal on symlinked target, got %v", err)
	}
}

func TestUnraidSource_WritePinRefusesOnDrift(t *testing.T) {
	dir := t.TempDir()
	p := writeTmpl(t, dir, "my-Nginx.xml", strings.Replace(sampleUnraidTemplate, "nginx:1.27", "nginx:1.28", 1))
	src := &UnraidSource{TemplateDirs: []string{dir}}
	prop := Proposal{Path: p, Line: 4, OldValue: "linuxserver/nginx:1.27", NewValue: "linuxserver/nginx:1.27@" + udigest64("d")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "no longer contains") {
		t.Fatalf("want drift refusal, got %v", err)
	}
}

func TestImageRefsFromUnraidBytes(t *testing.T) {
	// <Registry> is ignored; only <Repository> is returned, with its line number.
	body := "<Container>\n  <Registry>ignored</Registry>\n  <Repository>nginx:1.27</Repository>\n</Container>\n"
	refs, err := imageRefsFromUnraidBytes([]byte(body), "web")
	if err != nil || len(refs) != 1 || refs[0].Raw != "nginx:1.27" || refs[0].Line != 3 {
		t.Fatalf("refs = %+v (err %v)", refs, err)
	}
	// :latest is not pinnable.
	refs, _ = imageRefsFromUnraidBytes([]byte("<Repository>nginx:latest</Repository>\n"), "web")
	if len(refs) != 1 || refs[0].Pinnable {
		t.Fatalf(":latest must be non-pinnable: %+v", refs)
	}
	// Empty and multi-line/malformed <Repository> yield nil.
	if r, _ := imageRefsFromUnraidBytes([]byte("<Repository></Repository>\n"), "web"); r != nil {
		t.Fatalf("empty repository should yield nil, got %+v", r)
	}
	if r, _ := imageRefsFromUnraidBytes([]byte("<Repository>nginx:1.27\n</Repository>\n"), "web"); r != nil {
		t.Fatalf("multi-line repository should yield nil (fail-closed), got %+v", r)
	}
	if r, _ := imageRefsFromUnraidBytes([]byte("<Container></Container>\n"), "web"); r != nil {
		t.Fatalf("no-repository template should yield nil, got %+v", r)
	}
}

// mustDiscoverOne is a test helper returning the single discovered target.
func (s *UnraidSource) mustDiscoverOne(t *testing.T) Target {
	t.Helper()
	got, err := s.Discover(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("discover: err=%v got=%+v", err, got)
	}
	return got[0]
}
