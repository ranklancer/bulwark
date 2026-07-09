package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// propose runs the real Discover→Locate→Propose chain for one service so the
// write tests exercise a genuine Proposal.
func propose(t *testing.T, dir, svc, digest string) (*ComposeSource, Target, Proposal) {
	t.Helper()
	src := &ComposeSource{Paths: []string{dir}, Autodiscover: false, BackupDir: filepath.Join(dir, "backups")}
	targets, err := src.Discover(context.Background())
	if err != nil || len(targets) != 1 {
		t.Fatalf("discover: %v (%d targets)", err, len(targets))
	}
	refs, err := src.LocateImageRefs(context.Background(), targets[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.Service == svc {
			prop, err := src.ProposePin(context.Background(), targets[0], r, Pin{IndexDigest: digest, IsIndex: true})
			if err != nil {
				t.Fatalf("propose: %v", err)
			}
			return src, targets[0], prop
		}
	}
	t.Fatalf("service %q not found", svc)
	return nil, Target{}, Proposal{}
}

func TestWritePin_PreservesFormatAndComments(t *testing.T) {
	dir := t.TempDir()
	orig := "services:\n  web:\n    image: nginx:1.27   # the web server\n    restart: unless-stopped\n  db:\n    image: postgres:16\n"
	path := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	src, _, prop := propose(t, dir, "web", digest)

	applied, err := src.WritePin(context.Background(), prop)
	if err != nil {
		t.Fatalf("WritePin: %v", err)
	}
	got, _ := os.ReadFile(path)
	want := "services:\n  web:\n    image: nginx:1.27@" + digest + "   # the web server\n    restart: unless-stopped\n  db:\n    image: postgres:16\n"
	if string(got) != want {
		t.Errorf("in-place edit not format-preserving.\n got: %q\nwant: %q", got, want)
	}
	// Backup exists and equals the pre-edit original byte-for-byte.
	if applied.BackupPath == "" {
		t.Fatal("no backup path recorded")
	}
	bk, _ := os.ReadFile(applied.BackupPath)
	if string(bk) != orig {
		t.Errorf("backup not byte-identical to original.\n got: %q\nwant: %q", bk, orig)
	}
}

func TestWritePin_QuotedValuePreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	os.WriteFile(path, []byte("services:\n  web:\n    image: \"nginx:1.27\"\n"), 0o644)
	digest := "sha256:" + strings.Repeat("b", 64)
	src, _, prop := propose(t, dir, "web", digest)
	if _, err := src.WritePin(context.Background(), prop); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := "services:\n  web:\n    image: \"nginx:1.27@" + digest + "\"\n"
	if string(got) != want {
		t.Errorf("quotes not preserved.\n got: %q\nwant: %q", got, want)
	}
}

func TestWritePin_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	os.WriteFile(path, []byte("services:\n  web:\n    image: nginx:1.27\n"), 0o644)
	digest := "sha256:" + strings.Repeat("c", 64)
	src, _, prop := propose(t, dir, "web", digest)
	if _, err := src.WritePin(context.Background(), prop); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	// Re-apply the SAME proposal: the file already carries the digest → no-op.
	res, err := src.WritePin(context.Background(), prop)
	if err != nil {
		t.Fatalf("second WritePin: %v", err)
	}
	if !res.NoOp {
		t.Errorf("re-apply must be a no-op, got %+v", res)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(after) {
		t.Error("idempotent re-apply changed the file")
	}
}

func TestWritePin_RefusesOnDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	os.WriteFile(path, []byte("services:\n  web:\n    image: nginx:1.27\n"), 0o644)
	digest := "sha256:" + strings.Repeat("d", 64)
	src, _, prop := propose(t, dir, "web", digest)
	// Someone edits the file after the proposal was computed.
	drift := "services:\n  web:\n    image: caddy:2\n"
	os.WriteFile(path, []byte(drift), 0o644)
	if _, err := src.WritePin(context.Background(), prop); err == nil {
		t.Fatal("WritePin must refuse when the target line changed since propose")
	}
	got, _ := os.ReadFile(path)
	if string(got) != drift {
		t.Error("refused write must not modify the file")
	}
}

func TestRollback_RestoresByteIdentical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	orig := "services:\n  web:\n    image: nginx:1.27  # keep me\n"
	os.WriteFile(path, []byte(orig), 0o644)
	digest := "sha256:" + strings.Repeat("e", 64)
	src, _, prop := propose(t, dir, "web", digest)
	applied, err := src.WritePin(context.Background(), prop)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback(applied.BackupPath, path); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != orig {
		t.Errorf("rollback not byte-identical.\n got: %q\nwant: %q", got, orig)
	}
}
