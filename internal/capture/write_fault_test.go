// a hardening tier fault-injection tests for the pin-store atomic write-back path
// (internal/capture/write.go). These tests exist to prove that a failed or
// partial write to a pinned compose file can NEVER be observed by a reader
// as a valid "pinned" state: the destination is either byte-identical to its
// pre-write content, or (in the crash-before-rename case) the stray temp
// file left behind is never mistaken for the pin store itself.
//
// Faults are injected through real OS-level seams only:
//   - RLIMIT_FSIZE for a genuine mid-write I/O failure (EFBIG on the temp
//     file), with SIGXFSZ ignored so the test process is not killed;
//   - a directory placed at the rename destination for a genuine rename
//     failure (a structural EISDIR/"file exists", not a permission check).
//
// No production code is modified or mocked. Note: tests in this repo run as
// root (see dev-box CI), so permission-bit tricks (chmod 0500 on a
// directory) are NOT viable fault seams -- root bypasses DAC checks via
// CAP_DAC_OVERRIDE, confirmed empirically before writing these tests. The
// two seams above are privilege-proof.
package capture

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

var ignoreSIGXFSZOnce sync.Once

// withSmallFileSizeLimit lowers RLIMIT_FSIZE for the duration of fn so any
// write beyond limitBytes to a regular file fails with a real EFBIG/"file
// too large" error instead of succeeding. This is a genuine, privilege-proof
// way to inject a mid-write I/O failure into atomicWrite's tmp.WriteString
// call, without touching production code.
func withSmallFileSizeLimit(t *testing.T, limitBytes uint64, fn func()) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("RLIMIT_FSIZE fault injection requires Linux")
	}
	ignoreSIGXFSZOnce.Do(func() {
		// Default disposition for SIGXFSZ is to terminate the process; we
		// need the write() call to return EFBIG instead.
		signal.Ignore(syscall.SIGXFSZ)
	})

	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &orig); err != nil {
		t.Fatalf("getrlimit RLIMIT_FSIZE: %v", err)
	}
	limited := syscall.Rlimit{Cur: limitBytes, Max: orig.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatalf("setrlimit RLIMIT_FSIZE: %v", err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &orig); err != nil {
			t.Fatalf("restore RLIMIT_FSIZE: %v", err)
		}
	}()
	fn()
}

// assertNoStrayTempFiles fails the test if any atomicWrite temp file
// (".bulwark-pin-*.tmp") is left behind in dir. atomicWrite's defer must
// clean these up on every error path, or a real WritePin failure would
// litter the operator's stack directory with unreferenced pin fragments.
func assertNoStrayTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".bulwark-pin-*.tmp"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("orphan temp file(s) left behind after a failed write: %v", matches)
	}
}

// TestAtomicWrite_MidWriteFailure_NoPartialFile injects a real I/O failure
// partway through the temp-file write (via RLIMIT_FSIZE) and proves the
// destination compose file is fail-closed: it stays byte-identical to its
// pre-write content. If atomicWrite wrote directly to the destination
// instead of a temp file, this failure would truncate the real pin store in
// place -- this assertion would then fail.
func TestAtomicWrite_MidWriteFailure_NoPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	orig := "services:\n  web:\n    image: nginx:1.27\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}

	// A payload much larger than the RLIMIT_FSIZE ceiling installed below,
	// so the temp-file write fails partway through.
	newContent := "services:\n  web:\n    image: nginx:1.27@sha256:" + strings.Repeat("a", 64) + "\n" + strings.Repeat("# padding-line-to-force-a-mid-write-failure\n", 500)

	var writeErr error
	withSmallFileSizeLimit(t, 32, func() {
		writeErr = atomicWrite(path, newContent)
	})
	if writeErr == nil {
		t.Fatal("atomicWrite must fail when the temp-file write hits the RLIMIT_FSIZE ceiling")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("destination unreadable after a failed write: %v", err)
	}
	if string(got) != orig {
		t.Errorf("fail-closed violated: destination changed by a failed write.\n got: %q\nwant: %q", got, orig)
	}

	assertNoStrayTempFiles(t, dir)
}

// TestAtomicWrite_RenameFailure_NoPartialPinAndNoOrphanTemp injects a real
// rename failure by placing a directory at the rename destination (rename(2)
// fails with EISDIR/"file exists" when the source is a regular file and the
// destination is a directory -- a structural failure, not a permission
// check, so it holds even for root). It proves the "pinned" location is
// never left as a readable half-write, and the temp file is cleaned up.
func TestAtomicWrite_RenameFailure_NoPartialPinAndNoOrphanTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "compose.yaml")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}

	err := atomicWrite(target, "services:\n  web:\n    image: nginx:1.27@sha256:"+strings.Repeat("b", 64)+"\n")
	if err == nil {
		t.Fatal("atomicWrite must fail when the rename target is occupied by a directory")
	}

	fi, statErr := os.Stat(target)
	if statErr != nil || !fi.IsDir() {
		t.Fatalf("fail-closed violated: rename target must remain an untouched directory, got fi=%v statErr=%v", fi, statErr)
	}
	if _, err := os.ReadFile(target); err == nil {
		t.Error("a directory must never be readable as pin content -- it cannot be mistaken for a valid pinned compose file")
	}

	assertNoStrayTempFiles(t, dir)
}

// TestWritePin_CrashBetweenWriteAndRename_StrayTempNeverReadAsPinned
// simulates a process crash landing exactly between the temp-file write and
// the rename: it performs every step atomicWrite performs up to (but not
// including) os.Rename, by hand, then asserts that (a) the real compose file
// is untouched and (b) the REAL reader path (Discover + LocateImageRefs)
// never mistakes the orphaned temp file for a pinned target.
func TestWritePin_CrashBetweenWriteAndRename_StrayTempNeverReadAsPinned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	orig := "services:\n  web:\n    image: nginx:1.27\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("c", 64)
	pinnedContent := "services:\n  web:\n    image: nginx:1.27@" + digest + "\n"

	tmp, err := os.CreateTemp(dir, ".bulwark-pin-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(pinnedContent); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	// NOTE: intentionally no os.Rename call here -- this is the "crash"
	// point atomicWrite would still need to cross for the pin to go live.

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != orig {
		t.Fatalf("fail-closed violated: destination changed without a rename ever happening.\n got: %q\nwant: %q", got, orig)
	}

	src := &ComposeSource{Paths: []string{dir}}
	targets, err := src.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("Discover must find exactly the real compose file, never the stray temp file; got %d targets: %+v", len(targets), targets)
	}
	wantAbs, _ := filepath.Abs(path)
	if targets[0].Path != wantAbs {
		t.Fatalf("Discover picked up the wrong file: got %q, want %q", targets[0].Path, wantAbs)
	}

	refs, err := src.LocateImageRefs(context.Background(), targets[0])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range refs {
		if r.Service != "web" {
			continue
		}
		found = true
		if strings.Contains(r.Raw, "@sha256:") {
			t.Errorf("a reader must never see the stray temp file's pin -- web service reads as already pinned: %q", r.Raw)
		}
		if r.Raw != "nginx:1.27" {
			t.Errorf("web service image should still be the pre-crash, unpinned value, got %q", r.Raw)
		}
	}
	if !found {
		t.Fatal("web service not found by LocateImageRefs")
	}

	if err := os.Remove(tmp.Name()); err != nil {
		t.Fatal(err)
	}
}

// TestWritePin_RoundTrip_ExactContentAndRereadable pins the happy path: a
// successful WritePin followed by a fresh read (both a raw byte comparison
// and a real Discover+LocateImageRefs reread) returns exactly what was
// written, and leaves a sibling service untouched. This is what makes the
// fault-injection cases above meaningful -- they show the SAME code path
// staying fail-closed under fault, having established here that it is
// correct under success.
func TestWritePin_RoundTrip_ExactContentAndRereadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	orig := "services:\n  web:\n    image: nginx:1.27   # keep\n  cache:\n    image: redis:7\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	src, target, prop := propose(t, dir, "web", digest)

	applied, err := src.WritePin(context.Background(), prop)
	if err != nil {
		t.Fatalf("WritePin: %v", err)
	}
	if applied.NoOp {
		t.Fatal("first write must not be a no-op")
	}

	wantContent := "services:\n  web:\n    image: nginx:1.27@" + digest + "   # keep\n  cache:\n    image: redis:7\n"
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantContent {
		t.Fatalf("round-trip write not exact.\n got: %q\nwant: %q", got, wantContent)
	}

	refs, err := src.LocateImageRefs(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	var sawWeb, sawCache bool
	for _, r := range refs {
		switch r.Service {
		case "web":
			sawWeb = true
			wantRaw := "nginx:1.27@" + digest
			if r.Raw != wantRaw {
				t.Errorf("reread web image = %q, want %q", r.Raw, wantRaw)
			}
		case "cache":
			sawCache = true
			if r.Raw != "redis:7" {
				t.Errorf("sibling service must be untouched by the write, got %q", r.Raw)
			}
		}
	}
	if !sawWeb || !sawCache {
		t.Fatalf("expected both services on reread, sawWeb=%v sawCache=%v", sawWeb, sawCache)
	}
}

// TestAtomicWrite_ConcurrentReaderNeverObservesPartialContent is the
// strongest atomicity proof in this file: a reader goroutine continuously
// reads the destination while atomicWrite alternates it between two
// full-size, distinct payloads hundreds of times. Every single observation
// must be exactly one payload or the other -- never a truncated or mixed
// byte sequence. This assertion is only true because atomicWrite replaces
// the file via os.Rename (atomic on the same filesystem); if the code wrote
// directly into the destination in place, a concurrent reader would
// eventually observe a partial write, and this test would fail.
func TestAtomicWrite_ConcurrentReaderNeverObservesPartialContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin.txt")
	contentA := strings.Repeat("A", 5000) + "\n"
	contentB := strings.Repeat("B", 7000) + "\n"
	if err := os.WriteFile(path, []byte(contentA), 0o644); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var badObserved atomic.Bool
	var mu sync.Mutex
	var badSample string

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			got, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			s := string(got)
			if s != contentA && s != contentB {
				badObserved.Store(true)
				mu.Lock()
				if badSample == "" {
					badSample = s
				}
				mu.Unlock()
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		next := contentB
		if i%2 == 1 {
			next = contentA
		}
		if err := atomicWrite(path, next); err != nil {
			t.Fatalf("atomicWrite iteration %d: %v", i, err)
		}
	}
	stop.Store(true)
	wg.Wait()

	if badObserved.Load() {
		mu.Lock()
		sample := badSample
		mu.Unlock()
		n := min(len(sample), 64)
		t.Fatalf("atomicity violated: concurrent reader observed a partial/mixed write; sample len=%d, prefix=%q", len(sample), sample[:n])
	}
}
