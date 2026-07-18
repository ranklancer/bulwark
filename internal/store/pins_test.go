package store

import (
	"os"
	"strings"
	"testing"
)

func TestPinStore_RoundTripAndPersist(t *testing.T) {
	dir := t.TempDir()
	ps := OpenPinStore(dir)
	rec := PinRecord{
		Ref:         "nginx:1.27",
		IndexDigest: "sha256:" + strings.Repeat("a", 64),
		MediaType:   "application/vnd.oci.image.index.v1+json",
		Arches:      []string{"linux/amd64", "linux/arm64"},
		Source:      "file:dockge-main",
		ComposePath: "/mnt/stacks/web/compose.yaml",
		BackupPath:  "/data/pin-backups/web/x.yaml",
		Service:     "web",
		CanaryState: "candidate",
	}
	if err := ps.Set("web/web", rec); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := ps.Get("web/web")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok || got.IndexDigest != rec.IndexDigest || got.CanaryState != "candidate" {
		t.Fatalf("Get mismatch: %+v", got)
	}
	if got.CapturedAt == "" {
		t.Error("CapturedAt should default to now")
	}
	// Persisted: a fresh store reads the same file.
	ps2 := OpenPinStore(dir)
	all, err := ps2.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("List after reopen: %v (n=%d)", err, len(all))
	}
	if _, ok := all["web/web"]; !ok {
		t.Errorf("pin not persisted across reopen: %+v", all)
	}
}

// TestPinStore_GetDistinguishesNotFoundFromReadError locks in the 3-case
// pin-state model (the admission-gate design fail-closed fix, an internal audit): Get must distinguish a
// genuinely-empty/never-populated store (case 2: ok=false, err=nil) from a
// store whose underlying file exists but cannot be read or parsed (case 3:
// ok=false, err!=nil). Collapsing these into the same zero-value result is
// exactly the fail-open bug this test guards against.
func TestPinStore_GetDistinguishesNotFoundFromReadError(t *testing.T) {
	t.Run("case 2: store not yet created is legitimate not-found", func(t *testing.T) {
		ps := OpenPinStore(t.TempDir())
		got, ok, err := ps.Get("stack/app")
		if err != nil {
			t.Fatalf("a never-created store must not error: %v", err)
		}
		if ok {
			t.Fatalf("expected not-found for an empty store, got a hit: %+v", got)
		}
	})

	t.Run("case 3: an unreadable existing store surfaces a distinct error", func(t *testing.T) {
		dir := t.TempDir()
		ps := OpenPinStore(dir)
		if err := ps.Set("stack/app", PinRecord{Ref: "nginx:1.27", IndexDigest: "sha256:" + strings.Repeat("e", 64)}); err != nil {
			t.Fatal(err)
		}
		// Force a genuine read error: replace pins.json with a directory so
		// os.ReadFile fails with a non-NotExist error regardless of the
		// process's privilege level.
		p := dir + "/pins.json"
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}

		_, ok, err := ps.Get("stack/app")
		if err == nil {
			t.Fatal("expected Get to surface the read error, got nil")
		}
		if ok {
			t.Fatal("a read-error result must not report ok=true")
		}
	})
}
