package store

import (
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
	got, ok := ps.Get("web/web")
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
