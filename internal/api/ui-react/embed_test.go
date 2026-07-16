package uireact

import (
	"io/fs"
	"strings"
	"testing"
)

func TestFS_ContainsIndex(t *testing.T) {
	data, err := fs.ReadFile(FS(), "dist/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	if len(data) == 0 {
		t.Error("embedded index.html is empty")
	}
}

func TestSub_RootedAtDist(t *testing.T) {
	sub, err := Sub()
	if err != nil {
		t.Fatalf("Sub: %v", err)
	}
	if _, err := fs.ReadFile(sub, "index.html"); err != nil {
		t.Fatalf("sub-rooted read: %v", err)
	}
}

func TestIsBuilt_PlaceholderReturnsFalse(t *testing.T) {
	// The committed dist/index.html carries the placeholder marker;
	// IsBuilt must return false until `npm run build` overwrites it
	// with a real Vite artifact.
	data, _ := fs.ReadFile(FS(), "dist/index.html")
	hasMarker := strings.Contains(string(data), "BULWARK_REACT_PLACEHOLDER")
	if hasMarker && IsBuilt() {
		t.Error("IsBuilt() should be false while placeholder marker is present")
	}
	if !hasMarker && !IsBuilt() {
		t.Error("IsBuilt() should be true once the placeholder is replaced")
	}
}
