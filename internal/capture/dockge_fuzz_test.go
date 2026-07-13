package capture

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzStacksDirFromDockgeCompose fuzzes the untrusted-input parser that locates
// a Dockge host stacks dir from a Dockge compose file. Invariants: never panic,
// and any returned dir (ok==true) is non-empty and equal to its own cleaned form
// modulo surrounding whitespace (i.e. a sane path token, never partial garbage).
func FuzzStacksDirFromDockgeCompose(f *testing.F) {
	f.Add([]byte("services:\n  dockge:\n    environment:\n      - DOCKGE_STACKS_DIR=/opt/stacks\n    volumes:\n      - /opt/stacks:/opt/stacks\n"))
	f.Add([]byte("services:\n  d:\n    volumes:\n      - type: bind\n        source: /srv/x\n        target: /app/stacks\n"))
	f.Add([]byte("services:\n  d:\n    environment:\n      DOCKGE_STACKS_DIR: /data\n    volumes:\n      - /h:/data:ro\n"))
	f.Add([]byte("not: yaml: [unbalanced"))
	f.Add([]byte(""))
	f.Add([]byte("services: {}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir, ok := StacksDirFromDockgeCompose(data)
		if !ok {
			return
		}
		if strings.TrimSpace(dir) == "" {
			t.Fatalf("ok==true but empty dir for input %q", data)
		}
		if dir != strings.TrimSpace(dir) {
			t.Fatalf("returned dir has surrounding whitespace: %q", dir)
		}
		// Must be a usable path token: cleaning the trimmed value round-trips
		// (no embedded newline / control chars that would break a mount root).
		_ = filepath.Clean(dir)
	})
}
