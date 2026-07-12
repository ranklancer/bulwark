package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzComposeParse fuzzes the compose discovery + image-ref location path with
// arbitrary bytes written to a compose file (host compose files are untrusted
// input to the pinning engine). Contract: Discover + LocateImageRefs never
// panic — malformed YAML yields an error or an empty result.
func FuzzComposeParse(f *testing.F) {
	f.Add([]byte("services:\n  web:\n    image: nginx:1.27\n"))
	f.Add([]byte("services:\n  a:\n    image: ghcr.io/x/y@sha256:" + strings.Repeat("a", 64) + "\n"))
	f.Add([]byte("services: {}\n"))
	f.Add([]byte("not: [valid"))
	f.Add([]byte("services:\n  x:\n    image: 123\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "compose.yaml")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		s := &ComposeSource{Paths: []string{p}}
		targets, err := s.Discover(context.Background())
		if err != nil {
			return
		}
		for _, tg := range targets {
			_, _ = s.LocateImageRefs(context.Background(), tg)
		}
	})
}
