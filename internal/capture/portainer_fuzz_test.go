package capture

import "testing"

// FuzzImageRefsFromComposeBytes fuzzes the shared compose image-ref parser, now
// also fed untrusted compose text fetched from the Portainer API/DB. Invariant:
// never panic (a parse error is fine; a crash is not).
func FuzzImageRefsFromComposeBytes(f *testing.F) {
	f.Add([]byte("services:\n  a:\n    image: nginx:1.27\n"))
	f.Add([]byte("services:\n  a:\n    image: ${X}\n    build: .\n"))
	f.Add([]byte("services: {}\n"))
	f.Add([]byte("not yaml: ["))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = imageRefsFromComposeBytes(data, nil)
	})
}
