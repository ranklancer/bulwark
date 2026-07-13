package capture

import "testing"

// FuzzImageRefsFromQuadletBytes fuzzes the Podman quadlet unit parser. Invariant:
// never panic on untrusted unit-file bytes (a nil result or no ref is fine).
func FuzzImageRefsFromQuadletBytes(f *testing.F) {
	f.Add([]byte("[Container]\nImage=nginx:1.27\n"))
	f.Add([]byte("[Container]\nImage=\n"))
	f.Add([]byte("[Unit]\n[Container]\nImage=${X}\n"))
	f.Add([]byte("[Container]\r\nImage=nginx:1.27\r\n"))
	f.Add([]byte("[[[\nImage="))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = imageRefsFromQuadletBytes(data, "svc")
	})
}
