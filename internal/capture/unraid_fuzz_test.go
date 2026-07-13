package capture

import "testing"

// FuzzImageRefsFromUnraidBytes fuzzes the Unraid template parser. Invariant:
// never panic on untrusted template bytes (a nil result or no ref is fine).
func FuzzImageRefsFromUnraidBytes(f *testing.F) {
	f.Add([]byte("<Repository>nginx:1.27</Repository>\n"))
	f.Add([]byte("<Repository></Repository>\n"))
	f.Add([]byte("<Repository>${X}</Repository>\n"))
	f.Add([]byte("<Repository>nginx:1.27\r\n</Repository>\r\n"))
	f.Add([]byte("<Repository><Repository>x</Repository>"))
	f.Add([]byte("<<<Repository"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = imageRefsFromUnraidBytes(data, "svc")
	})
}
