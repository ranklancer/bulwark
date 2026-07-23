package registry

import "testing"

// a hardening tier benchstat baseline: reference/digest parse hot path.
var benchParseRefs = []string{
	"nginx",
	"nginx:1.25",
	"ghcr.io/acme/api:1.4",
	"registry.example.com:5000/library/nginx:1.25",
	"ghcr.io/acme/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range benchParseRefs {
			if _, err := Parse(s); err != nil {
				b.Fatal(err)
			}
		}
	}
}
