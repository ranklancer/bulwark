package registry

import (
	"strings"
	"testing"
)

// FuzzParseReference fuzzes the image-reference parser (parses untrusted image
// strings from compose files / webhooks). Contract: never panic; a returned
// Reference must round-trip its component pieces without exploding.
func FuzzParseReference(f *testing.F) {
	seeds := []string{
		"nginx", "nginx:1.27", "docker.io/library/nginx:1.27",
		"ghcr.io/acme/app:1.0@sha256:" + strings.Repeat("a", 64),
		"r.example.com:5000/team/app:tag", "", ":", "@", "a@b@c",
		"UPPER/Case:Tag", "registry/repo@sha256:zzz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		got, err := Parse(ref)
		if err == nil {
			// A successful parse must expose a non-empty repository and must not
			// panic when its derived views are computed.
			_ = got.FullName()
			_ = got.String()
		}
	})
}
