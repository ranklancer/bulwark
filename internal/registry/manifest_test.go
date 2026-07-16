package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func manifestServer(t *testing.T, digest, contentType, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/library/demo/manifests/1.0", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	return httptest.NewServer(mux)
}

// digestOf returns the canonical content digest of body, matching what a
// spec-compliant registry sets in Docker-Content-Digest.
func digestOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestResolveManifest_MultiArchIndex is the NPM 2.15.1 regression guard: a
// multi-arch tag must resolve to the INDEX digest with every real platform
// enumerated — never a per-arch sub-manifest digest.
func TestResolveManifest_MultiArchIndex(t *testing.T) {
	body := `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {"digest":"sha256:aaa","platform":{"os":"linux","architecture":"amd64"}},
    {"digest":"sha256:bbb","platform":{"os":"linux","architecture":"arm64"}},
    {"digest":"sha256:ccc","platform":{"os":"unknown","architecture":"unknown"}}
  ]
}`
	indexDigest := digestOf(body)
	srv := manifestServer(t, indexDigest, "application/vnd.oci.image.index.v1+json", body)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	info, err := c.ResolveManifest(context.Background(), Reference{Registry: "r.example.com", Repository: "library/demo", Tag: "1.0"})
	if err != nil {
		t.Fatalf("ResolveManifest: %v", err)
	}
	if info.Digest != indexDigest {
		t.Errorf("Digest = %q, want the index digest %q (NPM 2.15.1: never a sub-manifest)", info.Digest, indexDigest)
	}
	if !info.IsIndex {
		t.Error("IsIndex = false, want true for a multi-arch index")
	}
	if want := []string{"linux/amd64", "linux/arm64"}; !reflect.DeepEqual(info.Arches, want) {
		t.Errorf("Arches = %v, want %v (attestation unknown/unknown excluded)", info.Arches, want)
	}
}

func TestResolveManifest_SingleArch(t *testing.T) {
	body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`
	d := digestOf(body)
	srv := manifestServer(t, d, "application/vnd.oci.image.manifest.v1+json", body)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	info, err := c.ResolveManifest(context.Background(), Reference{Registry: "r.example.com", Repository: "library/demo", Tag: "1.0"})
	if err != nil {
		t.Fatalf("ResolveManifest: %v", err)
	}
	if info.IsIndex {
		t.Error("IsIndex = true, want false for a single-arch manifest")
	}
	if len(info.Arches) != 0 {
		t.Errorf("Arches = %v, want empty for single-arch", info.Arches)
	}
	if info.Digest != d {
		t.Errorf("Digest = %q, want %q", info.Digest, d)
	}
}

func TestResolveManifest_MediaTypeFallsBackToContentType(t *testing.T) {
	// Body omits mediaType; the client must fall back to the Content-Type header.
	body := `{"schemaVersion":2,"manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}`
	d := digestOf(body)
	srv := manifestServer(t, d, "application/vnd.docker.distribution.manifest.list.v2+json; charset=utf-8", body)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	info, err := c.ResolveManifest(context.Background(), Reference{Registry: "r.example.com", Repository: "library/demo", Tag: "1.0"})
	if err != nil {
		t.Fatalf("ResolveManifest: %v", err)
	}
	if !info.IsIndex || info.MediaType != "application/vnd.docker.distribution.manifest.list.v2+json" {
		t.Errorf("IsIndex=%v MediaType=%q, want index via Content-Type fallback", info.IsIndex, info.MediaType)
	}
}

func TestResolveManifest_RequiresTagOrDigest(t *testing.T) {
	c := New()
	if _, err := c.ResolveManifest(context.Background(), Reference{Registry: "x", Repository: "y"}); err == nil {
		t.Fatal("want error when neither tag nor digest is provided")
	}
}

// TestResolveManifest_DigestMismatch_Rejected is the pin-poisoning guard: a
// registry (or MITM) that serves one body while claiming a DIFFERENT digest in
// Docker-Content-Digest must be rejected fail-closed.
func TestResolveManifest_DigestMismatch_Rejected(t *testing.T) {
	body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}`
	other := "sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("a different body")); return s[:] }())
	srv := manifestServer(t, other, "application/vnd.oci.image.index.v1+json", body)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	if _, err := c.ResolveManifest(context.Background(), Reference{Registry: "r.example.com", Repository: "library/demo", Tag: "1.0"}); err == nil {
		t.Fatal("expected an error when Docker-Content-Digest != sha256(body)")
	}
}

func TestResolveManifest_MalformedDigestHeader_Rejected(t *testing.T) {
	body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	for _, bad := range []string{"sha256:not-hex", "sha256:" + "aa", "deadbeef", digestOf(body) + "ff"} {
		srv := manifestServer(t, bad, "application/vnd.oci.image.manifest.v1+json", body)
		c := New()
		c.BaseURL = srv.URL
		if _, err := c.ResolveManifest(context.Background(), Reference{Registry: "r.example.com", Repository: "library/demo", Tag: "1.0"}); err == nil {
			t.Errorf("expected rejection for malformed digest header %q", bad)
		}
		srv.Close()
	}
}

func TestIsSHA256Digest(t *testing.T) {
	good := "sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("x")); return s[:] }())
	if !IsSHA256Digest(good) {
		t.Errorf("IsSHA256Digest(%q) = false, want true", good)
	}
	for _, bad := range []string{"", "sha256:", "sha256:zz", "sha512:" + good[7:], good + "x", "SHA256:" + good[7:]} {
		if IsSHA256Digest(bad) {
			t.Errorf("IsSHA256Digest(%q) = true, want false", bad)
		}
	}
}
