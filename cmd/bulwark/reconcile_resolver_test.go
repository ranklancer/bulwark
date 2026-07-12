package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/registry"
)

func digestOfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// manifestSrv returns a *registry.Client pointed at a test server that serves a
// fixed manifest body with a caller-chosen Docker-Content-Digest header, for any
// /v2/.../manifests/<ref> request.
func manifestSrv(t *testing.T, digest, contentType, body string) *registry.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/manifests/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := registry.New()
	c.BaseURL = srv.URL
	return c
}

const (
	idxCT = "application/vnd.oci.image.index.v1+json"
	imgCT = "application/vnd.oci.image.manifest.v1+json"
)

// TestReconcileResolver_BodyVerify is the daemon-path regression guard for the
// MEDIUM fix: the LIVE reconcile resolver (now shared with the CLI) must
// content-verify the manifest body. A registry/MITM that serves body A under a
// header digest B must be rejected, so the daemon can never pin an unverified
// digest via the old HEAD-only path.
func TestReconcileResolver_BodyVerify(t *testing.T) {
	const ref = "r.example.com/library/demo:1.0"
	body := `{"mediaType":"` + idxCT + `","manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}`

	t.Run("content-digest mismatch rejected", func(t *testing.T) {
		lie := "sha256:" + strings.Repeat("f", 64) // != sha256(body)
		c := manifestSrv(t, lie, idxCT, body)
		if _, err := (reconcileResolver{client: c, requireIndex: true}).ResolveIndex(context.Background(), ref); err == nil {
			t.Fatal("daemon path must reject a body whose sha256 != Docker-Content-Digest")
		}
	})

	t.Run("verified index accepted", func(t *testing.T) {
		good := digestOfBytes([]byte(body))
		c := manifestSrv(t, good, idxCT, body)
		rec, err := (reconcileResolver{client: c, requireIndex: true}).ResolveIndex(context.Background(), ref)
		if err != nil {
			t.Fatalf("verified index: %v", err)
		}
		if rec.IndexDigest != good {
			t.Errorf("IndexDigest = %q, want %q", rec.IndexDigest, good)
		}
		if len(rec.Arches) != 2 {
			t.Errorf("Arches = %v, want 2 platforms", rec.Arches)
		}
	})

	t.Run("single-arch rejected under require-index", func(t *testing.T) {
		sbody := `{"mediaType":"` + imgCT + `","config":{},"layers":[]}`
		good := digestOfBytes([]byte(sbody))
		c := manifestSrv(t, good, imgCT, sbody)
		if _, err := (reconcileResolver{client: c, requireIndex: true}).ResolveIndex(context.Background(), ref); err == nil {
			t.Fatal("require-index must reject a single-arch (non-index) manifest")
		}
	})
}

// TestReconcileResolver_DigestOverride covers the LOW fix for the operator-supplied
// --digest override: it must be a canonical sha256 digest, never trusted raw.
func TestReconcileResolver_DigestOverride(t *testing.T) {
	if _, err := (reconcileResolver{digest: "not-a-digest"}).ResolveIndex(context.Background(), "nginx:1.27"); err == nil {
		t.Error("malformed --digest must be rejected")
	}
	if _, err := (reconcileResolver{digest: "sha256:tooshort"}).ResolveIndex(context.Background(), "nginx:1.27"); err == nil {
		t.Error("short --digest must be rejected")
	}
	good := "sha256:" + strings.Repeat("a", 64)
	rec, err := (reconcileResolver{digest: good}).ResolveIndex(context.Background(), "nginx:1.27")
	if err != nil {
		t.Fatalf("valid --digest: %v", err)
	}
	if rec.IndexDigest != good {
		t.Errorf("IndexDigest = %q, want %q", rec.IndexDigest, good)
	}
}
