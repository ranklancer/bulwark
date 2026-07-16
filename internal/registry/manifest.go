package registry

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Index/list media types. A tag whose manifest carries one of these is
// multi-arch: the digest to pin is the INDEX digest, never a per-arch
// sub-manifest (the "NPM 2.15.1 lesson" — pinning a sub-manifest silently
// breaks every other architecture). See the digest-pin capture design §5.4.
const (
	mediaTypeOCIIndex    = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	manifestBodyReadCap  = 8 << 20 // 8 MiB: manifests are tiny; cap to stay safe
	attestationUnknownOS = "unknown"
)

// ManifestInfo describes a resolved manifest for digest-pin capture.
type ManifestInfo struct {
	// Digest is the content digest of the manifest the registry returned for
	// the requested tag (sha256:...). For a multi-arch tag this is the INDEX
	// digest — exactly what digest pinning pins.
	Digest string
	// MediaType is the manifest's media type.
	MediaType string
	// IsIndex reports whether the manifest is a multi-arch index/list.
	IsIndex bool
	// Arches lists the platforms advertised by an index (e.g. "linux/amd64").
	// Empty for a single-arch manifest. Attestation entries
	// (platform "unknown/unknown") are excluded.
	Arches []string
}

// ResolveManifest fetches the manifest body for ref's tag (or digest) and
// reports its digest, media type, and — for a multi-arch index — the platforms
// it advertises. Unlike Resolve (a HEAD that only reads the digest header),
// this GETs the body so callers can assert an index vs a single-arch manifest
// before pinning. Fail-closed: a missing digest header is an error.
func (c *Client) ResolveManifest(ctx context.Context, ref Reference) (ManifestInfo, error) {
	id := ref.Tag
	if id == "" {
		id = ref.Digest
	}
	if id == "" {
		return ManifestInfo{}, errors.New("registry: ResolveManifest requires either a tag or a digest")
	}
	endpoint := c.endpoint(ref.Registry, "/v2/"+ref.Repository+"/manifests/"+id)
	resp, err := c.doManifest(ctx, "GET", endpoint, ref.Registry, ref.Repository)
	if err != nil {
		return ManifestInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ManifestInfo{}, fmt.Errorf("registry: GET %s: %s", endpoint, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, manifestBodyReadCap))
	if err != nil {
		return ManifestInfo{}, fmt.Errorf("registry: read manifest %s: %w", endpoint, err)
	}
	var doc struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Platform struct {
				OS      string `json:"os"`
				Arch    string `json:"architecture"`
				Variant string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ManifestInfo{}, fmt.Errorf("registry: parse manifest %s: %w", endpoint, err)
	}
	info := ManifestInfo{Digest: resp.Header.Get("Docker-Content-Digest"), MediaType: doc.MediaType}
	// Some registries omit mediaType in the body; fall back to Content-Type.
	if info.MediaType == "" {
		info.MediaType = strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	}
	info.IsIndex = isIndexMediaType(info.MediaType) || len(doc.Manifests) > 0
	if info.IsIndex {
		for _, m := range doc.Manifests {
			os, arch := m.Platform.OS, m.Platform.Arch
			if os == "" && arch == "" {
				continue
			}
			if os == attestationUnknownOS || arch == attestationUnknownOS {
				continue // buildx attestation manifest, not a real platform
			}
			p := os + "/" + arch
			if m.Platform.Variant != "" {
				p += "/" + m.Platform.Variant
			}
			info.Arches = append(info.Arches, p)
		}
	}
	info.Digest = strings.ToLower(strings.TrimSpace(info.Digest))
	if info.Digest == "" {
		return info, fmt.Errorf("registry: response from %s missing Docker-Content-Digest header", endpoint)
	}
	if !IsSHA256Digest(info.Digest) {
		return ManifestInfo{}, fmt.Errorf("registry: %s returned a malformed content digest %q", endpoint, info.Digest)
	}
	// Content-addressability trust check (fail-closed): the Docker-Content-Digest
	// header MUST equal the sha256 of the exact bytes we read. Defends against a
	// registry/MITM that serves index A while claiming digest B (pin poisoning).
	sum := sha256.Sum256(body)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(info.Digest), []byte(want)) != 1 {
		return ManifestInfo{}, fmt.Errorf("registry: manifest digest mismatch from %s (Docker-Content-Digest != sha256(body)) — refusing to pin", endpoint)
	}
	return info, nil
}

// isIndexMediaType reports whether mt is a multi-arch index/list media type.
func isIndexMediaType(mt string) bool {
	switch strings.TrimSpace(mt) {
	case mediaTypeOCIIndex, mediaTypeDockerList:
		return true
	default:
		return false
	}
}

// digestRe validates a canonical sha256 content digest.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// IsSHA256Digest reports whether s is a canonical "sha256:<64 lowercase hex>"
// digest. Callers reject anything else fail-closed before trusting a header or
// splicing a digest into a compose file.
func IsSHA256Digest(s string) bool { return digestRe.MatchString(s) }
