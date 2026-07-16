package main

import (
	"log/slog"

	"github.com/ranklancer/bulwark/internal/api"
	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/store"
)

// manifestClientFor returns a body-verifying *registry.Client for the LIVE
// daemon reconcile resolver.
//
// The daemon's shared registry handle is typed as the narrow api.DigestResolver
// (a HEAD that reads only the Docker-Content-Digest header — no manifest body,
// so no content-addressability check and no index-vs-submanifest assertion).
// Driving a pin from that path trusts a registry-/MITM-asserted digest without
// verifying the bytes. Routing through *registry.Client.ResolveManifest instead
// gives the daemon the same guarantees as `bulwark reconcile`: sha256(body) must
// equal the header digest, and require-index is enforced.
//
// In production regClient is already a *registry.Client (with Auth), so this is
// a cheap type assertion. A test/other stub that isn't gets a fresh
// authenticated client rather than a silent fall-back to the HEAD-only path.
func manifestClientFor(r api.DigestResolver, cfg *config.Config, logger *slog.Logger) *registry.Client {
	if c, ok := r.(*registry.Client); ok {
		return c
	}
	c := registry.New()
	c.Auth = buildRegistryAuth(cfg, logger)
	return c
}

// pinsForState returns a PinStore for the dashboard candidates view, or nil when
// no data dir is configured (which omits the GET /api/v1/candidates route).
func pinsForState(dataDir string) *store.PinStore {
	if dataDir == "" {
		return nil
	}
	return store.OpenPinStore(dataDir)
}
