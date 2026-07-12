package main

import (
	"context"

	"github.com/bulwark-docker/bulwark/internal/api"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/store"
)

// daemonIndexResolver adapts the daemon's api.DigestResolver (which returns the
// resolved digest for a ref) to reconcile.IndexResolver, so the live DIUN
// handler can reconcile detected updates without a second registry client.
type daemonIndexResolver struct{ r api.DigestResolver }

func (d daemonIndexResolver) ResolveIndex(ctx context.Context, ref string) (store.PinRecord, error) {
	parsed, err := registry.Parse(ref)
	if err != nil {
		return store.PinRecord{}, err
	}
	digest, err := d.r.Resolve(ctx, parsed)
	if err != nil {
		return store.PinRecord{}, err
	}
	return store.PinRecord{IndexDigest: digest}, nil
}

// pinsForState returns a PinStore for the dashboard candidates view, or nil when
// no data dir is configured (which omits the GET /api/v1/candidates route).
func pinsForState(dataDir string) *store.PinStore {
	if dataDir == "" {
		return nil
	}
	return store.OpenPinStore(dataDir)
}
