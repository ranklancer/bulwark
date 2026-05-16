package detect

import (
	"encoding/json"
	"strings"
)

// BindMount is the host:container half of a Docker bind mount as it
// appears in HostConfig.Binds. Source is always absolute on the host.
type BindMount struct {
	Source      string
	Destination string
}

// ParseHostConfigBinds extracts the bind mounts from a container's
// raw HostConfig JSON blob. The format Docker uses is the same one
// `docker inspect` shows under .HostConfig.Binds — a list of strings
// like "/host/path:/container/path[:options]". Volume references (no
// leading slash) are filtered out: they're managed by Docker, not by
// the host filesystem Bulwark can snapshot.
//
// A nil or empty rawHostConfig returns nil, no error — the caller's
// "no binds means no auto-target" fallback handles this naturally.
func ParseHostConfigBinds(rawHostConfig json.RawMessage) ([]BindMount, error) {
	if len(rawHostConfig) == 0 {
		return nil, nil
	}
	var hc struct {
		Binds []string `json:"Binds"`
	}
	if err := json.Unmarshal(rawHostConfig, &hc); err != nil {
		return nil, err
	}
	out := make([]BindMount, 0, len(hc.Binds))
	for _, b := range hc.Binds {
		bm, ok := parseBindEntry(b)
		if !ok {
			continue
		}
		out = append(out, bm)
	}
	return out, nil
}

// parseBindEntry splits one HostConfig.Binds entry into source +
// destination, dropping the optional ":ro" / ":Z" / ... options. Named
// volumes (entries whose source doesn't start with "/") are rejected
// — Bulwark can't snapshot them via the host filesystem.
func parseBindEntry(entry string) (BindMount, bool) {
	if entry == "" {
		return BindMount{}, false
	}
	// Docker bind notation: source:dest[:options]. Windows paths
	// complicate things on that platform; Bulwark targets Linux hosts
	// where the bind is always absolute and uses '/' separators, so
	// the first ':' marks the source/dest boundary safely.
	idx := strings.Index(entry, ":")
	if idx <= 0 {
		return BindMount{}, false
	}
	src := entry[:idx]
	rest := entry[idx+1:]

	// Named volume: source doesn't start with '/'. Skip.
	if !strings.HasPrefix(src, "/") {
		return BindMount{}, false
	}

	dest := rest
	if i := strings.Index(rest, ":"); i >= 0 {
		dest = rest[:i]
	}
	if dest == "" {
		return BindMount{}, false
	}
	return BindMount{Source: src, Destination: dest}, true
}

// InferTargetFromBinds walks a container's bind mounts in order and
// returns the first one that lives on a snapshot-capable filesystem,
// translated into a backend-specific target string. Returns empty
// string + ok=false when no bind matches a known mount.
//
// When multiple binds resolve to the same dataset/subvolume, the first
// one wins — Bulwark snapshots once per container, so it doesn't matter
// which of several aliased binds yields the target.
func InferTargetFromBinds(binds []BindMount, tbl *MountTable) (target string, ok bool) {
	if tbl == nil {
		return "", false
	}
	for _, b := range binds {
		m, found := tbl.FindContaining(b.Source)
		if !found {
			continue
		}
		t := InferSnapshotTarget(m, b.Source)
		if t != "" {
			return t, true
		}
	}
	return "", false
}
