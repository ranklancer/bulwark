// Package capture implements the digest-pin capture design's digest-pin capture layer. It is built
// around a backend-agnostic Source provider interface so different container-
// management backends (Dockge/compose, Portainer, Komodo, TrueNAS ix-apps,
// Swarm, podman quadlets, …) can be pinned without the capture/canary core
// knowing which one is in use.
//
// A hard split is enforced between FILE-based backends (the stack definition
// is a compose/env file on disk that bulwark edits IN PLACE, with product-grade
// safety) and API/DB-MANAGED backends (Portainer stacks-in-DB, ix-apps, Komodo)
// which must be pinned through their orchestrator API or declared source of
// truth — never by mangling files. See Source.Kind.
//
// digest pinning Phase 1 implements only the file-based compose adapter, and only its
// read / dry-run path (Discover, LocateImageRefs, ProposePin). Applying edits
// (WritePin) with backup/atomic/rollback safety lands in Phase 2.
package capture

import "context"

// SourceKind distinguishes how a backend's pins must be written.
type SourceKind string

const (
	// KindFile: the definition is a file on disk; pin by in-place edit.
	KindFile SourceKind = "file"
	// KindManaged: the definition lives in an orchestrator DB/API or its own
	// git source of truth; pin via that API, never by editing files.
	KindManaged SourceKind = "managed"
)

// Target is one stack/service a Source manages.
type Target struct {
	Name string     // stable identifier (e.g. the stack directory name)
	Path string     // file path (file adapters) or API id (managed adapters)
	Kind SourceKind // mirrors the owning Source's Kind
}

// ImageRef is one image reference located inside a Target.
type ImageRef struct {
	Service  string // compose service name
	Raw      string // the value as written, e.g. "nginx:1.27" or "${NGINX_IMAGE}"
	Ref      string // resolved reference after ${VAR}/.env expansion ("" if unresolved)
	Line     int    // 1-based line number in the file (file adapters; 0 otherwise)
	Pinnable bool   // false for build-context, :latest/untagged, or unresolved ${VAR}
	Reason   string // when Pinnable is false, why (surfaced to the operator)
}

// Pin is a resolved digest to apply to an ImageRef (from registry.ResolveManifest).
type Pin struct {
	IndexDigest string   // sha256:...
	IsIndex     bool     // whether the digest is a multi-arch index
	Arches      []string // platforms advertised by an index
}

// Proposal is a DRY-RUN description of a single pin edit. Producing a Proposal
// performs no write; WritePin applies it (Phase 2).
type Proposal struct {
	Target   Target
	Service  string
	Path     string
	Line     int
	OldValue string // image value before the pin
	NewValue string // image value after the pin (tag@sha256:index)
	Diff     string // human-readable "- old / + new" snippet
	NoOp     bool   // already pinned to this exact digest (idempotent re-run)
}

// Source is the backend-agnostic capture provider. The capture and canary core
// depend only on this interface; concrete adapters live in their own files.
type Source interface {
	// Kind reports whether this backend is file-based or API/DB-managed, so the
	// core can enforce the right write path.
	Kind() SourceKind
	// Discover enumerates the stacks/targets this backend manages.
	Discover(ctx context.Context) ([]Target, error)
	// LocateImageRefs resolves every image reference in a target, expanding
	// ${VAR}/.env and flagging non-pinnable refs (build-context, :latest,
	// unresolved vars).
	LocateImageRefs(ctx context.Context, t Target) ([]ImageRef, error)
	// ProposePin computes the change WITHOUT applying it (the dry-run path).
	ProposePin(ctx context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error)
	// WritePin applies a previously-computed Proposal. File adapters edit the
	// file in place (backup + atomic + rollback); managed adapters call the
	// orchestrator API. Never both.
	WritePin(ctx context.Context, p Proposal) error
}
