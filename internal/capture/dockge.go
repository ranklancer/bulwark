package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultDockgeStacksDir is Dockge's out-of-the-box stacks root. Dockge stores
// each stack as <stacksDir>/<stackName>/compose.yaml on the host — its own
// source of truth — so bulwark pins Dockge stacks by editing those files in
// place with the full digest pinning safety contract.
const DefaultDockgeStacksDir = "/opt/stacks"

// dockgeContainerStacksDefault is the in-container path Dockge historically
// bind-mounts the host stacks dir onto. Used only to auto-locate the host root
// from a Dockge compose when DOCKGE_STACKS_DIR is not set.
const dockgeContainerStacksDefault = "/app/stacks"

// DockgeSource is the first-class Dockge adapter (file-based). It understands
// Dockge's canonical layout — one or more flat "stacks roots", each holding
// <stack>/compose.yaml — and pins by editing those compose files in place,
// delegating the actual write to the audited ComposeSource core (backup +
// atomic + format/comment-preserving + idempotent + rollback). It is distinct
// from the generic ComposeSource in that it locates Dockge stacks specifically:
// from explicit roots, the DOCKGE_STACKS_DIR env var, an optional Dockge compose
// bind-mount, or the Dockge default — plus any operator-supplied extra roots
// (e.g. a TrueNAS "ix-dockge" apps stacks path).
//
// General-purpose: nothing is hardcoded to a particular host or deployment.
// Discovery is fail-closed — it never follows a symlink out of a stacks root
// (path-traversal / symlink-escape guard) — and every write goes through the
// same drift-checked, backup-first path as ComposeSource.
type DockgeSource struct {
	// StacksDirs are explicit Dockge stacks roots (each holds <stack>/compose.yaml).
	// When set, autodetection is skipped.
	StacksDirs []string
	// Autodetect, when true and StacksDirs is empty, probes well-known Dockge
	// locations: an optional DockgeCompose bind-mount, $DOCKGE_STACKS_DIR, the
	// default /opt/stacks, and any ExtraRoots. Discovery only — never a write.
	Autodetect bool
	// ExtraRoots are additional candidate roots consulted during autodetection,
	// e.g. a TrueNAS ix-dockge apps stacks path. Operator-configured; general.
	ExtraRoots []string
	// DockgeCompose is an optional path to the compose file that runs Dockge
	// itself; during autodetection its stacks bind-mount is used to locate the
	// host stacks root. Read-only; never edited by this adapter.
	DockgeCompose string
	// BackupDir mirrors ComposeSource.BackupDir (where originals are copied
	// before an in-place edit).
	BackupDir string
}

// Kind reports Dockge as file-based (its stacks are compose files on disk).
func (s *DockgeSource) Kind() SourceKind { return KindFile }

// core is the audited file-write engine the Dockge adapter delegates to. Reusing
// ComposeSource keeps a single, fuzzed, drift-checked in-place write path rather
// than duplicating the dangerous edit logic.
func (s *DockgeSource) core() *ComposeSource { return &ComposeSource{BackupDir: s.BackupDir} }

// LocateImageRefs delegates to the shared file core.
func (s *DockgeSource) LocateImageRefs(ctx context.Context, t Target) ([]ImageRef, error) {
	return s.core().LocateImageRefs(ctx, t)
}

// ProposePin delegates to the shared file core (dry-run; no write).
func (s *DockgeSource) ProposePin(ctx context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error) {
	return s.core().ProposePin(ctx, t, ref, pin)
}

// WritePin delegates to the shared file core (backup + atomic + rollback).
func (s *DockgeSource) WritePin(ctx context.Context, p Proposal) (Applied, error) {
	return s.core().WritePin(ctx, p)
}

// Discover enumerates Dockge stacks (<root>/<stack>/compose.yaml) across every
// resolved stacks root. It skips any entry that resolves outside its root
// (symlink-escape guard, fail-closed) and de-dupes by absolute compose path.
func (s *DockgeSource) Discover(_ context.Context) ([]Target, error) {
	seen := map[string]bool{}
	var targets []Target
	for _, root := range s.resolveStacksDirs() {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// Dockge stacks are real directories directly under the root. A
			// symlinked entry reports IsDir()==false and is skipped here.
			if !e.IsDir() {
				continue
			}
			f := composeInDir(filepath.Join(root, e.Name()))
			if f == "" {
				continue
			}
			// Fail-closed containment: the compose file must resolve to a path
			// that stays within this stacks root. Defends against a symlinked
			// stack file redirecting a later in-place write outside the root.
			if !withinRoot(root, f) {
				continue
			}
			abs, err := filepath.Abs(f)
			if err != nil || seen[abs] {
				continue
			}
			seen[abs] = true
			targets = append(targets, Target{Name: e.Name(), Path: abs, Kind: KindFile})
		}
	}
	return targets, nil
}

// resolveStacksDirs returns the ordered, de-duplicated, absolute list of stacks
// roots to scan: explicit StacksDirs first; otherwise (Autodetect) the Dockge
// compose bind-mount, $DOCKGE_STACKS_DIR, the Dockge default, and ExtraRoots.
func (s *DockgeSource) resolveStacksDirs() []string {
	var cands []string
	switch {
	case len(s.StacksDirs) > 0:
		cands = append(cands, s.StacksDirs...)
	case s.Autodetect:
		if s.DockgeCompose != "" {
			if data, err := os.ReadFile(s.DockgeCompose); err == nil { // #nosec G304 -- operator-configured Dockge compose path
				if dir, ok := StacksDirFromDockgeCompose(data); ok {
					// A relative bind source is relative to the compose file's directory
					// (Docker Compose semantics), never bulwark's CWD.
					if !filepath.IsAbs(dir) {
						dir = filepath.Join(filepath.Dir(s.DockgeCompose), dir)
					}
					cands = append(cands, dir)
				}
			}
		}
		if env := strings.TrimSpace(os.Getenv("DOCKGE_STACKS_DIR")); env != "" {
			cands = append(cands, env)
		}
		cands = append(cands, DefaultDockgeStacksDir)
		cands = append(cands, s.ExtraRoots...)
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		abs, err := filepath.Abs(c)
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

// withinRoot reports whether p resolves to a location inside root, following
// symlinks on both. Fail-closed: a broken or out-of-bounds symlink returns false.
func withinRoot(root, p string) bool {
	rr, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	pp, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(rr), filepath.Clean(pp))
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// StacksDirFromDockgeCompose parses a Dockge compose file (the compose that runs
// Dockge itself) and returns the HOST stacks directory Dockge manages, matching
// the bind-mount whose container target equals DOCKGE_STACKS_DIR (or the
// historical /app/stacks default). Untrusted input: it never panics and returns
// ok=false when no stacks mount can be determined.
func StacksDirFromDockgeCompose(data []byte) (string, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	services := findMapping(&doc, "services")
	if services == nil {
		return "", false
	}
	for i := 0; i+1 < len(services.Content); i += 2 {
		svc := services.Content[i+1]
		if svc == nil || svc.Kind != yaml.MappingNode {
			continue
		}
		target := dockgeEnvValue(svc, "DOCKGE_STACKS_DIR")
		if target == "" {
			target = dockgeContainerStacksDefault
		}
		for _, m := range serviceBindMounts(svc) {
			if strings.TrimSpace(m.source) != "" && pathsEqual(m.target, target) {
				return strings.TrimSpace(m.source), true
			}
		}
	}
	return "", false
}

type bindMount struct{ source, target string }

// serviceBindMounts extracts (source,target) pairs from a service's volumes,
// tolerating both the short "src:dst[:mode]" and long {source,target} forms.
func serviceBindMounts(svc *yaml.Node) []bindMount {
	vols := valueNode(svc, "volumes")
	if vols == nil || vols.Kind != yaml.SequenceNode {
		return nil
	}
	var out []bindMount
	for _, v := range vols.Content {
		if v == nil {
			continue
		}
		switch v.Kind {
		case yaml.ScalarNode:
			if bm, ok := parseShortVolume(v.Value); ok {
				out = append(out, bm)
			}
		case yaml.MappingNode:
			tgt := scalarField(v, "target")
			if tgt != "" {
				out = append(out, bindMount{source: scalarField(v, "source"), target: tgt})
			}
		}
	}
	return out
}

// parseShortVolume splits the Docker short volume syntax HOST:CONTAINER[:MODE].
// Bounds-safe for fuzzing.
func parseShortVolume(s string) (bindMount, bool) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return bindMount{}, false
	}
	src, tgt := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if tgt == "" {
		return bindMount{}, false
	}
	return bindMount{source: src, target: tgt}, true
}

// dockgeEnvValue reads a service environment value, tolerating both the list
// ("- KEY=VALUE") and mapping ("KEY: VALUE") forms.
func dockgeEnvValue(svc *yaml.Node, key string) string {
	env := valueNode(svc, "environment")
	if env == nil {
		return ""
	}
	switch env.Kind {
	case yaml.SequenceNode:
		for _, e := range env.Content {
			if e == nil || e.Kind != yaml.ScalarNode {
				continue
			}
			if k, v, ok := strings.Cut(e.Value, "="); ok && strings.TrimSpace(k) == key {
				return strings.TrimSpace(v)
			}
		}
	case yaml.MappingNode:
		if v := valueNode(env, key); v != nil && v.Kind == yaml.ScalarNode {
			return strings.TrimSpace(v.Value)
		}
	}
	return ""
}

func scalarField(m *yaml.Node, key string) string {
	if v := valueNode(m, key); v != nil && v.Kind == yaml.ScalarNode {
		return strings.TrimSpace(v.Value)
	}
	return ""
}

func pathsEqual(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}
