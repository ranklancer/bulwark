package capture

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ranklancer/bulwark/internal/registry"
)

// quadletSystemUnitDir is Podman's default system (rootful) quadlet unit root.
const quadletSystemUnitDir = "/etc/containers/systemd"

// QuadletSource is the file-based adapter for Podman quadlets. Podman's systemd
// generator reads ".container"/".pod"/".kube" unit files and turns them into
// systemd services; the unit file on disk is the source of truth. Bulwark pins a
// quadlet by editing the "Image=" key of a ".container" unit IN PLACE, with the
// full digest pinning safety contract (dry-run / backup / atomic / format-preserving /
// idempotent / rollback) and the same symlink-escape / path-traversal / TOCTOU
// write-boundary guards as the Dockge adapter.
//
// Only ".container" units carry an in-unit image (the "Image=" key). ".pod" units
// aggregate containers and carry no image; ".kube" units reference an external
// Kubernetes manifest whose images live in that manifest, not the unit. Neither
// has an in-unit image to pin, so they yield no pinnable refs here.
//
// General-purpose: nothing is hardcoded to a particular host. Discovery is
// fail-closed — it never follows a symlink out of a unit root — and every write
// re-asserts containment at the boundary before the audited backup/atomic edit.
type QuadletSource struct {
	// UnitDirs are explicit quadlet unit roots. When set, autodetection is skipped.
	UnitDirs []string
	// Autodetect, when true and UnitDirs is empty, probes well-known quadlet dirs:
	// the system root, the per-user root under $XDG_CONFIG_HOME/$HOME, and ExtraRoots.
	Autodetect bool
	// ExtraRoots are additional candidate roots consulted during autodetection.
	ExtraRoots []string
	// BackupDir mirrors ComposeSource.BackupDir (where originals are copied before
	// an in-place edit).
	BackupDir string
}

// Kind reports Podman quadlets as file-based (unit files edited in place).
func (s *QuadletSource) Kind() SourceKind { return KindFile }

// core is the audited file-write engine (backup + atomic) the adapter reuses so
// the dangerous edit machinery is never duplicated.
func (s *QuadletSource) core() *ComposeSource { return &ComposeSource{BackupDir: s.BackupDir} }

// Discover walks each resolved unit dir for *.container files. WalkDir never
// follows symlinks (Lstat), so a symlinked entry is skipped; each real file is
// resolved and must still stay within its root (symlink-escape guard,
// fail-closed). The RESOLVED path is carried forward as Target.Path so the write
// boundary operates on a canonical location.
func (s *QuadletSource) Discover(_ context.Context) ([]Target, error) {
	seen := map[string]bool{}
	var targets []Target
	for _, root := range s.resolveUnitDirs() {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".container") {
				return nil
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || !withinRoot(root, resolved) {
				return nil
			}
			if seen[resolved] {
				return nil
			}
			seen[resolved] = true
			targets = append(targets, Target{Name: unitName(resolved), Path: resolved, Kind: KindFile})
			return nil
		})
	}
	return targets, nil
}

// LocateImageRefs parses the quadlet unit and returns its [Container] Image= ref.
func (s *QuadletSource) LocateImageRefs(_ context.Context, t Target) ([]ImageRef, error) {
	data, err := os.ReadFile(t.Path) // #nosec G304 -- operator-configured quadlet unit path
	if err != nil {
		return nil, fmt.Errorf("capture: read %s: %w", t.Path, err)
	}
	return imageRefsFromQuadletBytes(data, unitName(t.Path))
}

// ProposePin delegates to the shared, adapter-agnostic proposer.
func (s *QuadletSource) ProposePin(_ context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error) {
	return computePinProposal(t, ref, pin)
}

// WritePin re-asserts the digest and containment guards at the write boundary,
// then splices the new value into the Image= key and writes via the shared
// backup + atomic path. This NARROWS the propose->apply TOCTOU window: the target
// must still resolve inside a configured unit dir and its FINAL component must not
// be a symlink (O_NOFOLLOW). O_NOFOLLOW covers only the final component, not an
// intermediate-directory symlink swap (same as Dockge; not exploitable when the
// unit roots are root-owned).
func (s *QuadletSource) WritePin(_ context.Context, p Proposal) (Applied, error) {
	res := Applied{Path: p.Path, Line: p.Line, OldValue: p.OldValue, NewValue: p.NewValue}
	if p.NoOp {
		res.NoOp = true
		return res, nil
	}
	if p.Path == "" || p.Line <= 0 {
		return res, fmt.Errorf("capture: quadlet: WritePin needs a Proposal with Path and Line (got %q line %d)", p.Path, p.Line)
	}
	if p.OldValue == "" || p.NewValue == "" {
		return res, fmt.Errorf("capture: quadlet: WritePin: empty old/new image value")
	}
	// Write-boundary digest guard (parity with the compose/managed write paths).
	if at := strings.LastIndex(p.NewValue, "@"); at < 0 || !registry.IsSHA256Digest(strings.ToLower(p.NewValue[at+1:])) {
		return res, fmt.Errorf("capture: quadlet: WritePin refusing to splice %q — not a sha256 digest-pinned reference", p.NewValue)
	}
	if !s.pathWithinAnyRoot(p.Path) {
		return res, fmt.Errorf("capture: quadlet: refusing to write %q — it no longer resolves inside any configured quadlet unit dir", p.Path)
	}
	if err := assertNoFinalSymlink(p.Path); err != nil {
		return res, err
	}
	data, err := os.ReadFile(p.Path) // #nosec G304 -- path already confirmed within a configured unit dir
	if err != nil {
		return res, fmt.Errorf("capture: read %s: %w", p.Path, err)
	}
	newContent, noOp, err := spliceValueOnLine(string(data), p.Line, "Image=", p.OldValue, p.NewValue)
	if err != nil {
		return res, fmt.Errorf("capture: quadlet: %s: %w", p.Path, err)
	}
	if noOp {
		res.NoOp = true
		return res, nil
	}
	backupPath, err := s.core().backup(p.Path, data)
	if err != nil {
		return res, err
	}
	res.BackupPath = backupPath
	if err := atomicWrite(p.Path, newContent); err != nil {
		return res, err
	}
	return res, nil
}

// pathWithinAnyRoot reports whether path resolves inside a configured unit dir.
// Fail-closed: false when none is configured or none contains the path.
func (s *QuadletSource) pathWithinAnyRoot(path string) bool {
	for _, root := range s.resolveUnitDirs() {
		if withinRoot(root, path) {
			return true
		}
	}
	return false
}

// resolveUnitDirs returns the ordered, de-duplicated, absolute list of unit roots:
// explicit UnitDirs first; otherwise (Autodetect) the system quadlet dir, the
// per-user quadlet dir under $XDG_CONFIG_HOME/$HOME, and ExtraRoots.
func (s *QuadletSource) resolveUnitDirs() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(s.UnitDirs) > 0 {
		for _, d := range s.UnitDirs {
			add(d)
		}
		return out
	}
	if !s.Autodetect {
		return out
	}
	add(quadletSystemUnitDir)
	if x := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); x != "" {
		add(filepath.Join(x, "containers", "systemd"))
	} else if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		add(filepath.Join(h, ".config", "containers", "systemd"))
	}
	for _, r := range s.ExtraRoots {
		add(r)
	}
	return out
}

// unitName derives a stable target name from a unit path: the base name without
// its extension (e.g. "web" from "web.container").
func unitName(path string) string {
	b := filepath.Base(path)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// imageRefsFromQuadletBytes parses a Podman quadlet unit and returns the
// [Container] section's Image= reference (at most one). Untrusted input: it never
// panics; a unit with no pinnable Image= yields nil. A ".image"-unit indirection
// or an unparseable ref is reported non-pinnable via classifyRef.
func imageRefsFromQuadletBytes(data []byte, service string) ([]ImageRef, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section := ""
	lineNo := 0
	for sc.Scan() {
		lineNo++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			continue
		}
		if section != "container" {
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		if !ok || strings.TrimSpace(key) != "Image" {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		ir := ImageRef{Service: service, Raw: val, Ref: val, Line: lineNo}
		// Parser/splicer must AGREE: the splicer keys on the literal "Image=" token,
		// so a non-canonical "Image =" (whitespace around '=') is reported
		// non-pinnable rather than silently failing to splice with a misleading
		// "content changed" error. systemd tolerates the spaced form; bulwark asks
		// the operator to normalize it to "Image=" before pinning.
		if key != "Image" {
			ir.Pinnable, ir.Reason = false, "non-canonical 'Image =' key (whitespace around '='); normalize to 'Image=' to pin"
		} else {
			ir.Pinnable, ir.Reason = classifyRef(val)
		}
		return []ImageRef{ir}, nil
	}
	return nil, nil
}
