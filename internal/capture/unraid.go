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

// unraidTemplatesDir is Unraid's default user-template root: each managed
// container is an XML template named my-<Name>.xml.
const unraidTemplatesDir = "/boot/config/plugins/dockerMan/templates-user"

// UnraidSource is the file-based adapter for Unraid Docker templates. Unraid
// stores each managed container as an XML template (my-<Name>.xml) whose
// <Repository> element holds the image reference; that template is the source of
// truth Unraid re-applies to (re)create the container. Bulwark pins an Unraid
// container by editing the <Repository> value IN PLACE, with the full digest pinning safety
// contract (dry-run / backup / atomic / format-preserving / idempotent /
// rollback) and the same symlink-escape / path-traversal / TOCTOU write-boundary
// guards as the Dockge and Podman-quadlet adapters. Its Kind() is file.
//
// General-purpose: nothing is hardcoded to a particular host. Discovery is
// fail-closed — it never follows a symlink out of a template root — and every
// write re-asserts containment at the boundary before the audited edit.
type UnraidSource struct {
	// TemplateDirs are explicit template roots. When set, autodetection is skipped.
	TemplateDirs []string
	// Autodetect, when true and TemplateDirs is empty, probes the Unraid default
	// templates-user root plus any ExtraRoots.
	Autodetect bool
	// ExtraRoots are additional candidate roots consulted during autodetection.
	ExtraRoots []string
	// BackupDir mirrors ComposeSource.BackupDir (where originals are copied before
	// an in-place edit).
	BackupDir string
}

// Kind reports Unraid templates as file-based (XML files edited in place).
func (s *UnraidSource) Kind() SourceKind { return KindFile }

// core is the audited file-write engine (backup + atomic) the adapter reuses so
// the dangerous edit machinery is never duplicated.
func (s *UnraidSource) core() *ComposeSource { return &ComposeSource{BackupDir: s.BackupDir} }

// Discover walks each resolved template root for *.xml files. WalkDir never
// follows symlinks (Lstat), so a symlinked entry is skipped; each real file is
// resolved and must still stay within its root (symlink-escape guard,
// fail-closed). The RESOLVED path is carried forward as Target.Path.
func (s *UnraidSource) Discover(_ context.Context) ([]Target, error) {
	seen := map[string]bool{}
	var targets []Target
	for _, root := range s.resolveTemplateDirs() {
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
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".xml") {
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
			targets = append(targets, Target{Name: unraidName(resolved), Path: resolved, Kind: KindFile})
			return nil
		})
	}
	return targets, nil
}

// LocateImageRefs parses the template and returns its <Repository> image ref.
func (s *UnraidSource) LocateImageRefs(_ context.Context, t Target) ([]ImageRef, error) {
	data, err := os.ReadFile(t.Path) // #nosec G304 -- operator-configured Unraid template path
	if err != nil {
		return nil, fmt.Errorf("capture: read %s: %w", t.Path, err)
	}
	return imageRefsFromUnraidBytes(data, unraidName(t.Path))
}

// ProposePin delegates to the shared, adapter-agnostic proposer.
func (s *UnraidSource) ProposePin(_ context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error) {
	return computePinProposal(t, ref, pin)
}

// WritePin re-asserts the digest, sanity and containment guards at the write
// boundary, then splices the new value inside the <Repository> element and writes
// via the shared backup + atomic path. This NARROWS the propose->apply TOCTOU: the
// target must still resolve inside a configured template dir and its FINAL
// component must not be a symlink (O_NOFOLLOW). O_NOFOLLOW covers only the final
// component, not an intermediate-directory symlink swap (same as Dockge; not
// exploitable when the template roots are root-owned).
func (s *UnraidSource) WritePin(_ context.Context, p Proposal) (Applied, error) {
	res := Applied{Path: p.Path, Line: p.Line, OldValue: p.OldValue, NewValue: p.NewValue}
	if p.NoOp {
		res.NoOp = true
		return res, nil
	}
	if p.Path == "" || p.Line <= 0 {
		return res, fmt.Errorf("capture: unraid: WritePin needs a Proposal with Path and Line (got %q line %d)", p.Path, p.Line)
	}
	if p.OldValue == "" || p.NewValue == "" {
		return res, fmt.Errorf("capture: unraid: WritePin: empty old/new image value")
	}
	// Write-boundary digest guard (parity with the compose/managed write paths).
	if at := strings.LastIndex(p.NewValue, "@"); at < 0 || !registry.IsSHA256Digest(strings.ToLower(p.NewValue[at+1:])) {
		return res, fmt.Errorf("capture: unraid: WritePin refusing to splice %q — not a sha256 digest-pinned reference", p.NewValue)
	}
	if !s.pathWithinAnyRoot(p.Path) {
		return res, fmt.Errorf("capture: unraid: refusing to write %q — it no longer resolves inside any configured template dir", p.Path)
	}
	if err := assertNoFinalSymlink(p.Path); err != nil {
		return res, err
	}
	data, err := os.ReadFile(p.Path) // #nosec G304 -- path already confirmed within a configured template dir
	if err != nil {
		return res, fmt.Errorf("capture: read %s: %w", p.Path, err)
	}
	newContent, noOp, err := spliceValueOnLine(string(data), p.Line, "<Repository>", p.OldValue, p.NewValue)
	if err != nil {
		return res, fmt.Errorf("capture: unraid: %s: %w", p.Path, err)
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

// pathWithinAnyRoot reports whether path resolves inside a configured template
// dir. Fail-closed: false when none is configured or none contains the path.
func (s *UnraidSource) pathWithinAnyRoot(path string) bool {
	for _, root := range s.resolveTemplateDirs() {
		if withinRoot(root, path) {
			return true
		}
	}
	return false
}

// resolveTemplateDirs returns the ordered, de-duplicated, absolute list of
// template roots: explicit TemplateDirs first; otherwise (Autodetect) the Unraid
// default templates-user root and any ExtraRoots.
func (s *UnraidSource) resolveTemplateDirs() []string {
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
	if len(s.TemplateDirs) > 0 {
		for _, d := range s.TemplateDirs {
			add(d)
		}
		return out
	}
	if !s.Autodetect {
		return out
	}
	add(unraidTemplatesDir)
	for _, r := range s.ExtraRoots {
		add(r)
	}
	return out
}

// unraidName derives a stable target name from a template path: the base name
// without its .xml extension and the Unraid "my-" template prefix (e.g. "Nginx"
// from "my-Nginx.xml").
func unraidName(path string) string {
	b := filepath.Base(path)
	b = strings.TrimSuffix(b, filepath.Ext(b))
	return strings.TrimPrefix(b, "my-")
}

// imageRefsFromUnraidBytes parses an Unraid container template and returns the
// <Repository> image reference (at most one). Untrusted input: it never panics; a
// template with no single-line <Repository>…</Repository> yields nil. :latest/
// untagged and unparseable refs are reported non-pinnable via classifyRef.
func imageRefsFromUnraidBytes(data []byte, service string) ([]ImageRef, error) {
	const openTag, closeTag = "<Repository>", "</Repository>"
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inComment := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		// The splicer keys on the FIRST literal "<Repository>" on the line, so the
		// parser only accepts a line whose first occurrence is LIVE (not inside an
		// XML comment) — parser and splicer agree. A commented-out <Repository>
		// (full-line, after an unclosed <!-- on the line, or inside a multi-line
		// comment opened earlier) is skipped, so a real element further down is the
		// one located and pinned — never the comment (which would be a silent
		// mis-pin: digest spliced into a comment while the live image stays
		// unpinned). Attribute/namespaced/CDATA <Repository ...> forms do not match
		// the literal open tag and are a documented fail-closed limitation.
		if oi := strings.Index(line, openTag); oi >= 0 && !xmlCommentedAt(line, inComment, oi) {
			rest := line[oi+len(openTag):]
			if ci := strings.Index(rest, closeTag); ci >= 0 {
				if val := strings.TrimSpace(rest[:ci]); val != "" {
					ir := ImageRef{Service: service, Raw: val, Ref: val, Line: lineNo}
					ir.Pinnable, ir.Reason = classifyRef(val)
					return []ImageRef{ir}, nil
				}
			}
		}
		inComment = xmlCommentEnd(line, inComment)
	}
	return nil, nil
}

// xmlCommentedAt reports whether byte offset idx on line is inside an XML
// comment, given the comment state at the start of the line.
func xmlCommentedAt(line string, inComment bool, idx int) bool {
	i := 0
	for i < idx {
		if inComment {
			j := strings.Index(line[i:idx], "-->")
			if j < 0 {
				return true
			}
			i += j + len("-->")
			inComment = false
		} else {
			j := strings.Index(line[i:idx], "<!--")
			if j < 0 {
				return false
			}
			i += j + len("<!--")
			inComment = true
		}
	}
	return inComment
}

// xmlCommentEnd returns the XML-comment state at the end of line, given the
// state at its start — so a comment opened on one line is still open on the next.
func xmlCommentEnd(line string, inComment bool) bool {
	i := 0
	for i < len(line) {
		if inComment {
			j := strings.Index(line[i:], "-->")
			if j < 0 {
				return true
			}
			i += j + len("-->")
			inComment = false
		} else {
			j := strings.Index(line[i:], "<!--")
			if j < 0 {
				return false
			}
			i += j + len("<!--")
			inComment = true
		}
	}
	return inComment
}
