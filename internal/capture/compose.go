package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bulwark-docker/bulwark/internal/registry"
)

// ComposeSource is the file-based adapter (the digest-pin capture design §5.6): Dockge flat
// stacks-roots (<root>/<stack>/compose.yaml), raw compose directories, and
// single compose files. It edits the compose file in place (writes land in
// Phase 2).
type ComposeSource struct {
	// Paths are directories, globs, or files to search.
	Paths []string
	// Autodiscover enables the <root>/<stack>/<compose> subdirectory scan
	// (the flat Dockge layout).
	Autodiscover bool
	// BackupDir is where WritePin copies the original before an in-place edit.
	// Empty => a .bulwark-pin-backups directory beside the compose file.
	BackupDir string
}

var composeFileNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// Kind reports this adapter as file-based (pinned by in-place edit).
func (s *ComposeSource) Kind() SourceKind { return KindFile }

// Discover enumerates compose files under the configured paths.
func (s *ComposeSource) Discover(_ context.Context) ([]Target, error) {
	seen := map[string]bool{}
	var targets []Target
	add := func(path string) {
		abs, err := filepath.Abs(path)
		if err != nil || seen[abs] {
			return
		}
		seen[abs] = true
		targets = append(targets, Target{Name: stackName(abs), Path: abs, Kind: KindFile})
	}
	for _, p := range s.Paths {
		matches, _ := filepath.Glob(p)
		if len(matches) == 0 {
			matches = []string{p}
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				continue
			}
			if !info.IsDir() {
				add(m)
				continue
			}
			if f := composeInDir(m); f != "" {
				add(f)
			}
			if s.Autodiscover {
				entries, _ := os.ReadDir(m)
				for _, e := range entries {
					if e.IsDir() {
						if f := composeInDir(filepath.Join(m, e.Name())); f != "" {
							add(f)
						}
					}
				}
			}
		}
	}
	return targets, nil
}

func composeInDir(dir string) string {
	for _, name := range composeFileNames {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// stackName derives a stable target name: the parent directory name (the flat
// Dockge stack dir), else the file base.
func stackName(path string) string {
	dir := filepath.Base(filepath.Dir(path))
	if dir != "" && dir != "." && dir != string(filepath.Separator) {
		return dir
	}
	return filepath.Base(path)
}

// LocateImageRefs parses the compose file and returns each service's image
// reference, expanding ${VAR}/.env and flagging non-pinnable refs.
func (s *ComposeSource) LocateImageRefs(_ context.Context, t Target) ([]ImageRef, error) {
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return nil, fmt.Errorf("capture: read %s: %w", t.Path, err)
	}
	env := loadDotEnv(filepath.Dir(t.Path))
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("capture: parse %s: %w", t.Path, err)
	}
	services := findMapping(&doc, "services")
	if services == nil {
		return nil, nil
	}
	var refs []ImageRef
	for i := 0; i+1 < len(services.Content); i += 2 {
		svcName := services.Content[i].Value
		svc := services.Content[i+1]
		if svc.Kind != yaml.MappingNode {
			continue
		}
		imageNode := valueNode(svc, "image")
		hasBuild := valueNode(svc, "build") != nil
		ir := ImageRef{Service: svcName}
		if imageNode == nil {
			if hasBuild {
				ir.Pinnable = false
				ir.Reason = "build-context image (deferred to the full-fleet sweep)"
				refs = append(refs, ir)
			}
			continue
		}
		ir.Raw = imageNode.Value
		ir.Line = imageNode.Line
		expanded, ok := expandVars(imageNode.Value, env)
		ir.Ref = expanded
		switch {
		case !ok:
			ir.Pinnable, ir.Reason = false, "unresolved ${VAR} (no .env value or default)"
		case strings.Contains(imageNode.Value, "${"):
			ir.Pinnable, ir.Reason = false, "image defined via ${VAR}; var-aware pinning is Phase 2"
		case hasBuild:
			ir.Pinnable, ir.Reason = false, "has build: context (deferred to the full-fleet sweep)"
		default:
			ir.Pinnable, ir.Reason = classifyRef(expanded)
		}
		refs = append(refs, ir)
	}
	return refs, nil
}

// classifyRef decides whether a fully-resolved ref may be pinned in digest pinning's first
// batch (an internal note). Already-pinned refs are pinnable (ProposePin makes them no-ops).
func classifyRef(ref string) (bool, string) {
	if strings.Contains(ref, "@sha256:") {
		return true, "already digest-pinned"
	}
	parsed, err := registry.Parse(ref)
	if err != nil {
		return false, "unparseable image reference"
	}
	if parsed.Tag == "" || parsed.Tag == "latest" {
		return false, ":latest or untagged (deferred to the full-fleet sweep)"
	}
	return true, ""
}

// ProposePin computes the inline digest pin for ref WITHOUT writing anything.
func (s *ComposeSource) ProposePin(_ context.Context, t Target, ref ImageRef, pin Pin) (Proposal, error) {
	if !ref.Pinnable {
		return Proposal{}, fmt.Errorf("capture: %s/%s not pinnable: %s", t.Name, ref.Service, ref.Reason)
	}
	if pin.IndexDigest == "" {
		return Proposal{}, errors.New("capture: empty pin digest")
	}
	base := ref.Raw
	if at := strings.Index(base, "@sha256:"); at >= 0 {
		if base[at+1:] == pin.IndexDigest {
			return Proposal{Target: t, Service: ref.Service, Path: t.Path, Line: ref.Line,
				OldValue: ref.Raw, NewValue: ref.Raw, NoOp: true}, nil
		}
		base = base[:at]
	}
	newVal := base + "@" + pin.IndexDigest
	return Proposal{
		Target: t, Service: ref.Service, Path: t.Path, Line: ref.Line,
		OldValue: ref.Raw, NewValue: newVal,
		Diff: fmt.Sprintf("- image: %s\n+ image: %s", ref.Raw, newVal),
	}, nil
}

// --- helpers ---------------------------------------------------------------

func loadDotEnv(dir string) map[string]string {
	env := map[string]string{}
	f, err := os.Open(filepath.Join(dir, ".env"))
	if err != nil {
		return env
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return env
}

// expandVars expands ${VAR} and ${VAR:-default} / ${VAR-default}. ok is false
// when a referenced var is unset and has no default.
func expandVars(s string, env map[string]string) (string, bool) {
	ok := true
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			expr := s[i+2 : i+2+end]
			name, def, hasDef := expr, "", false
			if j := strings.Index(expr, ":-"); j >= 0 {
				name, def, hasDef = expr[:j], expr[j+2:], true
			} else if j := strings.IndexByte(expr, '-'); j >= 0 {
				name, def, hasDef = expr[:j], expr[j+1:], true
			}
			switch v, present := env[name]; {
			case present && v != "":
				b.WriteString(v)
			case hasDef:
				b.WriteString(def)
			default:
				ok = false
			}
			i += 2 + end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), ok
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

func findMapping(doc *yaml.Node, key string) *yaml.Node {
	root := documentRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	if v := valueNode(root, key); v != nil && v.Kind == yaml.MappingNode {
		return v
	}
	return nil
}

func valueNode(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
