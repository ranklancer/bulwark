package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// grypeReport is the subset of `grype <image> -o json` output we consume.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
		Artifact struct {
			Name string `json:"name"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Target struct {
			UserInput   string   `json:"userInput"`
			ImageID     string   `json:"imageID"`
			RepoTags    []string `json:"tags"`
			RepoDigests []string `json:"repoDigests"`
		} `json:"target"`
	} `json:"source"`
}

func grypeVulns(rep grypeReport) []Vuln {
	var out []Vuln
	seen := make(map[string]bool)
	for _, m := range rep.Matches {
		id := m.Vulnerability.ID
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Vuln{
			ID:       id,
			Severity: ParseSeverity(m.Vulnerability.Severity),
			PkgName:  m.Artifact.Name,
		})
	}
	return out
}

// ParseGrypeReport parses one `grype -o json` report, returning the scanned
// image reference (source.target.userInput) and its de-duplicated vulns.
func ParseGrypeReport(data []byte) (artifact string, vulns []Vuln, err error) {
	var rep grypeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return "", nil, fmt.Errorf("cve: parse grype report: %w", err)
	}
	return rep.Source.Target.UserInput, grypeVulns(rep), nil
}

// GrypeDirSource is a Source backed by a directory of `grype -o json` reports.
// It implements the same pluggable cve.Source seam as TrivyDirSource and
// reuses the shared digest-strict matching, so current vs candidate images
// (same tag, different digest) don't collapse onto one report.
type GrypeDirSource struct {
	Dir string
}

func (g GrypeDirSource) Vulns(ctx context.Context, ref string) ([]Vuln, error) {
	if g.Dir == "" {
		return nil, fmt.Errorf("cve: grype report_dir is empty")
	}
	entries, err := os.ReadDir(g.Dir)
	if err != nil {
		return nil, fmt.Errorf("cve: read grype report_dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, rerr := os.ReadFile(filepath.Join(g.Dir, e.Name()))
		if rerr != nil {
			continue
		}
		var rep grypeReport
		if json.Unmarshal(data, &rep) != nil {
			continue
		}
		t := rep.Source.Target
		if matchArtifact(ref, t.UserInput, t.RepoDigests, t.RepoTags) {
			return grypeVulns(rep), nil
		}
	}
	return nil, nil
}
