package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// trivyReport is the subset of `trivy image --format json` output we consume.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Metadata     struct {
		RepoDigests []string `json:"RepoDigests"`
		RepoTags    []string `json:"RepoTags"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func vulnsFromReport(rep trivyReport) []Vuln {
	var out []Vuln
	seen := make(map[string]bool)
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true
			out = append(out, Vuln{
				ID:       v.VulnerabilityID,
				Severity: ParseSeverity(v.Severity),
				PkgName:  v.PkgName,
				Title:    v.Title,
			})
		}
	}
	return out
}

// ParseTrivyReport parses one Trivy JSON report, returning the artifact name
// it describes and the de-duplicated vulnerabilities it contains.
func ParseTrivyReport(data []byte) (artifact string, vulns []Vuln, err error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return "", nil, fmt.Errorf("cve: parse trivy report: %w", err)
	}
	return rep.ArtifactName, vulnsFromReport(rep), nil
}

// TrivyDirSource is a Source backed by a directory of Trivy JSON reports (as
// written by `trivy image --format json -o <dir>/<name>.json`). A requested
// image ref is matched against each report's ArtifactName / RepoDigests /
// RepoTags. Read-only and safe for concurrent use.
type TrivyDirSource struct {
	Dir string
}

// Vulns scans the report directory for a report describing ref and returns its
// vulnerabilities. No matching report yields (nil, nil) — "none/unknown".
func (t TrivyDirSource) Vulns(ctx context.Context, ref string) ([]Vuln, error) {
	if t.Dir == "" {
		return nil, fmt.Errorf("cve: trivy report_dir is empty")
	}
	entries, err := os.ReadDir(t.Dir)
	if err != nil {
		return nil, fmt.Errorf("cve: read trivy report_dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, rerr := os.ReadFile(filepath.Join(t.Dir, e.Name()))
		if rerr != nil {
			continue
		}
		var rep trivyReport
		if json.Unmarshal(data, &rep) != nil {
			continue
		}
		if matchArtifact(ref, rep.ArtifactName, rep.Metadata.RepoDigests, rep.Metadata.RepoTags) {
			return vulnsFromReport(rep), nil
		}
	}
	return nil, nil
}

// matchArtifact reports whether ref refers to the same image a report
// describes. When ref is digest-pinned, matching is STRICT on digest — this is
// what keeps "current" and "candidate" (same tag, different digest) from
// collapsing onto a single report and reporting zero closed CVEs. Without a
// digest, it falls back to repo:tag / exact matching.
func matchArtifact(ref, artifact string, digests, tags []string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if rd := digestOf(ref); rd != "" {
		if digestOf(artifact) == rd {
			return true
		}
		for _, d := range digests {
			if digestOf(d) == rd {
				return true
			}
		}
		return artifact == ref
	}
	if eqImageRef(ref, artifact) {
		return true
	}
	for _, tg := range tags {
		if eqImageRef(ref, tg) {
			return true
		}
	}
	return false
}

func eqImageRef(a, b string) bool {
	return a != "" && b != "" && (a == b || trimDigest(a) == trimDigest(b))
}

func trimDigest(s string) string {
	if i := strings.Index(s, "@"); i >= 0 {
		return s[:i]
	}
	return s
}

func digestOf(s string) string {
	if i := strings.Index(s, "@"); i >= 0 {
		return s[i+1:]
	}
	return ""
}
