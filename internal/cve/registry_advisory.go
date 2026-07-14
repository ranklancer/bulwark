package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The registry-advisory adapter reads advisory results in the OSV schema as
// produced by osv-scanner (`osv-scanner --format json --image <ref>`), which
// queries advisory databases (OSV / GitHub Security Advisories / distro feeds)
// rather than scanning image layers directly. It is file-based (report-dir):
// no live advisory-API call on the hot path in this phase; a live registry /
// referrers-API fetch is a documented future phase. Kind is report-dir.

type osvResults struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

type osvVuln struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// ParseOSVResults parses one osv-scanner results document, returning the image
// it describes (source.path of the first image-typed result) and its
// de-duplicated advisories.
func ParseOSVResults(data []byte) (image string, vulns []Vuln, err error) {
	var r osvResults
	if err := json.Unmarshal(data, &r); err != nil {
		return "", nil, fmt.Errorf("cve: parse osv results: %w", err)
	}
	seen := make(map[string]bool)
	var out []Vuln
	for _, res := range r.Results {
		if image == "" && strings.TrimSpace(res.Source.Path) != "" {
			image = strings.TrimSpace(res.Source.Path)
		}
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				id := osvPreferredID(v)
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, Vuln{
					ID:       id,
					Severity: osvSeverity(v),
					PkgName:  pkg.Package.Name,
					Title:    strings.TrimSpace(v.Summary),
				})
			}
		}
	}
	return image, out, nil
}

// osvPreferredID prefers a CVE alias (stable, cross-referenced) over the native
// OSV/GHSA id, so thresholds and de-dup align with the other providers.
func osvPreferredID(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(a)), "CVE-") {
			return strings.TrimSpace(a)
		}
	}
	return strings.TrimSpace(v.ID)
}

// osvSeverity uses the advisory DB's textual severity when present; a bare CVSS
// vector (no numeric band) is left Unknown rather than guessed.
func osvSeverity(v osvVuln) Severity {
	if s := ParseSeverity(v.DatabaseSpecific.Severity); s != SeverityUnknown {
		return s
	}
	for _, s := range v.Severity {
		if band := severityFromScore(s.Score); band != SeverityUnknown {
			return band
		}
	}
	return SeverityUnknown
}

// RegistryAdvisoryDirSource is a Source backed by a directory of osv-scanner
// results. Read-only; concurrency-safe.
type RegistryAdvisoryDirSource struct {
	Dir string
}

// Vulns scans the report directory for an advisory result describing ref.
// No matching report yields (nil, nil) — "none/unknown".
func (a RegistryAdvisoryDirSource) Vulns(ctx context.Context, ref string) ([]Vuln, error) {
	if a.Dir == "" {
		return nil, fmt.Errorf("cve: registry-advisory report_dir is empty")
	}
	entries, err := os.ReadDir(a.Dir)
	if err != nil {
		return nil, fmt.Errorf("cve: read registry-advisory report_dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !isJSONReport(e.Name()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, rerr := os.ReadFile(filepath.Join(a.Dir, e.Name()))
		if rerr != nil {
			continue
		}
		image, vulns, perr := ParseOSVResults(data)
		if perr != nil {
			continue
		}
		if matchArtifact(ref, image, nil, nil) || (image == "" && refMatchesFilename(ref, e.Name())) {
			return vulns, nil
		}
	}
	return nil, nil
}
