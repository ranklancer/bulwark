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

// ParseOSVResults parses one osv-scanner results document. It returns the image
// it describes (source.path of the first image-typed result), its de-duplicated
// advisories, and structured — whether the top-level `results` key was present.
// osv-scanner emits `{"results":[]}` for a scanned-clean image (key present,
// empty), versus `{}` (key absent) for a truncated/empty document; only the
// latter is structurally empty and must be treated as UNKNOWN (fail closed).
func ParseOSVResults(data []byte) (image string, vulns []Vuln, structured bool, err error) {
	var r osvResults
	if err := json.Unmarshal(data, &r); err != nil {
		return "", nil, false, fmt.Errorf("cve: parse osv results: %w", err)
	}
	idx := make(map[string]int) // vuln id -> index in out (dedup keeping MAX severity)
	var out []Vuln
	for _, res := range r.Results {
		if image == "" && strings.TrimSpace(res.Source.Path) != "" {
			image = strings.TrimSpace(res.Source.Path)
		}
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				id := osvPreferredID(v)
				if id == "" {
					continue
				}
				sev := osvSeverity(v)
				// Same advisory can recur across packages/ecosystems; keep MAX
				// severity so a Critical never buckets as a lower earlier hit.
				if i, ok := idx[id]; ok {
					if sev > out[i].Severity {
						out[i].Severity = sev
					}
					continue
				}
				idx[id] = len(out)
				out = append(out, Vuln{
					ID:       id,
					Severity: sev,
					PkgName:  pkg.Package.Name,
					Title:    strings.TrimSpace(v.Summary),
				})
			}
		}
	}
	return image, out, r.Results != nil, nil
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

// osvSeverity uses the advisory DB's textual severity when present; a CVSS
// vector string (osv-scanner's usual severity[].score encoding) is NOT a numeric
// band and is left Unknown rather than guessed. A known advisory that grades as
// Unknown still fails closed at the gate (it is a known vulnerability).
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

// Vulns scans the report directory for an advisory result describing ref. No
// matching report yields (nil, nil). A matching but structurally-empty (`{}`,
// no results key) report yields an ERROR so the gate fails closed.
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
		image, vulns, structured, perr := ParseOSVResults(data)
		if perr != nil {
			continue
		}
		if matchArtifact(ref, image, nil, nil) || (image == "" && refMatchesFilename(ref, e.Name())) {
			if !structured {
				return nil, fmt.Errorf("cve: registry-advisory report %q for %q is structurally empty (no results; truncated?) — unknown, not clean", e.Name(), ref)
			}
			return vulns, nil
		}
	}
	return nil, nil
}
