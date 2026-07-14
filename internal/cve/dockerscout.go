package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// docker-scout emits SARIF 2.1.0 via
// `docker scout cves <ref> --format sarif --output <dir>/<name>.sarif.json`.
// This adapter parses the minimal SARIF subset needed to (a) identify the
// analyzed image and (b) list its CVEs with severity. It is file-based
// (report-dir): there is no live `docker scout` invocation on the hot path,
// matching the Trivy/Grype adapters and the "no live scanner on the hot path"
// design principle.

type scoutSARIF struct {
	Runs []scoutRun `json:"runs"`
}

type scoutRun struct {
	Tool struct {
		Driver struct {
			Rules []scoutRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	AutomationDetails struct {
		ID string `json:"id"`
	} `json:"automationDetails"`
	Properties struct {
		ImageName string `json:"imageName"`
	} `json:"properties"`
}

type scoutRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	Properties struct {
		CVSSV3Severity   string `json:"cvssV3_severity"`
		SecuritySeverity string `json:"security-severity"`
	} `json:"properties"`
}

// ParseDockerScoutSARIF parses one docker-scout SARIF report. It returns the
// image it describes (best-effort: run properties.imageName, else
// automationDetails.id, else ""), the de-duplicated CVEs it contains, and
// structured — whether the document is a real report. A valid SARIF report has
// at least one run; zero runs (`{}` or `{"runs":[]}`) is a truncated/empty
// document, NOT a clean scan, so structured is false and callers must treat it
// as UNKNOWN (fail closed) rather than as a clean image.
func ParseDockerScoutSARIF(data []byte) (image string, vulns []Vuln, structured bool, err error) {
	var s scoutSARIF
	if err := json.Unmarshal(data, &s); err != nil {
		return "", nil, false, fmt.Errorf("cve: parse docker-scout sarif: %w", err)
	}
	image, vulns = scoutVulns(s)
	return image, vulns, len(s.Runs) > 0, nil
}

func scoutVulns(s scoutSARIF) (string, []Vuln) {
	var image string
	var out []Vuln
	idx := make(map[string]int) // CVE id -> index in out (dedup keeping MAX severity)
	for _, run := range s.Runs {
		if image == "" {
			switch {
			case strings.TrimSpace(run.Properties.ImageName) != "":
				image = strings.TrimSpace(run.Properties.ImageName)
			case strings.TrimSpace(run.AutomationDetails.ID) != "":
				image = strings.TrimSpace(run.AutomationDetails.ID)
			}
		}
		for _, rule := range run.Tool.Driver.Rules {
			id := cveIDFrom(rule.ID, rule.Name)
			if id == "" {
				continue
			}
			sev := scoutSeverity(rule.Properties.CVSSV3Severity, rule.Properties.SecuritySeverity)
			// On a duplicate id (multi-arch runs[], repeated rule) keep the MAX
			// severity — a Critical seen after a Low must never bucket as Low.
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
				Title:    strings.TrimSpace(rule.ShortDescription.Text),
			})
		}
	}
	return image, out
}

// scoutSeverity prefers docker-scout's textual cvssV3_severity, falling back to
// the numeric SARIF security-severity (a CVSS base score) bucketed to a band.
func scoutSeverity(text, score string) Severity {
	if s := ParseSeverity(text); s != SeverityUnknown {
		return s
	}
	return severityFromScore(score)
}

// DockerScoutDirSource is a Source backed by a directory of docker-scout SARIF
// reports. A requested ref is matched against each report's declared image
// (content) and, as a fallback, the report filename. Read-only; concurrency-safe.
type DockerScoutDirSource struct {
	Dir string
}

// Vulns scans the report directory for a docker-scout report describing ref.
// No matching report yields (nil, nil) — "none/unknown", identical to Trivy. A
// report that matches but is structurally empty (truncated) yields an ERROR, so
// the trust gate fails closed rather than reading it as a clean image.
func (d DockerScoutDirSource) Vulns(ctx context.Context, ref string) ([]Vuln, error) {
	if d.Dir == "" {
		return nil, fmt.Errorf("cve: docker-scout report_dir is empty")
	}
	entries, err := os.ReadDir(d.Dir)
	if err != nil {
		return nil, fmt.Errorf("cve: read docker-scout report_dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !isJSONReport(e.Name()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, rerr := os.ReadFile(filepath.Join(d.Dir, e.Name()))
		if rerr != nil {
			continue
		}
		image, vulns, structured, perr := ParseDockerScoutSARIF(data)
		if perr != nil {
			continue
		}
		if matchArtifact(ref, image, nil, nil) || (image == "" && refMatchesFilename(ref, e.Name())) {
			if !structured {
				return nil, fmt.Errorf("cve: docker-scout report %q for %q is structurally empty (no runs; truncated?) — unknown, not clean", e.Name(), ref)
			}
			return vulns, nil
		}
	}
	return nil, nil
}
