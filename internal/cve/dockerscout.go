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
// automationDetails.id, else "") and the de-duplicated CVEs it contains.
func ParseDockerScoutSARIF(data []byte) (image string, vulns []Vuln, err error) {
	var s scoutSARIF
	if err := json.Unmarshal(data, &s); err != nil {
		return "", nil, fmt.Errorf("cve: parse docker-scout sarif: %w", err)
	}
	image, vulns = scoutVulns(s)
	return image, vulns, nil
}

func scoutVulns(s scoutSARIF) (string, []Vuln) {
	var image string
	var out []Vuln
	seen := make(map[string]bool)
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
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, Vuln{
				ID:       id,
				Severity: scoutSeverity(rule.Properties.CVSSV3Severity, rule.Properties.SecuritySeverity),
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
// No matching report yields (nil, nil) — "none/unknown", identical to Trivy.
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
		image, vulns, perr := ParseDockerScoutSARIF(data)
		if perr != nil {
			continue
		}
		if matchArtifact(ref, image, nil, nil) || (image == "" && refMatchesFilename(ref, e.Name())) {
			return vulns, nil
		}
	}
	return nil, nil
}
