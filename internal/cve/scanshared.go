package cve

import (
	"strconv"
	"strings"
)

// isJSONReport reports whether name is a JSON/SARIF report file the report-dir
// sources should attempt to parse.
func isJSONReport(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".sarif")
}

// cveIDFrom picks the first value that looks like a vulnerability id (CVE-*,
// GHSA-*, or any non-empty id), preferring a CVE form.
func cveIDFrom(candidates ...string) string {
	var fallback string
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(c), "CVE-") {
			return c
		}
		if fallback == "" {
			fallback = c
		}
	}
	return fallback
}

// severityFromScore buckets a CVSS base score (as a string, e.g. "9.8") into a
// severity band per the CVSS v3 qualitative ranges. A non-numeric score (e.g. a
// bare CVSS vector) yields SeverityUnknown.
func severityFromScore(score string) Severity {
	f, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil {
		return SeverityUnknown
	}
	switch {
	case f >= 9.0:
		return SeverityCritical
	case f >= 7.0:
		return SeverityHigh
	case f >= 4.0:
		return SeverityMedium
	case f > 0.0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// refMatchesFilename is a fallback for reports that do not declare their image
// in content: it matches ref against the report's base filename (minus a
// .json/.sarif[.json] suffix) under the common convention of sanitizing "/" and
// ":" to "_". It never matches an empty ref.
func refMatchesFilename(ref, filename string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	base := filename
	for _, suf := range []string{".sarif.json", ".sarif", ".json"} {
		if strings.HasSuffix(strings.ToLower(base), suf) {
			base = base[:len(base)-len(suf)]
			break
		}
	}
	san := func(s string) string {
		s = trimDigest(s) // filename convention drops the digest
		r := strings.NewReplacer("/", "_", ":", "_", "@", "_")
		return strings.ToLower(r.Replace(s))
	}
	return san(ref) == strings.ToLower(base)
}
