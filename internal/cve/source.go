package cve

import "context"

// Vuln is a single known vulnerability present in an image.
type Vuln struct {
	ID       string // e.g. "CVE-2024-1234" or a GHSA id
	Severity Severity
	PkgName  string
	Title    string
}

// Source returns the vulnerabilities known for a given image reference. It is
// the pluggable seam: Trivy (filesystem reports) is the first implementation,
// with room for a Trivy server, Grype, OSV, or Docker Scout behind the same
// interface.
type Source interface {
	// Vulns returns the vulnerabilities present in the image identified by
	// ref ("repo:tag", "repo:tag@digest", or "repo@digest"). A nil error with
	// an empty slice means "looked up, none found / no report"; a non-nil
	// error means "unknown" and callers skip urgency for that pair.
	Vulns(ctx context.Context, ref string) ([]Vuln, error)
}
